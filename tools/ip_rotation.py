#!/usr/bin/env python3
import argparse
import random
import re
import socket
import socketserver
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen

RED, DIM, RST = "\033[1;31m", "\033[2;31m", "\033[0m"

BANNER = r"""
:::::::::::::.     .        :    :::.       .,-::::: :::::::..       ...
;;; `;;;```.;;;    ;;,.    ;;;   ;;`;;    ,;;;'````' ;;;;``;;;;   .;;;;;;;.
[[[  `]]nnn]]'     [[[,, ,[[[[, ,[[ '[[,  [[[         [[[,/[[['  ,[[     \[[,
$$$   $$$""        $$$$$$$$"$$$c$$$cc$$$c $$$         $$$$$$c    $$$,     $$$
888   888o         888 Y88" 888o888   888,`88bo,__,o, 888b "88bo,"888,_ _,88P
MMM   YMMMb        MMM  M'  "MMMYMM   ""`   "YUMMMMMP"MMMM   "W"   "YMMMMMP"
"""

FETCH = [
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies"
    "&protocol=http&proxy_format=protocolipport&format=text&timeout=5000",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]

PORT = 8899
DIRECT_IP = None
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


def log(msg):
    print(f"{DIM}[{time.strftime('%H:%M:%S')}]{RST} {RED}{msg}{RST}", flush=True)


def get_direct_ip():
    for url in ("http://api.ipify.org", "http://ifconfig.me/ip"):
        try:
            req = Request(url, headers={"User-Agent": "curl/8.5.0"})
            body = urlopen(req, timeout=6).read().decode("utf-8", "ignore").strip()
            if IP_RE.match(body):
                return body
        except Exception:
            continue
    return None


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.pool = []
        self.i = 0
        self.cur = None
        self.served = 0
        self.failures = {}

    def load(self, pool):
        with self.lock:
            self.pool = pool[:]
            random.shuffle(self.pool)
            self.i = 0
            self.cur = self.pool[0] if self.pool else None
            self.failures.clear()

    def add_unique(self, proxies):
        with self.lock:
            existing = set(self.pool)
            added = 0
            for p in proxies:
                if p not in existing:
                    self.pool.append(p)
                    existing.add(p)
                    added += 1
            if self.cur is None and self.pool:
                self.i = 0
                self.cur = self.pool[0]
            return added

    def current(self):
        with self.lock:
            return self.cur

    def size(self):
        with self.lock:
            return len(self.pool)

    def snapshot(self):
        with self.lock:
            if not self.pool:
                return []
            return self.pool[self.i :] + self.pool[: self.i]

    def set_current(self, proxy):
        with self.lock:
            if proxy in self.pool:
                self.cur = proxy
                self.i = self.pool.index(proxy)

    def rotate(self):
        with self.lock:
            if not self.pool:
                return None
            self.i = (self.i + 1) % len(self.pool)
            self.cur = self.pool[self.i]
            self.served += 1
            return self.cur

    def mark_bad(self, proxy):
        with self.lock:
            if proxy not in self.pool:
                return
            count = self.failures.get(proxy, 0) + 1
            self.failures[proxy] = count
            if count >= 2 and len(self.pool) > 1:
                idx = self.pool.index(proxy)
                self.pool.pop(idx)
                self.failures.pop(proxy, None)
                if not self.pool:
                    self.cur = None
                    self.i = 0
                else:
                    self.i %= len(self.pool)
                    if self.cur == proxy:
                        self.cur = self.pool[self.i]


STATE = State()


def parse_proxy(raw):
    raw = raw.strip().replace("\r", "")
    if not raw or raw.startswith("#"):
        return None
    scheme = "http"
    if raw.startswith("socks5://"):
        scheme = "socks5"
        raw = raw[len("socks5://") :]
    elif raw.startswith("socks4://"):
        return None
    else:
        raw = re.sub(r"^https?://", "", raw)
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        return None
    p = int(port)
    if not (1 <= p <= 65535):
        return None
    return (scheme, (host, p))


def fetch_candidates():
    found = []
    for url in FETCH:
        try:
            req = Request(url, headers={"User-Agent": "curl/8.5.0"})
            body = urlopen(req, timeout=15).read().decode("utf-8", "ignore")
        except Exception as e:
            log(f"source failed: {url.split('/')[2]} ({e.__class__.__name__})")
            continue
        got = [p for p in (parse_proxy(line) for line in body.splitlines()) if p]
        log(f"source ok: {url.split('/')[2]} -> {len(got)} candidates")
        found.extend(got)
    seen, out = set(), []
    for p in found:
        if p[1] not in seen:
            seen.add(p[1])
            out.append(p)
    random.shuffle(out)
    return out


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("eof")
        buf += chunk
    return buf


def open_socks5(addr, host, port, timeout=8):
    s = socket.create_connection(addr, timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if recv_exact(s, 2) != b"\x05\x00":
            raise IOError("socks handshake failed")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        ver, rep, _, atyp = recv_exact(s, 4)
        if ver != 5 or rep != 0:
            raise IOError("socks connect refused")
        if atyp == 1:
            recv_exact(s, 4 + 2)
        elif atyp == 3:
            ln = recv_exact(s, 1)[0]
            recv_exact(s, ln + 2)
        elif atyp == 4:
            recv_exact(s, 16 + 2)
        else:
            raise IOError("socks bad atyp")
        return s
    except Exception:
        s.close()
        raise


def open_http_connect(addr, host, port, timeout=8):
    s = socket.create_connection(addr, timeout=timeout)
    try:
        req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Proxy-Connection: Keep-Alive\r\n\r\n"
        )
        s.sendall(req.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                raise IOError("proxy closed during CONNECT")
            data += chunk
            if len(data) > 32768:
                raise IOError("header flood")
        status = data.split(b"\r\n", 1)[0]
        if b" 200" not in status:
            raise IOError("CONNECT refused")
        return s
    except Exception:
        s.close()
        raise


def fetch_via_upstream(p, url="http://api.ipify.org", timeout=6):
    scheme, addr = p
    m = re.match(r"^http://([^/:]+)(?::(\d+))?(/.*)?$", url)
    if not m:
        raise ValueError("unsupported validation url")
    host = m.group(1)
    port = int(m.group(2) or 80)
    path = m.group(3) or "/"

    if scheme == "socks5":
        s = open_socks5(addr, host, port, timeout=timeout)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: curl/8.5.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    else:
        s = socket.create_connection(addr, timeout=timeout)
        req = (
            f"GET http://{host}:{port}{path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: curl/8.5.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

    try:
        s.settimeout(timeout)
        s.sendall(req)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 16384:
                break
    finally:
        s.close()

    if b"\r\n\r\n" not in resp:
        raise IOError("incomplete http response")
    head, body = resp.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0]
    if b" 200" not in status:
        raise IOError("non-200 status")
    ip = body.decode("utf-8", "ignore").strip()
    if not IP_RE.match(ip):
        raise IOError("invalid ip body")
    return ip


def validate(p):
    try:
        ip = fetch_via_upstream(p, timeout=5)
        if DIRECT_IP and ip == DIRECT_IP:
            return None
        return p
    except Exception:
        return None


def harvest_live(cands, limit):
    live = []
    done = 0
    with ThreadPoolExecutor(max_workers=60) as ex:
        for res in ex.map(validate, cands):
            done += 1
            if res:
                live.append(res)
                sys.stdout.write(
                    f"\r{RED}  live {len(live)}/{limit}  ·  tested {done}/{len(cands)}{RST}  "
                )
                sys.stdout.flush()
                if len(live) >= limit:
                    break
    if done:
        print()
    return live


def build_pool(target, source_file=None, do_validate=True):
    if source_file:
        with open(source_file, encoding="utf-8", errors="ignore") as f:
            cands = [p for p in (parse_proxy(line) for line in f) if p]
        random.shuffle(cands)
        log(f"file loaded: {len(cands)} candidates")
    else:
        log("harvesting public proxy lists ...")
        cands = fetch_candidates()
    if not cands:
        sys.exit(f"{RED}no candidates found{RST}")
    if not do_validate:
        STATE.load(cands[:target])
        log(f"pool: {STATE.size()} (unvalidated)")
        return

    log(f"validating until {target} live non-transparent proxies ...")
    pool = harvest_live(cands, target)
    if len(pool) < 3:
        sys.exit(f"{RED}only {len(pool)} live proxies — try again later{RST}")
    STATE.load(pool)
    log(f"pool armed: {STATE.size()} live exit nodes")


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def open_upstream(up, method, target, head, rest):
    scheme, addr = up
    if method == b"CONNECT":
        host, _, port_s = target.decode().rpartition(":")
        port = int(port_s)
        if scheme == "socks5":
            remote = open_socks5(addr, host, port)
        else:
            remote = open_http_connect(addr, host, port)
        return remote, b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n", rest

    m = re.match(rb"(?i)^http://([^/:]+)(?::(\d+))?(/.*)?$", target)
    if not m:
        raise ValueError("bad http target")
    host = m.group(1).decode()
    port = int(m.group(2) or 80)
    path = m.group(3) or b"/"

    if scheme == "socks5":
        remote = open_socks5(addr, host, port)
        lines = head.split(b"\r\n")
        lines[0] = method + b" " + path + b" HTTP/1.1"
        payload = b"\r\n".join(lines) + b"\r\n\r\n" + rest
        remote.sendall(payload)
    else:
        remote = socket.create_connection(addr, timeout=8)
        remote.sendall(head + b"\r\n\r\n" + rest)
    return remote, None, b""


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cli = self.request
        cli.settimeout(25)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = cli.recv(4096)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 65536:
                return
        head, _, rest = buf.partition(b"\r\n\r\n")
        try:
            method, target, _ = head.split(b"\r\n", 1)[0].split(b" ", 2)
        except ValueError:
            return

        candidates = STATE.snapshot()
        if not candidates:
            cli.sendall(b"HTTP/1.1 503 No Upstream\r\nConnection: close\r\n\r\n")
            return

        remote = None
        for up in candidates[:6]:
            try:
                remote, immediate, pending = open_upstream(up, method, target, head, rest)
                STATE.set_current(up)
                if immediate:
                    cli.sendall(immediate)
                if pending:
                    remote.sendall(pending)
                break
            except ValueError:
                cli.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            except Exception:
                STATE.mark_bad(up)
                remote = None

        if remote is None:
            cli.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return

        try:
            t = threading.Thread(target=pump, args=(remote, cli), daemon=True)
            t.start()
            pump(cli, remote)
            t.join(timeout=5)
        finally:
            try:
                remote.close()
            except Exception:
                pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


IP_CHECK_LOCK = threading.Lock()


def query_local_exit_ip():
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        try:
            s.sendall(
                b"GET http://api.ipify.org/ HTTP/1.1\r\n"
                b"Host: api.ipify.org\r\n"
                b"Connection: close\r\n\r\n"
            )
            resp = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
        finally:
            s.close()
        if b"\r\n\r\n" not in resp:
            return "unverified"
        head, body = resp.split(b"\r\n\r\n", 1)
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            return "unverified"
        ip = body.decode("utf-8", "ignore").strip()
        return ip if IP_RE.match(ip) else "unverified"
    except Exception:
        return "unverified"


def log_exit_ip():
    if not IP_CHECK_LOCK.acquire(blocking=False):
        return
    try:
        log(f"exit ip: {query_local_exit_ip()}")
    finally:
        IP_CHECK_LOCK.release()


def replacer_loop(target_size, source_file, stop_evt):
    while not stop_evt.wait(20):
        if STATE.size() >= max(8, target_size // 3):
            continue
        try:
            if source_file:
                with open(source_file, encoding="utf-8", errors="ignore") as f:
                    cands = [p for p in (parse_proxy(line) for line in f) if p]
            else:
                cands = fetch_candidates()
            live = harvest_live(cands, max(5, target_size // 2))
            added = STATE.add_unique(live)
            if added:
                log(f"pool replenished: +{added} live nodes (total {STATE.size()})")
        except Exception:
            pass


def rotator(interval, jitter, stop_evt):
    while True:
        wait_s = max(1.0, interval * random.uniform(0.9, 1.1) if jitter else interval)
        if stop_evt.wait(wait_s):
            break
        p = STATE.rotate()
        if p:
            log(f"SWAP -> {p[1][0]}:{p[1][1]}  (served {STATE.served})")
            threading.Thread(target=log_exit_ip, daemon=True).start()


def menu():
    print(f"{RED}rotation interval{RST}")
    opts = [10, 30, 60, 120, 240]
    for n, s in enumerate(opts, 1):
        print(f"{RED}  [+] {n}: Rotate every {s} Seconds{RST}")
    while True:
        c = input(f"{RED}select [1-5]: {RST}").strip()
        if c.isdigit() and 1 <= int(c) <= 5:
            sec = opts[int(c) - 1]
            break
    while True:
        c = input(f"{RED}pool size 30-240 [60]: {RST}").strip() or "60"
        if c.isdigit() and 30 <= int(c) <= 240:
            return sec, int(c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--backend", choices=["proxy", "tor"], default="proxy")
    ap.add_argument("--file", help="local proxy list (host:port per line)")
    ap.add_argument("--jitter", action="store_true", help="+-10%% random on interval")
    ap.add_argument("--no-validate", action="store_true")
    a = ap.parse_args()

    global PORT, DIRECT_IP
    PORT = a.port
    print(f"{RED}{BANNER}{RST}")
    print(f"{RED}// exit node shuffler — cycle public ip every N seconds{RST}\n")

    sec, size = menu()

    if a.backend == "tor":
        try:
            socket.create_connection(("127.0.0.1", 9050), timeout=3).close()
        except Exception:
            sys.exit(f"{RED}tor not listening on 9050 — install/start tor first{RST}")
        STATE.load([("socks5", ("127.0.0.1", 9050))])
        log("backend: tor (circuit rotation)")
    else:
        DIRECT_IP = get_direct_ip()
        if DIRECT_IP:
            log(f"direct baseline ip: {DIRECT_IP}")
        log(f"backend: proxy pool · target {size} · interval {sec}s")
        build_pool(size, a.file, not a.no_validate)

    srv = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"listening on 127.0.0.1:{PORT}")

    stop = threading.Event()
    threading.Thread(target=rotator, args=(sec, a.jitter, stop), daemon=True).start()
    if a.backend == "proxy" and not a.no_validate:
        threading.Thread(target=replacer_loop, args=(size, a.file, stop), daemon=True).start()

    print(f"\n{RED}route traffic through it:{RST}")
    print(f"{RED}  curl -x http://127.0.0.1:{PORT} http://api.ipify.org{RST}")
    print(f"{RED}  curl -x http://127.0.0.1:{PORT} https://ifconfig.me{RST}")
    print(f"{RED}  export http_proxy=http://127.0.0.1:{PORT} https_proxy=http://127.0.0.1:{PORT}{RST}")
    print(f"{RED}ctrl-c to halt{RST}\n")
    log_exit_ip()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        srv.shutdown()
        print()
        log(f"HALTED · {STATE.served} swaps served · {STATE.size()} nodes in pool")


if __name__ == "__main__":
    main()

