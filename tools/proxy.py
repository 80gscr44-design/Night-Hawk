#!/usr/bin/env python3
"""
Night_Hawk - OPSEC Option 4: Use Proxy
Configure, test, and apply HTTP / SOCKS4 / SOCKS5 proxies.
Optionally writes proxychains4 config and prints export lines.
"""

import subprocess
import sys
import shutil
import os
from urllib.parse import urlparse

# ---------- style: everything bold red ----------
RED = "\033[1;31m"
RESET = "\033[0m"

BANNER = r"""
██▓███   ███▀███   ▒█████  ▒██   ██▒▓██   ██▓
▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▒▒ █ █ ▒░ ▒██  ██▒
▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒░░ ███  ░  ▒██ ██░
▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░ ░ █ █ ▒   ░ ▐██▓░
▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░▒██▒ ▒██▒  ░ ██▒▓░
▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▒ ░ ░▓ ░   ██▒▒▒
░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░ ▓██ ░▒░
░░         ░░   ░ ░ ░ ░ ▒   ░    ░   ▒ ▒ ░░
            ░         ░ ░   ░    ░   ░ ░
                                     ░ ░
"""

PROXYCHAINS_CONF_CANDIDATES = [
    "/etc/proxychains4.conf",
    "/etc/proxychains.conf",
]


def red(text: str) -> str:
    return f"{RED}{text}{RESET}"


def die(msg: str) -> None:
    print(red(f"[!] {msg}"))
    sys.exit(1)


def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    return r


def check_root_soft():
    """Root only needed for writing proxychains conf."""
    out = run(["id", "-u"], timeout=5)
    return out is not None and out.stdout.strip() == "0"


def parse_proxy(raw: str, scheme: str):
    """Build scheme://[user:pass@]host:port and (scheme, host, port)."""
    raw = raw.strip()
    if "://" in raw:
        u = urlparse(raw)
    else:
        # expect host:port
        u = urlparse(f"{scheme}://{raw}")

    if not u.hostname or not u.port:
        die(f"Could not parse proxy '{raw}'. Use host:port or full URL.")

    rebuilt = f"{u.scheme}://"
    if u.username:
        rebuilt += f"{u.username}:{u.password or ''}@"
    rebuilt += f"{u.hostname}:{u.port}"
    return rebuilt, u.scheme, u.hostname, u.port


def test_proxy(proxy_url: str, timeout=15):
    """Return the exit IP seen through the proxy, or None."""
    env = os.environ.copy()
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url
    env["ALL_PROXY"] = proxy_url

    r = subprocess.run(
        ["curl", "-s", "--max-time", str(timeout), "https://api.ipify.org"],
        env=env,
        capture_output=True,
        text=True,
    )
    ip = r.stdout.strip()
    if r.returncode == 0 and ip:
        return ip
    return None


def direct_ip():
    r = run(["curl", "-s", "--max-time", "10", "https://api.ipify.org"])
    if r and r.returncode == 0:
        return r.stdout.strip()
    return None


def write_proxychains(scheme, host, port):
    """Write socks5/socks4/http proxy as last entry in proxychains conf."""
    conf = next((c for c in PROXYCHAINS_CONF_CANDIDATES if os.path.exists(c)), None)
    if not conf:
        print(red("[!] No proxychains config found (skipping write)."))
        return None

    line = f"proxy_type\t{scheme}\t{host}\t{port}"

    with open(conf) as f:
        content = f.read()

    # find [ProxyList] section
    marker = "[ProxyList]"
    if marker not in content:
        print(red(f"[!] {conf} has no [ProxyList] section (skipping write)."))
        return conf

    head, tail = content.split(marker, 1)
    # drop our old Night_Hawk entries, keep user's own entries
    tail_lines = [
        l for l in tail.splitlines()
        if "Night_Hawk-proxy-entry" not in l
        and not l.strip().startswith(f"proxy_type\t{scheme}\t{host}\t{port}")
    ]

    new_tail = tail_lines + [f"{line}  # Night_Hawk-proxy-entry"]
    new_content = head + marker + "\n" + "\n".join(new_tail) + "\n"

    with open(conf, "w") as f:
        f.write(new_content)

    return conf


def main():
    print(red(BANNER))
    print(red("=" * 60))
    print(red("        NIGHT HAWK :: OPSEC :: PROXY CONFIGURATOR"))
    print(red("=" * 60))

    print(red("\n[*] Proxy type:"))
    print(red("    1) HTTP"))
    print(red("    2) SOCKS4"))
    print(red("    3) SOCKS5"))
    t = input(red("[?] Choose type: ")).strip()

    scheme = {"1": "http", "2": "socks4", "3": "socks5"}.get(t)
    if not scheme:
        die("Invalid type.")

    raw = input(red("[?] Proxy (host:port or user:pass@host:port): ")).strip()
    if not raw:
        die("No proxy given.")

    proxy_url, scheme, host, port = parse_proxy(raw, scheme)

    print(red("\n[*] Checking direct exit IP..."))
    direct = direct_ip()
    print(red(f"[*] Direct IP: {direct or 'unavailable'}"))

    print(red(f"[*] Testing proxy {proxy_url} ..."))
    proxied = test_proxy(proxy_url)

    if proxied:
        print(red(f"[+] Proxy works. Exit IP through proxy: {proxied}"))
        if direct and direct == proxied:
            print(red("[!] WARNING: exit IP matches direct IP — proxy may be transparent or not applied."))
    else:
        print(red("[!] Proxy test FAILED (no response or bad credentials)."))

    print(red("\n[*] Apply where?"))
    print(red("    1) Print export lines (current shell traffic)"))
    print(red("    2) Write to proxychains4 config"))
    print(red("    3) Both"))
    print(red("    4) Nothing, just exit"))
    mode = input(red("[?] Choose: ")).strip()

    if mode in ("1", "3"):
        print(red("\n[+] Paste these into your shell:"))
        print(red(f"    export http_proxy={proxy_url}"))
        print(red(f"    export https_proxy={proxy_url}"))
        print(red(f"    export ALL_PROXY={proxy_url}"))
        print(red(f"    export HTTP_PROXY={proxy_url}"))
        print(red(f"    export HTTPS_PROXY={proxy_url}"))

    if mode in ("2", "3"):
        if not check_root_soft():
            print(red("[!] Not root — cannot write proxychains config. Re-run with sudo."))
        else:
            conf = write_proxychains(scheme, host, port)
            if conf:
                print(red(f"[+] Written to {conf}"))
                if shutil.which("proxychains4") or shutil.which("proxychains"):
                    print(red("[+] Use it like:  proxychains4 <command>"))
                else:
                    print(red("[!] proxychains not installed:  apt install proxychains4"))

    print(red("\n[*] Done."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(red("\n[!] Aborted by user."))
        sys.exit(1)
PY
