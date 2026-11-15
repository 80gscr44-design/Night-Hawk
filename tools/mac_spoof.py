#!/usr/bin/env python3
"""
Night_Hawk - OPSEC Option 1: MAC Address Spoofing
Requires root. Changes MAC on a chosen interface (random or custom),
with restore of the original MAC.
"""

import subprocess
import random
import sys
import re
import shutil

# ---------- style: everything bold red ----------
RED = "\033[1;31m"
RESET = "\033[033m" if False else "\033[0m"

BANNER = r"""
 .S_SsS_S.    .S_SSSs      sSSs   .S   S.
.SS~S*S~SS.  .SS~SSSSS    d%%SP  .SS SS.
S%S  `Y' S%S  S%S   SSSS  d%S'    S%S S%S
S%S      S%S  S%S    S%S  S%S     S%S S%S
S%S      S%S  S%S SSSS%S  S&S     S%S S%S
S&S      S&S  S&S  SSS%S  S&S      SS SS
S&S      S&S  S&S    S&S  S&S       S_S
S&S      S&S  S&S    S&S  S&S      SS~SS
S*S      S*S  S*S    S&S  S*b     S*S S*S
S*S      S*S  S*S    S*S  S*S.    S*S S*S
S*S      S*S  S*S    S*S   SSSbs  S*S S*S
SSS      S*S  SSS    S*S    YSSP  S*S S*S
         SP          SP           SP
         Y           Y            Y
"""


def red(text: str) -> str:
    return f"{RED}{text}{RESET}"


def die(msg: str) -> None:
    print(red(f"[!] {msg}"))
    sys.exit(1)


def run(cmd, check=True):
    print(red(f"[cmd] {' '.join(cmd)}"))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"command failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return r


def require_root():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        die("Must run as root (sudo).")


def require_iproute2():
    if shutil.which("ip") is None:
        die("'ip' (iproute2) not found. apt install iproute2")


def list_interfaces():
    r = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True)
    ifaces = []
    for line in r.stdout.splitlines():
        m = re.match(r"\d+:\s+([^:@]+)", line)
        if m:
            ifaces.append(m.group(1))
    return ifaces


def get_current_mac(iface: str) -> str:
    r = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
    m = re.search(r"link/ether\s+([0-9a-f:]{17})", r.stdout)
    return m.group(1) if m else None


def random_mac() -> str:
    # Locally administered, unicast MAC
    first = random.randint(0x00, 0xFE)
    first = (first & 0xFC) | 0x02  # set locally administered bit, clear multicast
    octets = [first] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{o:02x}" for o in octets)


def valid_mac(mac: str) -> bool:
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac))


def set_mac(iface: str, mac: str):
    run(["ip", "link", "set", "dev", iface, "down"])
    run(["ip", "link", "set", "dev", iface, "address", mac])
    run(["ip", "link", "set", "dev", iface, "up"])


def main():
    print(red(BANNER))
    print(red("=" * 60))
    print(red("       NIGHT HAWK :: OPSEC :: MAC ADDRESS SPOOFER"))
    print(red("=" * 60))

    require_root()
    require_iproute2()

    ifaces = list_interfaces()
    if not ifaces:
        die("No network interfaces found.")

    print(red("\n[*] Available interfaces:"))
    for i, name in enumerate(ifaces, 1):
        cur = get_current_mac(name)
        print(red(f"    {i}) {name}  (MAC: {cur})"))

    try:
        choice = input(red("\n[?] Select interface number: ")).strip()
        iface = ifaces[int(choice) - 1]
    except (ValueError, IndexError):
        die("Invalid selection.")

    original = get_current_mac(iface)
    if not original:
        die(f"Could not read MAC for {iface}.")

    print(red("\n[*] Spoof mode:"))
    print(red("    1) Random MAC (locally administered, unicast)"))
    print(red("    2) Custom MAC"))
    print(red("    3) Restore original MAC"))
    mode = input(red("[?] Choose mode: ")).strip()

    if mode == "1":
        new_mac = random_mac()
    elif mode == "2":
        new_mac = input(red("[?] Enter MAC (e.g. de:ad:be:ef:00:01): ")).strip().lower()
        if not valid_mac(new_mac):
            die("Invalid MAC format.")
    elif mode == "3":
        set_mac(iface, original)
        print(red(f"[+] {iface} restored to {original}"))
        return
    else:
        die("Invalid mode.")

    set_mac(iface, new_mac)
    current = get_current_mac(iface)

    print(red("\n" + "-" * 60))
    print(red(f"[*] Interface : {iface}"))
    print(red(f"[*] Old MAC   : {original}"))
    print(red(f"[*] New MAC   : {current}"))
    if current == new_mac:
        print(red(f"[+] SUCCESS: MAC spoofed on {iface}"))
    else:
        print(red(f"[!] FAILURE: MAC did not change (driver/network manager may block it)"))
    print(red(f"[*] Original saved for restore: {original}"))
    print(red("-" * 60))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(red("\n[!] Aborted by user."))
        sys.exit(1)
