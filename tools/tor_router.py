import os
import socket
import subprocess
import sys
from wcwidth import wcswidth


RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

RED_TEAM = [
    "DOS",
    "SQL Injection",
    "Admin Panel Finder",
    "Hash Cracking",
    "Bruteforce (Credential Stuffing)",
    "Phishing",
    "Password Spraying",
    "XSS (Cross-Site Scripting)",
    "Web Defacement",
    "Deauth Attack",
    "Port Scanner"
]

OSINT = [
    "Search / Dorking",
    "Shodan Intel Search",
    "Check Password Against Corpus",
    "Email Check + Breach Portals",
    "List Breach-Check Portals",
    "WHOIS Domain Lookup",
    "IP Forensics Lookup",
    "Reverse DNS",
    "Domain History / Logs",
    "DNS Record",
    "Metadata Stripper / Viewer",
    "Linked Social Accounts (Email / User)",
    "Phone number intel"
]

OPSEC = [
    "IP Rotation"
]

# Paths are relative to the Night-Hawk project directory.
# Add entries for the tools that exist in your project.
TOOL_FILES = {
    ("RED TEAM CYBERSECURITY", "DOS"): "tools/dos_tool.py",
    ("RED TEAM CYBERSECURITY", "SQL Injection"): "tools/sql_injection.py",
    ("RED TEAM CYBERSECURITY", "Admin Panel Finder"): "tools/admin_finder.py",
    ("RED TEAM CYBERSECURITY", "Hash Cracking"): "tools/hash_cracker.py",
    ("OPSEC", "IP Rotation"): "tools/ip_rotation.py",
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def terminal_width():
    return max(20, min(shutil_width() - 2, 80))


def shutil_width():
    import shutil
    return shutil.get_terminal_size((80, 24)).columns


def box_top(title="", color=CYAN):
    width = terminal_width()

    if title:
        title_text = f" {title} "
        remaining = width - wcswidth(title_text)
        left = max(0, remaining // 2)
        right = max(0, remaining - left)
        print(color + "╔" + "═" * left + title_text + "═" * right + "╗" + RESET)
    else:
        print(color + "╔" + "═" * width + "╗" + RESET)


def box_bottom(color=CYAN):
    print(color + "╚" + "═" * terminal_width() + "╝" + RESET)


def box_row(text="", color=WHITE, border_color=CYAN):
    width = terminal_width()
    text = str(text)

    # Keep the border aligned even if the terminal is narrow.
    while wcswidth(text) > width:
        text = text[:-1]

    padding = width - wcswidth(text)
    print(
        border_color + "║" + RESET
        + color + text + (" " * padding) + RESET
        + border_color + "║" + RESET
    )


def section_box(title, rows, border_color=CYAN):
    box_top(title, border_color)
    for text, color in rows:
        box_row(text, color, border_color)
    box_bottom(border_color)


def tor_available():
    try:
        with socket.create_connection((TOR_HOST, TOR_PORT), timeout=2):
            return True
    except OSError:
        return False


def main():
    clear()

    art = r"""
ooooooooooooo                    
8'   888   `8                    
     888       .ooooo.  oooo d8b 
     888      d88' `88b `888""8P 
     888      888   888  888     
     888      888   888  888     
    o888o     `Y8bod8P' d888b    
"""
    print(RED + BOLD + art + RESET)

    # Numbering continues across categories so each selection is unique.
    all_tools = []
    rows = []

    for category, tools in (
        ("RED TEAM CYBERSECURITY", RED_TEAM),
        ("OSINT", OSINT),
        ("OPSEC", OPSEC),
    ):
        rows.append((category, BOLD + RED))
        for tool in tools:
            all_tools.append((category, tool))
            rows.append((f"[+] {len(all_tools)}: {tool}", BOLD + RED))
        rows.append(("", WHITE))

    rows.extend([
        (f"Tor SOCKS5 proxy: {TOR_HOST}:{TOR_PORT}", YELLOW),
        ("Enter tool number(s), comma-separated. Example: 1, 4, 7", CYAN),
        ("[+] 0: Back", BOLD + RED),
    ])
    section_box("Route Through Tor", rows)

    selection = input(f"\n{BOLD}{RED}Enter Selection:{RESET} ").strip()
    if selection in ("", "0"):
        return

    try:
        numbers = sorted({int(part.strip()) for part in selection.split(",")})
    except ValueError:
        input(f"{YELLOW}Invalid selection. Press ENTER to exit...{RESET}")
        return

    if any(number < 1 or number > len(all_tools) for number in numbers):
        input(f"{YELLOW}Selection out of range. Press ENTER to exit...{RESET}")
        return

    if not tor_available():
        input(
            f"{YELLOW}Tor is not listening at {TOR_HOST}:{TOR_PORT}. "
            f"Start Tor and try again. Press ENTER to exit...{RESET}"
        )
        return

    # Night-Hawk is expected to run this script from the project directory.
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    for number in numbers:
        category, tool = all_tools[number - 1]
        relative_path = TOOL_FILES.get((category, tool))

        if relative_path is None:
            print(f"{YELLOW}No script configured for {tool}; skipping.{RESET}")
            continue

        script_path = os.path.join(project_dir, relative_path)
        if not os.path.isfile(script_path):
            print(f"{YELLOW}Missing script: {relative_path}{RESET}")
            continue

        env = os.environ.copy()
        proxy = f"socks5h://{TOR_HOST}:{TOR_PORT}"
        for name in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
                     "HTTPS_PROXY", "https_proxy"):
            env[name] = proxy

        print(f"\n{CYAN}Launching {tool} with Tor proxy settings...{RESET}")
        try:
            subprocess.run(
                [sys.executable, script_path],
                cwd=project_dir,
                env=env,
                check=False,
            )
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted.{RESET}")
            break

    input(f"\n{CYAN}Press ENTER to exit...{RESET}")


if __name__ == "__main__":
    main()
