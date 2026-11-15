import time
import os
import shutil
import subprocess
import sys
from wcwidth import wcswidth

# =========================
# COLORS
# =========================
RED = "\033[91m"
DARK_RED = "\033[31m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


# =========================
# TERMINAL UTILITIES
# =========================
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def terminal_width():
    return min(shutil.get_terminal_size((80, 24)).columns - 2, 80)


def box_top(title="", color=CYAN):
    width = terminal_width()

    if title:
        title_text = f" {title} "
        title_width = wcswidth(title_text)

        remaining = width - title_width
        left = remaining // 2
        right = remaining - left

        print(
            color + "╔"
            + "═" * left
            + title_text
            + "═" * right
            + "╗" + RESET
        )
    else:
        print(color + "╔" + "═" * width + "╗" + RESET)


def box_bottom(color=CYAN):
    width = terminal_width()
    print(color + "╚" + "═" * width + "╝" + RESET)


def box_row(text="", color=WHITE, border_color=CYAN):
    width = terminal_width()
    inner_width = width

    text = str(text)
    text_width = wcswidth(text)

    if text_width > inner_width:
        text = text[:inner_width]
        text_width = wcswidth(text)

    padding = inner_width - text_width

    print(
        border_color + "║" + RESET
        + color + text + (" " * padding) + RESET
        + border_color + "║" + RESET
    )


def section_box(title, rows, border_color=CYAN):
    box_top(title, border_color)

    for row in rows:
        if isinstance(row, tuple):
            text, color = row
        else:
            text, color = row, WHITE

        box_row(text, color, border_color)

    box_bottom(border_color)


def prompt():
    return input(
        f"\n{BOLD}{RED}Night-Hawk{RESET} {CYAN}» {RESET}"
    ).strip()


# =========================
# ASCII ART
# =========================
def banner():
    art = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⣟⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⢟   ⣻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢰⣿       ⣷⡀⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⢻        ⣿⣿⡜⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣿⣿⡿⠿⠿⠟⠛⠛⠃⣾          ⣿⡘⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⣿⣿⠀⠀⠀⠀⠀⠀⢸            ⣧⠀⠈⠉⠛⠻⠿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⢀⣿             ⣿⡄⠀⠀⠀⠀⠀⠀⠉⠻⢿⣧⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣾               ⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣄⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⣿⡀⠀⠀ ⣾                 ⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⢐⣼                 ⣞⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀
⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⢺⣿                 ⡿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⠀
⠀⠀⠀⠀⠀⠀⢸⢹⡇⠀⣰⣾⣿⣿               ⣿⣿⣿⣷⣄ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃
⠀⠀⠀⠀⠀⣀⣼⣿⡿⣰⣿⣿⣿⣿⣿⣿⣿⣷       ⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧ ⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡴⣻⣿⣿⣷⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣾⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀
⠀⠀⢰⣇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡃⠀⠀⠀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀
⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀
 ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣿⣿⣿⣿⣿⣆⠀⠀⠀
 ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⢿⣿⠀⠀⠀
 ⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⡇⣿⡿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⣸⣿⠀⠀⠀
 ⣿⣿⣿⣿⣿⢻⣿⣿⣿⡁⣧⣿⣷⡏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣧⣿⣿⣿⣿⣿⣿⠀⠀⠀
⠀⣿⣿⣿⣿⣿⢹⣿⣿⣿⡅⡟⢻⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⢸⣿⣿⣿⠀⢸⡇⣿⣿⣿⣿⢻⣿⠀⠀⠀
⠀⣿⡟⣿⠻⣿⢸⣿⣿⣿⡅⡇⣸⣿⠃⣿⣿⣿⣿⡿⣿⣿⡿⢼⣿⢸⣿⣿⣹⢸⣿⣿⣿⠀⢸⡇⣿⣿⣿⣿⢸⣿⠀⠀⠀
⠀⣿⣧⣿⢠⣿⢸⢹⣿⣿⠆⡇⢸⡿⠀⣿⣿⣿⣿⡟⢻⣿⡇⣿⣿⢸⣿⣿⢸⢸⣿⠀⣿⠀⢸⡇⣿⣿⣿⣿⢸⣿⠀⠀⠀
⠀⣿⡟⣿⢸⡟⢸⠘⣿⣿⡃⡇⢸⡇⠀⣿⡇⠹⣿⡇⢸⣿⡇⢻⣿⢸⣿⠙⢸⢸⣿⠀⣿⠀⢸⡇⣿⡇⣿⣿⢸⣿⠀⠀⠀
⠀⢹⡇⢾⠸⡇⢸⠀⣿⣿⡅⠀⢸⡇ ⣿⡇0⣿⠇⠸⣿⠀⢸⡿⢸⣿⡆⢸⠈⢹⠄⠉⠀⢸⡇⢸⡇⣿⣿⠈⣿⡄⠀⠀
 ⡇⢻⠀⡇⢸⠀⣿⣿1⠀⢸⡇0⣿⡇⠀⣿⠀⠐⣿⡀⢸⡟⢸⡿⠁⢸⠀⢸⠆1⠀⢸⡇⢸⡇⠉⣿⠀⣿⡇⠀⠀
⠀ ⡇⣹1⠁⢸⠀⢻⣿⠀⡀⢸⡇⠀⣿⡇⠀⣯0⠀⣿⠆⠀⡇⢸⡇⠀⢸⠀⢸⡃⠀⠀⢸⡇⠸⡇⠀⣿⢸⡇⠀⠀
⠀   ⠸⡇⢼⠀0⠀⢸⢸⣿⠀⠀⢸⡇1⣿⡇⠀⡗⠀0⢸⡇⠀1⠘⡇1⢸⠀⢸⡅⠀0⢸⡇⣿⢸⡇⠀⠀
⠀    0 ⡇⢸⠀0⠀⠀⢸⣿⠀0⢸⡇ ⣿⡇⠀⣏⠀⠀⢸⡇1  ⠀0⢸⠀⢸⠆⠀⠀⢸⡇0⠀⠀
        11     0     1    1       10    ⡿⠀⠀
                1          0       1
    """

    print(RED + BOLD + art + RESET)
# =========================
# TOOL LISTS
# =========================
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
    "URL Masker",
    "Deauth Attack",
    "Evil Twin",
    "Port Scanner"
    
]

OSINT = [
    "Search / Dorking ",
    "Shodan Intel Search ",
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
    "Generate Professional PDF / TXT",
    "Phone number intel"
]

OPSEC = [
    "Spoof MAC",
    "IP Rotation",
    "Use Tor Network",
    "Use Proxy"
]

# =========================
# MODULE Shii
# =========================
TOOL_FILES = {
    ("RED TEAM CYBERSECURITY", "DOS"): "tools/dos_tool.py",
    ("RED TEAM CYBERSECURITY", "Hash Cracking"): "tools/hash_cracker.py",
    ("RED TEAM CYBERSECURITY", "Admin Panel Finder"): "tools/admin_finder.py",
    ("RED TEAM CYBERSECURITY", "SQL Injection"): "tools/sql_injection.py",
    ("OPSEC", "IP Rotation"): "tools/ip_rotation.py",
    ("OPSEC", "Spoof MAC"): "tools/mac_spoof.py",
    ("OPSEC", "Use Tor Network"): "tools/tor_router.py",
    ("OPSEC", "Use Proxy"): "tools/proxy.py",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def launch_tool(category, module):
    filename = TOOL_FILES.get((category, module))

    if not filename:
        module_placeholder(category, module)
        return

    path = os.path.join(BASE_DIR, filename)

    clear()

    if not os.path.exists(path):
        section_box(
            f"{category} MODULE",
            [
                (f"Selected: {module}", BOLD + RED),
                ("", WHITE),
                (f"MISSING FILE: {filename}", YELLOW),
                ("Place it next to this script.", GRAY),
                ("", WHITE),
                ("Press ENTER to return.", GRAY)
            ],
            CYAN
        )
        input()
        return

    try:
        subprocess.run([sys.executable, path], cwd=BASE_DIR)
    except KeyboardInterrupt:
        pass

    input(f"\n{CYAN}Press ENTER to return...{RESET}")


# =========================
# PLACEHOLDER SCREEN
# =========================
def module_placeholder(category, module):
    clear()

    section_box(
        f"{category} MODULE",
        [
            (f"Selected: {module}", BOLD + RED),
            ("", WHITE),
            ("GUI PLACEHOLDER", CYAN),
            ("This option is a label only.", YELLOW),
            ("No tool is being executed.", GREEN),
            ("", WHITE),
            ("Press ENTER to return.", GRAY)
        ],
        CYAN
    )

    input()


# =========================
# CATEGORY MENU
# =========================
def category_menu(category, tools):
    while True:
        clear()

        rows = []

        for index, tool in enumerate(tools, start=1):
            rows.append((f"[+] {index}: {tool}", BOLD + RED))

        rows.append(("", WHITE))
        rows.append(("[+] 0: Back", BOLD + RED))

        section_box(category, rows, CYAN)

        choice = prompt()

        if choice in ("0", "00"):
            break

        if choice.isdigit():
            index = int(choice)

            if 1 <= index <= len(tools):
                launch_tool(category, tools[index - 1])


# =========================
# SHOW ALL TOOLS
# =========================
def show_all():
    clear()

    rows = [
        ("RED TEAM CYBERSECURITY", BOLD + RED)
    ]

    for index, tool in enumerate(RED_TEAM, start=1):
        rows.append((f"[+] {index}: {tool}", WHITE))

    rows.append(("", WHITE))
    rows.append(("OSINT", BOLD + RED))

    for index, tool in enumerate(OSINT, start=1):
        rows.append((f"[+] {index}: {tool}", WHITE))

    rows.append(("", WHITE))
    rows.append(("OPSEC", BOLD + RED))

    for index, tool in enumerate(OPSEC, start=1):
        rows.append((f"[+] {index}: {tool}", WHITE))

    rows.append(("", WHITE))
    rows.append(("[+] 0: Back", BOLD + RED))

    section_box("ALL TOOLS", rows, CYAN)

    input(f"\n{CYAN}Press ENTER to return...{RESET}")


# =========================
# MAIN MENU
# =========================
def main():
    while True:
        clear()
        banner()
        print()

        section_box(
            "MAIN MENU",
            [
                ("[+] 1: Red Team Cybersecurity", BOLD + RED),
                ("[+] 2: OSINT", BOLD + RED),
                ("[+] 3: OpSec", BOLD + RED),
                ("[+] 4: Show All", BOLD + RED),
                ("[+] 0: Exit", BOLD + RED)
            ],
            CYAN
        )

        choice = prompt()

        if choice == "1":
            category_menu("RED TEAM CYBERSECURITY", RED_TEAM)

        elif choice == "2":
            category_menu("OSINT", OSINT)

        elif choice == "3":
            category_menu("OPSEC", OPSEC)

        elif choice == "4":
            show_all()

        elif choice == "0":
            clear()

            section_box(
                "NIGHT-HAWK",
                [
                    ("SESSION TERMINATED", BOLD + RED),
                    ("THANK YOU", CYAN)
                ],
                CYAN
            )

            break


# =========================
# START APPLICATION
# =========================
if __name__ == "__main__":
    main()
