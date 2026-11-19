# ============================================================
#  Night-Hawk :: Main Menu & Console (Block 1/2)
# ============================================================
import re
import time
import os
import shlex
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
    "Port Scanner",
    "Vunrability Scanner"
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
    "Phone number intel",
    "IP Logger"
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
TOOL_FILES = {}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = BASE_DIR if os.path.basename(BASE_DIR) == "tools" else (
    os.path.join(BASE_DIR, "tools") if os.path.isdir(os.path.join(BASE_DIR, "tools")) else BASE_DIR
)
ROOT_DIR = os.path.dirname(BASE_DIR) if os.path.basename(BASE_DIR) == "tools" else BASE_DIR

EXPLICIT_ALIASES = {('RED TEAM CYBERSECURITY', 'DOS'): 'dos_tool.py', ('RED TEAM CYBERSECURITY', 'SQL Injection'): 'sql_injection.py', ('RED TEAM CYBERSECURITY', 'Admin Panel Finder'): 'admin_finder.py', ('RED TEAM CYBERSECURITY', 'Hash Cracking'): 'hash_cracker.py', ('RED TEAM CYBERSECURITY', 'Phishing'): 'Fast_Phish.py', ('OSINT', 'IP Logger'): 'ip_logger.py', ('OPSEC', 'Spoof MAC'): 'mac_spoof.py', ('OPSEC', 'IP Rotation'): 'ip_rotation.py', ('OPSEC', 'Use Proxy'): 'proxy.py'}


def _tools_files():
    if not os.path.isdir(TOOLS_DIR):
        return []
    self_name = os.path.basename(os.path.abspath(__file__))
    return [
        f for f in sorted(os.listdir(TOOLS_DIR))
        if f != self_name
        and f != "__init__.py"
        and not f.startswith("__")
        and os.path.isfile(os.path.join(TOOLS_DIR, f))
    ]


def _stem_of(fname):
    stem, _ = os.path.splitext(fname)
    return stem.lower()


def _tokenize_norm(text):
    clean = re.sub(r"\([^)]*\)", " ", str(text)).lower()
    raw_tokens = [t for t in re.split(r"[^a-z0-9]+", clean) if t]
    stems = set()
    for tok in raw_tokens:
        stems.add(tok)
        for suf in ("ing", "er", "ed", "s"):
            if len(tok) > len(suf) + 2 and tok.endswith(suf):
                stems.add(tok[: -len(suf)])
    return stems, re.sub(r"[^a-z0-9]+", "", clean)


def _find_tool_script(category, module):
    files = _tools_files()
    if not files:
        return None

    alias_fname = EXPLICIT_ALIASES.get((category, module))
    if alias_fname and alias_fname in files:
        return os.path.join(TOOLS_DIR, alias_fname)

    m_tokens, m_compact = _tokenize_norm(module)
    best_path = None
    best_score = 0

    for fname in files:
        stem = _stem_of(fname)
        f_tokens, f_compact = _tokenize_norm(stem)
        score = 0

        if m_compact and m_compact == f_compact:
            score += 100
        elif m_compact and (m_compact in f_compact or f_compact in m_compact):
            score += 60

        overlap = len(m_tokens & f_tokens)
        if overlap:
            score += overlap * 25

        if score > best_score:
            best_score = score
            best_path = os.path.join(TOOLS_DIR, fname)

    return best_path if best_score >= 25 else None


def _build_tool_map():
    mapping = {}
    for cat_label, items in (
        ("RED TEAM CYBERSECURITY", RED_TEAM),
        ("OSINT", OSINT),
        ("OPSEC", OPSEC),
    ):
        for mod in items:
            found = _find_tool_script(cat_label, mod)
            if found:
                mapping[(cat_label, mod)] = found
    return mapping


TOOL_FILES = _build_tool_map()


def launch_tool(category, module):
    filename = TOOL_FILES.get((category, module)) or _find_tool_script(category, module)

    if not filename:
        module_placeholder(category, module)
        return

    path = filename if os.path.isabs(filename) else os.path.join(BASE_DIR, filename)

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
        if path.endswith(".sql"):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                print(f.read())
        else:
            subprocess.run([sys.executable, path], cwd=ROOT_DIR)
    except KeyboardInterrupt:
        pass

    input(f"\n{CYAN}Press ENTER to return...{RESET}")
# ============================================================
#  Night-Hawk :: Main Menu & Console (Block 2/2)
# ============================================================
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
        rows.append((f"[+] {index}: {tool}", BOLD + RED))

    rows.append(("", BOLD + RED))
    rows.append(("OSINT", BOLD + RED))

    for index, tool in enumerate(OSINT, start=1):
        rows.append((f"[+] {index}: {tool}", BOLD + RED))

    rows.append(("", BOLD + RED))
    rows.append(("OPSEC", BOLD + RED))

    for index, tool in enumerate(OPSEC, start=1):
        rows.append((f"[+] {index}: {tool}", BOLD + RED))

    rows.append(("", BOLD + RED))
    rows.append(("[+] 0: Back", BOLD + RED))

    section_box("ALL TOOLS", rows, CYAN)

    input(f"\n{CYAN}Press ENTER to return...{RESET}")


# =========================
# CONSOLE HELP & MAIN MENU
# =========================
def console_help():
    clear()
    section_box(
        "CONSOLE HELP",
        [
            ("1 / 2 / 3 / 4 / 5 / 0", BOLD + RED),
            ("  Direct home screen shortcuts", WHITE),
            ("", WHITE),
            ("help / ?", BOLD + RED),
            ("  Open Console Help", WHITE),
            ("", WHITE),
            ("banner", BOLD + RED),
            ("  Reprint the Night-Hawk banner", WHITE),
            ("", WHITE),
            ("clear / cls", BOLD + RED),
            ("  Clear the terminal screen", WHITE),
            ("", WHITE),
            ("list / all", BOLD + RED),
            ("  Open All Tools", WHITE),
            ("", WHITE),
            ("search <keyword>", BOLD + RED),
            ("  Filter tools across Red Team, OSINT, and OpSec", WHITE),
            ("", WHITE),
            ("use <category> <number>", BOLD + RED),
            ("  Launch a tool directly (e.g. use red 1, use osint 6, use opsec 3)", WHITE),
            ("", WHITE),
            ("exit / quit", BOLD + RED),
            ("  Terminate session", WHITE),
            ("", WHITE),
            ("Press ENTER to return.", GRAY),
        ],
        CYAN
    )
    input()


def _resolve_category(name):
    key = name.strip().lower()
    if key in ("1", "red", "redteam", "red_team", "red team"):
        return ("RED TEAM CYBERSECURITY", RED_TEAM)
    if key in ("2", "osint"):
        return ("OSINT", OSINT)
    if key in ("3", "opsec"):
        return ("OPSEC", OPSEC)
    return None


def _console_search(keyword):
    clear()
    needle = keyword.strip().lower()
    rows = []
    for cat_label, items in (
        ("RED TEAM CYBERSECURITY", RED_TEAM),
        ("OSINT", OSINT),
        ("OPSEC", OPSEC),
    ):
        matches = [
            (idx, item)
            for idx, item in enumerate(items, start=1)
            if needle in item.lower() or needle in cat_label.lower()
        ]
        if matches:
            rows.append((cat_label, BOLD + RED))
            for idx, item in matches:
                rows.append((f"[+] {idx}: {item}", WHITE))
            rows.append(("", WHITE))

    if not rows:
        rows.append((f"No tools matching '{keyword}'.", YELLOW))
        rows.append(("", WHITE))

    rows.append(("Press ENTER to return.", GRAY))
    section_box(f"SEARCH: {keyword}", rows, CYAN)
    input()


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
                ("[+] 5: Console Help", BOLD + RED),
                ("[+] 0: Exit", BOLD + RED)
            ],
            CYAN
        )

        raw = prompt()
        if not raw:
            continue

        choice = raw.lower()

        if choice == "1":
            category_menu("RED TEAM CYBERSECURITY", RED_TEAM)
            continue
        elif choice == "2":
            category_menu("OSINT", OSINT)
            continue
        elif choice == "3":
            category_menu("OPSEC", OPSEC)
            continue
        elif choice == "4":
            show_all()
            continue
        elif choice in ("5", "help", "?"):
            console_help()
            continue
        elif choice in ("0", "exit", "quit"):
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

        try:
            tokens = shlex.split(raw)
        except ValueError:
            tokens = raw.split()

        cmd = tokens[0].lower()

        if cmd == "banner":
            clear()
            banner()
            input(f"\n{CYAN}Press ENTER to return...{RESET}")
        elif cmd in ("clear", "cls"):
            clear()
        elif cmd in ("list", "all"):
            show_all()
        elif cmd == "search" and len(tokens) >= 2:
            _console_search(" ".join(tokens[1:]))
        elif cmd == "use" and len(tokens) >= 3 and tokens[2].isdigit():
            resolved = _resolve_category(tokens[1])
            if resolved is not None:
                cat_label, items = resolved
                idx = int(tokens[2])
                if 1 <= idx <= len(items):
                    launch_tool(cat_label, items[idx - 1])
                else:
                    print(f"{RED}[!] Tool index out of range.{RESET}")
                    time.sleep(1)
            else:
                print(f"{RED}[!] Unknown category. Use: red, osint, or opsec.{RESET}")
                time.sleep(1)
        else:
            print(f"{RED}[!] Unknown command. Type '5' or 'help' for Console Help.{RESET}")
            time.sleep(1)


# =========================
# START APPLICATION
# =========================
if __name__ == "__main__":
    main()

