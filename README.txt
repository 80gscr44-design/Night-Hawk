run this so it will work
python3 - <<'PY'
import pathlib

p = pathlib.Path.home() / "Night-Hawk" / "Night-Hawk.py"
if not p.exists():
    p = pathlib.Path.home() / "Night-Hawk" / "tools" / "Night-Hawk.py"
if not p.exists():
    p = pathlib.Path("Night-Hawk.py").resolve()

src = p.read_text(encoding="utf-8")

alias_map = {
    ("RED TEAM CYBERSECURITY", "DOS"): "dos_tool.py",
    ("RED TEAM CYBERSECURITY", "SQL Injection"): "sql_injection.py",
    ("RED TEAM CYBERSECURITY", "Admin Panel Finder"): "admin_finder.py",
    ("RED TEAM CYBERSECURITY", "Hash Cracking"): "hash_cracker.py",
    ("RED TEAM CYBERSECURITY", "Phishing"): "Fast_Phish.py",
    ("OSINT", "IP Logger"): "ip_logger.py",
    ("OPSEC", "Spoof MAC"): "mac_spoof.py",
    ("OPSEC", "IP Rotation"): "ip_rotation.py",
    ("OPSEC", "Use Proxy"): "proxy.py",
}

marker_start = "# =========================\n# MODULE Shii\n# ========================="
marker_end = "def launch_tool(category, module):"

if marker_start in src and marker_end in src:
    prefix = src[: src.index(marker_start)]
    suffix = src[src.index(marker_end) :]

    replacement_mid = f'''# =========================
# MODULE Shii
# =========================
TOOL_FILES = {{}}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = BASE_DIR if os.path.basename(BASE_DIR) == "tools" else (
    os.path.join(BASE_DIR, "tools") if os.path.isdir(os.path.join(BASE_DIR, "tools")) else BASE_DIR
)
ROOT_DIR = os.path.dirname(BASE_DIR) if os.path.basename(BASE_DIR) == "tools" else BASE_DIR

EXPLICIT_ALIASES = {alias_map!r}


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
    clean = re.sub(r"\\([^)]*\\)", " ", str(text)).lower()
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
    mapping = {{}}
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


'''
    p.write_text(prefix + replacement_mid + suffix, encoding="utf-8")
    print("Patched", p)
else:
    print("Markers not found in", p)
PY
cd ~/Night-Hawk && python3 -m py_compile Night-Hawk.py && echo "Compile OK" && python3 Night-Hawk.py

