#!/usr/bin/env python3
# ============================================================
#  Night-Hawk :: Admin Panel Finder (./nh Suite Edition)
#  Block 1/2: Paths, bold-red output, ASCII art, signatures, CORE
# ============================================================
import hashlib
import json
import os
import random
import re
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

RED = "\033[1;31m"
RST = "\033[0m"

HERE = Path(__file__).resolve().parent
SUITE_ROOT = HERE.parent if HERE.name == "tools" else HERE
OUT_DIR = SUITE_ROOT / "reports"

ART = (
    "      d8888      888               d8b          Y88b   d88P\n"
    "     d88888      888               Y8P           Y88b d88P\n"
    "    d88P888      888                              Y88o88P\n"
    "   d88P 888  .d88888 88888b.d88b.  888 88888b.     Y888P\n"
    '  d88P  888 d88" 888 888 "888 "88b 888 888 "88b    d888b\n'
    " d88P   888 888  888 888  888  888 888 888  888   d88888b\n"
    "d8888888888 Y88b 888 888  888  888 888 888  888  d88P Y88b\n"
    'd88P     88  "Y88888 888  888  888 888 888  888 d88P   Y88b'
)

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

SIGNATURES = {
    "WordPress":    ["wp-login", "wp-admin", "wp-content", "wordpress"],
    "phpMyAdmin":   ["phpmyadmin", "pma_", "pma_username"],
    "Adminer":      ["adminer"],
    "Joomla":       ["joomla", "com_login", "mod_login"],
    "Drupal":       ["drupal", "user-login", "form-item-name"],
    "Django":       ["csrfmiddlewaretoken", "django"],
    "Rails":        ["authenticity_token", "rails"],
    "Jenkins":      ["jenkins"],
    "Grafana":      ["grafana"],
    "Kibana":       ["kibana"],
    "GitLab":       ["gitlab"],
    "Jira":         ["jira", "atlassian"],
    "Confluence":   ["confluence", "atlassian"],
    "Tomcat":       ["tomcat", "manager/html"],
    "Webmin":       ["webmin", "usermin"],
    "cPanel":       ["cpanel", "cpsess"],
    "Plesk":        ["plesk"],
    "Zabbix":       ["zabbix"],
    "Nagios":       ["nagios"],
    "Cacti":        ["cacti"],
    "Roundcube":    ["roundcube"],
    "SquirrelMail": ["squirrelmail"],
    "OWA":          ["outlook web app", "owa/logon"],
    "ADFS":         ["adfs", "adfs/ls"],
    "pfSense":      ["pfsense"],
    "OPNsense":     ["opnsense"],
    "UniFi":        ["unifi", "unifi controller"],
    "Portainer":    ["portainer"],
    "Rancher":      ["rancher"],
    "Prometheus":   ["prometheus"],
    "Traefik":      ["traefik"],
    "Spring":       ["whitelabel error", "spring boot", "_links"],
    "Swagger":      ["swagger-ui", "swagger"],
    "CyberPanel":   ["cyberpanel"],
    "VestaCP":      ["vesta", "vestacp"],
    "ISPConfig":    ["ispconfig"],
    "Pterodactyl":  ["pterodactyl"],
    "SonarQube":    ["sonarqube", "sonar"],
    "Metabase":     ["metabase"],
    "Superset":     ["superset"],
    "Airflow":      ["airflow"],
}

RAW_CORE = [
    "admin", "admin/", "admin/index.php", "admin/login.php", "admin/login",
    "admin/index.html", "admin/index.htm", "admin/index.aspx", "admin/index.jsp",
    "admin/default.aspx", "admin/Login.aspx", "admin/login.aspx", "admin/login.asp",
    "admin/login.jsp", "admin/login.html", "admin/home.php", "admin/home.aspx",
    "admin/panel", "admin/console", "admin/dashboard", "admin/account/login",
    "admin/auth", "admin/secure", "admin/manage", "admin/settings",
    "admin/config", "admin/system", "admin/users", "admin/members",
    "admin/tools", "admin/db", "admin/sql", "admin/logs", "admin/info.php",
    "admin/phpinfo.php", "admin/upload", "admin/backup", "admin/content",
    "admin/media", "admin/files", "admin/reports", "admin/analytics",
    "admin/roles", "admin/permissions", "admin/audit", "admin/api",
    "admin/swagger", "admin/docs", "admin/status", "admin/health",
    "admincp", "admincp/", "admincp/index.php", "admincp/login.php",
    "adminpanel", "adminpanel.php", "adminpanel.aspx", "adminpanel/",
    "admin_area", "admin_area/", "admin_area/login", "admin_area/admin.php",
    "adminarea", "adminarea/", "admin-console", "admin-console/",
    "admin_console", "admin-panel", "admin_panel", "admin-login", "admin_login",
    "administrator", "administrator/", "administrator/index.php",
    "administrator/login.php", "administrator/login", "administrator/account",
    "admin.php", "admin.html", "admin.htm", "admin.aspx", "admin.asp",
    "admin.jsp", "admin.do", "admin.cgi", "admin.pl", "admin.action",
    "admin/index.action", "admin/portal", "admin1", "admin2", "adm", "adm/",
    "acp", "acp/", "backend", "backend/", "backend/login", "backend/admin",
    "backoffice", "backoffice/", "back-office", "back-office/",
    "panel", "panel/", "panel/login", "panel/admin", "dashboard", "dashboard/",
    "dashboard/login", "dashboard/admin", "dash", "dash/",
    "console", "console/", "console/login", "console/login/LoginForm.jsp",
    "controlpanel", "controlpanel/", "control-panel", "control-panel/",
    "control_panel", "cpanel", "cpanel/", "whm", "whm/", "webadmin",
    "webadmin.php", "webadmin/", "webadmin/index.php", "webmaster",
    "webmaster/", "sysadmin", "sysadmin/", "siteadmin", "siteadmin/",
    "manage", "manage/", "manage/login", "management", "management/",
    "management/console", "mgmt", "mgmt/", "manager", "manager/",
    "manager/html", "manager/status", "moderator", "moderator/", "mod", "mod/",
    "staff", "staff/", "staff/login", "employee", "employee/", "employees",
    "employees/", "portal", "portal/", "portal/login", "portal/admin",
    "intranet", "intranet/", "extranet", "extranet/",
    "login", "login/", "login.php", "login.html", "login.htm", "login.aspx",
    "login.asp", "login.jsp", "login.do", "login.action", "login/admin",
    "signin", "signin/", "sign-in", "sign-in/", "sign_in", "sign_in/",
    "logon", "logon/", "logon.aspx", "logon.php", "log-in",
    "auth", "auth/", "auth/login", "auth/signin", "auth/admin", "auth/realms",
    "accounts", "accounts/", "accounts/login", "accounts/signin",
    "account/login", "account/signin", "users/sign_in", "users/login",
    "user/login", "user/signin", "session/new", "session/login", "sessions/new",
    "secure", "secure/", "secure/login", "secure/admin", "security",
    "private", "private/", "private/login", "private/admin",
    "internal", "internal/", "internal/login", "restricted", "restricted/",
    "members", "members/", "members/login", "member", "member/login",
    "client", "client/login", "clients", "clients/login", "customer/login",
    "customers/login", "partner", "partner/login", "partners", "partners/login",
    "vendor", "vendor/login", "vendors/login", "supplier/login",
    "j_security_check", "sso", "sso/", "sso/login", "cas", "cas/login",
    "oauth", "oauth/", "oauth/authorize", "oauth2", "oauth2/", "oauth2/authorize",
    "openid", "openid/", "oidc", "oidc/", "saml", "saml/", "saml2",
    "adfs/ls", "adfs/ls/", "certsrv", "certsrv/", "owa", "owa/", "ecp", "ecp/",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-admin/admin.php",
    "wp-admin/index.php", "wp-admin/setup-config.php", "wp-admin/install.php",
    "xmlrpc.php", "wp-json/wp/v2/users", "wp-config.php.bak",
    "phpmyadmin", "phpmyadmin/", "phpMyAdmin", "phpMyAdmin/", "pma", "pma/",
    "myadmin", "myadmin/", "mysql", "mysql/", "mysqladmin", "mysql-admin",
    "sqladmin", "sqlmanager", "dbadmin", "db", "db/", "database", "database/",
    "phpmysql", "phpPgAdmin", "phppgadmin", "pgadmin", "pgadmin/",
    "adminer.php", "adminer", "adminer/", "rockmongo", "mongo", "mongo-express",
    "sqlite", "sqlitebrowser", "redis-commander", "kibana", "grafana",
    "joomla/administrator", "administrator/index.php", "typo3", "typo3/",
    "typo3/login.php", "drupal", "drupal/user", "drupal/user/login",
    "user/register", "user/password", "magento", "magento/admin",
    "magento/index.php/admin", "shop/admin", "store/admin", "cart/admin",
    "prestashop/admin", "opencart/admin", "shopify/admin", "umbraco",
    "umbraco/", "kentico/cmsdesk", "sitecore/login", "sitecore/shell",
    "laravel/log-viewer", "telescope", "horizon", "nova", "nova/login",
    "filament", "filament/login", "django-admin", "__admin__",
    "rails/info", "rails/mailers", "sidekiq", "sidekiq/", "flower",
    "actuator", "actuator/", "actuator/health", "actuator/env",
    "swagger-ui", "swagger-ui/", "swagger-ui.html", "swagger", "api-docs",
    "openapi.json", "openapi.yaml", "graphql", "graphiql", "playground",
    "debug", "debug/", "_debugbar", "elmah.axd", "trace.axd", "server-status",
    "server-info", "status", "health", "healthz", "readyz", "metrics",
]

CORE = list(dict.fromkeys(RAW_CORE))


def rprint(msg: str, stream=sys.stdout) -> None:
    for line in str(msg).splitlines():
        stream.write(f"{RED}{line}{RST}\n")
    stream.flush()
# ============================================================
#  Night-Hawk :: Admin Panel Finder (./nh Suite Edition)
#  Block 2/2: Engine, soft-404 filter, scorer, crawler, run()
# ============================================================
class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts = []
        self.links = []
        self.form_actions = []
        self.scripts = []
        self.form_count = 0
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.tag_sequence = []

    def handle_starttag(self, tag, attrs):
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        self.tag_sequence.append(tag)
        if tag == "title":
            self.in_title = True
        elif tag == "a" and "href" in attr_map:
            self.links.append(attr_map["href"])
        elif tag == "form":
            self.form_count += 1
            if "action" in attr_map:
                self.form_actions.append(attr_map["action"])
        elif tag == "script" and "src" in attr_map:
            self.scripts.append(attr_map["src"])
        elif tag == "input":
            itype = attr_map.get("type", "text").lower()
            if itype == "password":
                self.password_inputs += 1
            elif itype == "hidden":
                self.hidden_inputs += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.title_parts)).strip()


@dataclass
class PageProfile:
    status: int | None
    final_url: str
    length: int
    title: str
    form_count: int
    password_inputs: int
    hidden_inputs: int
    skeleton: str
    headers: dict = field(default_factory=dict)


class TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append((code, req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RateLimiter:
    def __init__(self, rps: float = 10.0):
        self.interval = 1.0 / max(rps, 0.1)
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            wait_for = max(0.0, self.next_time - now)
            self.next_time = max(now, self.next_time) + self.interval
        if wait_for > 0:
            time.sleep(wait_for + random.uniform(0.0, self.interval * 0.25))


def build_opener_with_tracker(insecure: bool = True):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    tracker = TrackingRedirectHandler()
    opener = build_opener(tracker, HTTPSHandler(context=ctx))
    return opener, tracker


def build_skeleton(html: str, parser: _PageParser) -> str:
    stripped = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.S | re.I)
    stripped = re.sub(r"<style\b[^>]*>.*?</style>", "", stripped, flags=re.S | re.I)
    stripped = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<HEX>", stripped)
    stripped = re.sub(r"\b\d{4,}\b", "<NUM>", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    tag_sig = "|".join(parser.tag_sequence[:120])
    return f"{tag_sig}::{stripped[:3000]}"


def fetch_with_retry(
    insecure: bool,
    url: str,
    timeout: int,
    retries: int,
    limiter: RateLimiter,
) -> tuple[PageProfile | None, str, list]:
    for attempt in range(retries + 1):
        limiter.acquire()
        opener, tracker = build_opener_with_tracker(insecure)
        headers = {
            "User-Agent": random.choice(UAS),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        req = Request(url, headers=headers, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(262_144)
                body = raw.decode("utf-8", errors="replace")
                parser = _PageParser()
                try:
                    parser.feed(body)
                except Exception:
                    pass
                profile = PageProfile(
                    status=resp.status,
                    final_url=resp.geturl(),
                    length=len(raw),
                    title=parser.title,
                    form_count=parser.form_count,
                    password_inputs=parser.password_inputs,
                    hidden_inputs=parser.hidden_inputs,
                    skeleton=build_skeleton(body, parser),
                    headers={k.lower(): v for k, v in resp.headers.items()},
                )
                return profile, body, tracker.hops
        except HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < retries:
                time.sleep((2 ** attempt) + random.uniform(0.1, 0.5))
                continue
            try:
                raw = e.read(65_536)
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            parser = _PageParser()
            try:
                parser.feed(body)
            except Exception:
                pass
            hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            profile = PageProfile(
                status=e.code,
                final_url=e.geturl() if hasattr(e, "geturl") else url,
                length=len(raw) if "raw" in locals() else len(body.encode("utf-8", errors="ignore")),
                title=parser.title,
                form_count=parser.form_count,
                password_inputs=parser.password_inputs,
                hidden_inputs=parser.hidden_inputs,
                skeleton=build_skeleton(body, parser),
                headers=hdrs,
            )
            return profile, body, tracker.hops
        except (URLError, TimeoutError, ValueError, OSError):
            if attempt < retries:
                time.sleep((2 ** attempt) + random.uniform(0.1, 0.5))
                continue
            return None, "", []
    return None, "", []


def build_soft404_baselines(
    insecure: bool, base_url: str, timeout: int, retries: int, limiter: RateLimiter
) -> list[PageProfile]:
    baselines = []
    for _ in range(2):
        token = hashlib.sha256(f"{time.monotonic_ns()}-{random.random()}".encode()).hexdigest()[:14]
        probe_url = urljoin(base_url, f"nh-probe-{token}/login.php")
        profile, _, _ = fetch_with_retry(insecure, probe_url, timeout, retries, limiter)
        if profile is not None:
            baselines.append(profile)
    return baselines


def is_soft_404(candidate: PageProfile, baselines: list[PageProfile]) -> bool:
    if not baselines:
        return False
    for base in baselines:
        if candidate.status != base.status:
            continue
        if candidate.password_inputs > 0 and base.password_inputs == 0:
            continue
        if candidate.title and base.title and candidate.title == base.title:
            return True
        if abs(candidate.length - base.length) <= 64 and candidate.form_count == base.form_count:
            return True
        sim = SequenceMatcher(None, candidate.skeleton[:1500], base.skeleton[:1500]).ratio()
        if sim >= 0.90:
            return True
    return False


def score_finding(
    path: str,
    profile: PageProfile,
    body: str,
    hops: list,
    base_host: str,
) -> tuple[int, dict, list[str]]:
    reasons = []
    sig_scores = {}

    title_l = profile.title.lower()
    body_l = body.lower()
    final_l = profile.final_url.lower()

    for name, tokens in SIGNATURES.items():
        pts = 0
        for tok in tokens:
            t = tok.lower()
            if t in title_l:
                pts += 40
            if t in final_l:
                pts += 25
            if t in body_l:
                pts += 10
        if pts > 0:
            sig_scores[name] = min(100, pts)

    score = min(100, sum(sig_scores.values()))

    if profile.password_inputs > 0:
        score = min(100, score + 35)
        reasons.append(f"password_inputs={profile.password_inputs}")

    if any(k in title_l for k in ("sign in", "log in", "login", "admin", "dashboard", "console", "panel")):
        score = min(100, score + 20)
        reasons.append("auth_title")

    if profile.status in (401, 403):
        score = min(100, score + 25)
        reasons.append(f"protected_status={profile.status}")

    final_host = urlparse(profile.final_url).netloc
    if final_host and final_host != base_host:
        reasons.append(f"external_redirect->{final_host}")
        if any(k in final_l for k in ("login", "auth", "sso", "oauth", "saml", "adfs", "okta", "keycloak")):
            score = min(100, score + 25)
            reasons.append("sso_redirect")
    elif hops:
        reasons.append(f"redirects={len(hops)}")

    if re.search(r"(?:admin|login|auth|dashboard|panel)", path.lower()) and profile.status == 200:
        score = min(100, score + 10)

    return score, sig_scores, reasons


def discover_paths(
    insecure: bool,
    base_url: str,
    timeout: int,
    retries: int,
    limiter: RateLimiter,
    existing: list[str],
) -> list[str]:
    candidates = list(existing)
    seen = set(candidates)
    base_parsed = urlparse(base_url)

    def add_rel(raw_href: str):
        target = urljoin(base_url, raw_href.strip())
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https") and parsed.netloc == base_parsed.netloc:
            rel = parsed.path.lstrip("/")
            if rel and rel not in seen:
                seen.add(rel)
                candidates.append(rel)

    root_profile, root_body, _ = fetch_with_retry(insecure, base_url, timeout, retries, limiter)
    if not root_profile or not root_body:
        return candidates

    parser = _PageParser()
    try:
        parser.feed(root_body)
    except Exception:
        pass

    for link in parser.links + parser.form_actions:
        add_rel(link)

    for script_src in parser.scripts[:8]:
        script_url = urljoin(base_url, script_src.strip())
        if urlparse(script_url).netloc != base_parsed.netloc:
            continue
        s_prof, s_body, _ = fetch_with_retry(insecure, script_url, timeout, retries, limiter)
        if s_prof and s_body:
            for m in re.findall(r"""["'](/[^"'?\s]{1,80})["']""", s_body):
                if any(k in m.lower() for k in ("admin", "login", "auth", "panel", "dash", "console", "portal")):
                    add_rel(m.lstrip("/"))

    return candidates


def scan_target(
    target: str,
    wordlist: list[str],
    threads: int = 8,
    timeout: int = 8,
    retries: int = 2,
    rps: float = 10.0,
    min_score: int = 20,
    insecure: bool = True,
    crawl: bool = True,
) -> dict:
    if not urlparse(target).scheme:
        target = "https://" + target
    parsed_target = urlparse(target)
    base_url = urlunparse((parsed_target.scheme, parsed_target.netloc, parsed_target.path or "/", "", "", ""))
    if not base_url.endswith("/"):
        base_url += "/"
    base_host = parsed_target.netloc

    limiter = RateLimiter(rps=rps)
    baselines = build_soft404_baselines(insecure, base_url, timeout, retries, limiter)

    candidates = (
        discover_paths(insecure, base_url, timeout, retries, limiter, wordlist)
        if crawl
        else list(wordlist)
    )

    findings = []
    print_lock = threading.Lock()
    counter = 0

    def worker(path: str):
        nonlocal counter
        url = urljoin(base_url, path.lstrip("/"))
        profile, body, hops = fetch_with_retry(insecure, url, timeout, retries, limiter)
        with print_lock:
            counter += 1
            if counter % 50 == 0 or counter == len(candidates):
                sys.stdout.write(f"\r{RED}[*] Progress: {counter}/{len(candidates)} tested{RST}")
                sys.stdout.flush()

        if profile is None or profile.status is None:
            return None
        if profile.status >= 500:
            return None
        if profile.status in (404, 410):
            return None
        if profile.status < 400 and is_soft_404(profile, baselines):
            return None

        score, sigs, reasons = score_finding(path, profile, body, hops, base_host)
        if score < min_score:
            return None

        return {
            "path": path,
            "url": profile.final_url or url,
            "status": profile.status,
            "length": profile.length,
            "title": profile.title,
            "password_inputs": profile.password_inputs,
            "score": score,
            "signatures": sigs,
            "reasons": reasons,
            "redirect_hops": len(hops),
        }

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, p) for p in candidates]
        for fut in as_completed(futures):
            item = fut.result()
            if item:
                findings.append(item)
                with print_lock:
                    sys.stdout.write("\r" + " " * 70 + "\r")
                    sig_str = ", ".join(f"{k}:{v}" for k, v in item["signatures"].items()) or "none"
                    reason_str = ", ".join(item["reasons"]) or "status_match"
                    rprint(
                        f"[+] [{item['status']}] score={item['score']} {item['url']} "
                        f"| title={item['title']!r} | sigs=[{sig_str}] | {reason_str}"
                    )

    sys.stdout.write("\r" + " " * 70 + "\r")
    findings.sort(key=lambda r: (-r["score"], r["status"], r["url"]))
    return {
        "target": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "soft_404_baselines": [
            {"status": b.status, "length": b.length, "title": b.title} for b in baselines
        ],
        "tested_paths": len(candidates),
        "findings": findings,
    }


def save_report(report: dict) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    host = re.sub(r"[^A-Za-z0-9._-]", "_", urlparse(report["target"]).netloc or "target")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"nighthawk_{host}_{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out_path


def run() -> None:
    rprint(ART)
    print()
    sys.stdout.write(f"{RED}Target-Url: {RST}")
    sys.stdout.flush()
    try:
        target = input().strip()
    except EOFError:
        return

    if not target:
        rprint("[!] No Target-Url entered.")
        return

    rprint(f"[*] Scanning {target}...\n")
    try:
        report = scan_target(target=target, wordlist=CORE)
    except KeyboardInterrupt:
        rprint("\n[!] Scan interrupted.")
        return

    report_path = save_report(report)
    rprint(f"[*] Done. {len(report['findings'])} admin candidate(s) found. Saved: {report_path}")


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        rprint("\n[!] Interrupted.")


if __name__ == "__main__":
    main()

