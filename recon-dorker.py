#!/usr/bin/env python3
"""
recon-dorker.py — Google Dorking for Bug Bounty
Usage: python recon-dorker.py <domain> [options]

Examples:
  python recon-dorker.py example.com
  python recon-dorker.py example.com --delay 5 --max-results 20
  python recon-dorker.py example.com --categories sensitive_files,api_endpoints
  python recon-dorker.py example.com --priority HIGH
  python recon-dorker.py example.com --output-dir ~/results
  python recon-dorker.py example.com --list-categories
"""

import sys
import json
import csv
import time
import random
import argparse
import hashlib
import re
import webbrowser
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

# ─── Dependency check ─────────────────────────────────────────────────────────

def _check_deps():
    missing = []
    try:
        import googlesearch  # noqa: F401
    except ImportError:
        missing.append("googlesearch-python")
    if missing:
        print(f"[!] Missing: {', '.join(missing)}")
        print(f"    pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()

from googlesearch import search as _gsearch  # noqa: E402

# ─── Terminal colors ──────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def col(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + C.RESET

def no_color(text: str) -> str:
    """Strip ANSI codes for clean file output."""
    return re.sub(r"\033\[[0-9;]*m", "", text)

# ─── Dork definitions ─────────────────────────────────────────────────────────
# Priority: CRITICAL > HIGH > MEDIUM > LOW
# {target} is replaced with the actual domain at runtime.
# All dorks are bug-bounty-focused: confirmed impact classes only.

DORK_CATEGORIES: Dict[str, Dict] = {

    "credentials_exposure": {
        "name": "Credentials & Keys",
        "priority": "CRITICAL",
        "dorks": [
            'site:{target} intext:"-----BEGIN RSA PRIVATE KEY-----"',
            'site:{target} intext:"-----BEGIN OPENSSH PRIVATE KEY-----"',
            'site:{target} intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----"',
            'site:{target} intext:DB_PASSWORD OR intext:DB_PASS OR intext:DATABASE_URL',
            'site:{target} intext:aws_access_key_id OR intext:aws_secret_access_key',
            'site:{target} intext:"AKIA" filetype:env OR filetype:txt OR filetype:log',
            'site:{target} intext:client_secret OR intext:client_id intext:oauth',
            'site:{target} intext:access_token OR intext:refresh_token filetype:json',
            'site:{target} intext:"api_key" OR intext:"apikey" OR intext:"secret_key"',
            'site:{target} inurl:token= OR inurl:secret= OR inurl:api_key=',
            'site:{target} intext:"password" filetype:log',
            'site:{target} intext:"Authorization: Bearer" OR intext:"Authorization: Basic"',
        ],
    },

    "sensitive_files": {
        "name": "Sensitive Files",
        "priority": "CRITICAL",
        "dorks": [
            'site:{target} ext:env',
            'site:{target} ext:env.local OR ext:env.production OR ext:env.backup',
            'site:{target} ext:log intext:error OR intext:exception OR intext:password',
            'site:{target} ext:sql',
            'site:{target} ext:bak OR ext:backup OR ext:old OR ext:orig',
            'site:{target} ext:config OR ext:conf intext:password',
            'site:{target} ext:yaml OR ext:yml intext:password OR intext:secret',
            'site:{target} ext:ini intext:password',
            'site:{target} filetype:json intext:secret OR intext:password OR intext:api_key',
            'site:{target} filetype:xml intext:password OR intext:credential',
            'site:{target} filetype:txt intext:password OR intext:username',
            'site:{target} ext:properties intext:password',
        ],
    },

    "git_exposure": {
        "name": "Git & Source Code",
        "priority": "CRITICAL",
        "dorks": [
            'site:{target} inurl:/.git',
            'site:{target} intitle:"index of /.git"',
            'site:{target} inurl:/.gitignore OR inurl:/.gitconfig OR inurl:/.git/config',
            'site:{target} inurl:/Dockerfile OR inurl:/docker-compose.yml OR inurl:/docker-compose.yaml',
            'site:{target} inurl:/.travis.yml OR inurl:/.circleci/config.yml OR inurl:/Jenkinsfile',
            'site:{target} inurl:/composer.json OR inurl:/composer.lock -blog',
            'site:{target} inurl:/package.json -blog -npm',
            'site:{target} inurl:/Gemfile OR inurl:/Gemfile.lock',
            'site:{target} inurl:/requirements.txt OR inurl:/setup.py',
            'site:{target} inurl:/.env intext:DB_',
        ],
    },

    "api_endpoints": {
        "name": "API Endpoints & Docs",
        "priority": "HIGH",
        "dorks": [
            'site:{target} inurl:/api/',
            'site:{target} inurl:/api/v1/ OR inurl:/api/v2/ OR inurl:/api/v3/',
            'site:{target} inurl:/graphql OR inurl:/graphiql',
            'site:{target} inurl:swagger OR inurl:swagger-ui OR inurl:swagger.json',
            'site:{target} inurl:api-docs OR inurl:openapi.json OR inurl:openapi.yaml',
            'site:{target} inurl:/rest/ OR inurl:/restapi/',
            'site:{target} inurl:wsdl OR inurl:?wsdl',
            'site:{target} filetype:json inurl:api',
            'site:{target} intitle:"Swagger UI"',
            'site:{target} inurl:/internal/ OR inurl:/private/ OR inurl:/v0/',
        ],
    },

    "admin_panels": {
        "name": "Admin & Login Panels",
        "priority": "HIGH",
        "dorks": [
            'site:{target} inurl:admin',
            'site:{target} inurl:admin intitle:login OR intitle:dashboard',
            'site:{target} inurl:login OR inurl:signin OR inurl:sign-in',
            'site:{target} inurl:dashboard OR inurl:control-panel OR inurl:cpanel',
            'site:{target} inurl:wp-admin OR inurl:wp-login.php',
            'site:{target} inurl:phpmyadmin',
            'site:{target} inurl:webmin OR inurl:plesk OR inurl:directadmin',
            'site:{target} inurl:administrator',
            'site:{target} inurl:manage OR inurl:management',
            'site:{target} intitle:"admin panel" OR intitle:"administration"',
        ],
    },

    "directory_listing": {
        "name": "Directory Listings",
        "priority": "HIGH",
        "dorks": [
            'site:{target} intitle:"index of"',
            'site:{target} intitle:"index of /" intext:".env" OR intext:".git"',
            'site:{target} intitle:"index of" intext:"backup" OR intext:"database"',
            'site:{target} intitle:"index of" intext:".sql" OR intext:".log" OR intext:".bak"',
            'site:{target} intitle:"Directory listing"',
            'site:{target} intitle:"index of" intext:"parent directory"',
            'site:{target} intitle:"index of" "last modified"',
        ],
    },

    "debug_errors": {
        "name": "Debug & Error Pages",
        "priority": "HIGH",
        "dorks": [
            'site:{target} intext:"Warning: mysql_connect" OR intext:"Warning: mysqli_connect"',
            'site:{target} intext:"Fatal error" intext:"on line" intext:"in /"',
            'site:{target} intext:"Traceback (most recent call last)"',
            'site:{target} intext:"Exception in thread" OR intext:"java.lang.NullPointerException"',
            'site:{target} intitle:"phpinfo()" OR inurl:phpinfo.php',
            'site:{target} intext:"SQL syntax" OR intext:"mysql_fetch_array"',
            'site:{target} intext:"ORA-00907" OR intext:"ORA-00933" OR intext:"ORA-01756"',
            'site:{target} intext:"You have an error in your SQL syntax"',
            'site:{target} intext:"Uncaught exception" intext:"Stack trace:"',
            'site:{target} intext:"SQLSTATE" OR intext:"PDOException"',
        ],
    },

    "dev_staging": {
        "name": "Dev / Staging / Test",
        "priority": "HIGH",
        "dorks": [
            'site:dev.{target} OR site:staging.{target} OR site:test.{target}',
            'site:beta.{target} OR site:qa.{target} OR site:uat.{target}',
            'site:{target} inurl:dev OR inurl:staging OR inurl:preprod',
            'site:{target} inurl:test OR inurl:uat OR inurl:sandbox',
            'site:{target} inurl:debug OR inurl:internal',
            'site:{target} intitle:"test" inurl:test -"unit test"',
        ],
    },

    "cloud_storage": {
        "name": "Cloud Storage Exposure",
        "priority": "HIGH",
        "dorks": [
            'site:s3.amazonaws.com "{target}"',
            'site:storage.googleapis.com "{target}"',
            'site:blob.core.windows.net "{target}"',
            'site:{target} inurl:s3.amazonaws.com',
            'site:{target} inurl:storage.googleapis.com OR inurl:blob.core.windows.net',
            '"index of" site:s3.amazonaws.com "{target}"',
            'site:{target} intext:"AmazonS3" OR intext:"Google Cloud Storage"',
        ],
    },

    "exposed_documents": {
        "name": "Exposed Documents",
        "priority": "MEDIUM",
        "dorks": [
            'site:{target} filetype:pdf intext:confidential OR intext:"internal use only"',
            'site:{target} filetype:xls OR filetype:xlsx intext:password OR intext:username',
            'site:{target} filetype:doc OR filetype:docx intext:confidential OR intext:secret',
            'site:{target} ext:csv intext:email OR intext:phone OR intext:ssn OR intext:credit',
            'site:{target} filetype:ppt OR filetype:pptx intext:confidential',
            'site:{target} ext:xlsx intext:"social security" OR intext:"credit card"',
        ],
    },

    "monitoring_infra": {
        "name": "Monitoring & Internal Tools",
        "priority": "MEDIUM",
        "dorks": [
            'site:{target} intitle:"Grafana" OR intitle:"Kibana"',
            'site:{target} intitle:"Prometheus" OR intitle:"Alertmanager"',
            'site:{target} intitle:"Jenkins" inurl:jenkins',
            'site:{target} intitle:"GitLab" OR intitle:"Bitbucket"',
            'site:{target} intitle:"Jira" OR intitle:"Confluence"',
            'site:{target} intitle:"Nagios" OR intitle:"Zabbix"',
            'site:{target} inurl:/actuator OR inurl:/actuator/env',
            'site:{target} inurl:/_cat/indices OR inurl:/_nodes (Elasticsearch)',
        ],
    },

    "subdomains_infra": {
        "name": "Subdomains & Infrastructure",
        "priority": "MEDIUM",
        "dorks": [
            'site:*.{target} -www',
            'site:{target} inurl:vpn OR inurl:remote OR inurl:citrix',
            'site:{target} inurl:mail OR inurl:webmail OR inurl:smtp',
            'site:{target} inurl:ftp',
            'site:{target} intext:"Powered by" filetype:html',
            'site:{target} inurl:server-status OR inurl:server-info',
        ],
    },

    "oauth_sso": {
        "name": "OAuth / SSO / Auth Flow",
        "priority": "MEDIUM",
        "dorks": [
            'site:{target} inurl:oauth OR inurl:oauth2 OR inurl:authorize',
            'site:{target} inurl:callback OR inurl:redirect_uri',
            'site:{target} inurl:saml OR inurl:sso',
            'site:{target} inurl:openid OR inurl:oidc',
            'site:{target} inurl:forgot-password OR inurl:reset-password',
            'site:{target} inurl:register OR inurl:signup',
        ],
    },
}

PRIORITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
PRIORITY_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.CYAN,
    "LOW":      C.WHITE,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
]

# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class DorkEntry:
    category:              str
    category_name:         str
    priority:              str
    query:                 str
    results_count:         int            = 0
    unique_results_count:  int            = 0
    results:               List[str]      = field(default_factory=list)
    error:                 Optional[str]  = None
    timestamp:             str            = ""

    def to_dict(self) -> Dict:
        return {
            "category":             self.category,
            "category_name":        self.category_name,
            "priority":             self.priority,
            "query":                self.query,
            "results_count":        self.results_count,
            "unique_results_count": self.unique_results_count,
            "results":              self.results,
            "error":                self.error,
            "timestamp":            self.timestamp,
        }


@dataclass
class ScanResult:
    target:              str
    timestamp:           str
    total_results:       int             = 0
    unique_urls:         int             = 0
    dorks_run:           int             = 0
    dorks_with_results:  int             = 0
    dorks:               List[DorkEntry] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target":    self.target,
            "timestamp": self.timestamp,
            "summary": {
                "total_results":      self.total_results,
                "unique_urls":        self.unique_urls,
                "dorks_run":          self.dorks_run,
                "dorks_with_results": self.dorks_with_results,
            },
            "dorks": [d.to_dict() for d in self.dorks],
        }

# ─── Core search ─────────────────────────────────────────────────────────────

def _run_dork(query: str, max_results: int, ua: str) -> List[str]:
    """
    Execute one dork query via googlesearch-python.
    Returns a list of result URLs or raises RuntimeError on failure.
    The caller handles rate-limit detection and sleeping.
    """
    import inspect
    urls: List[str] = []
    try:
        # Build kwargs based on what this version of googlesearch actually supports
        sig    = inspect.signature(_gsearch)
        params = sig.parameters

        kwargs: Dict = {"num_results": max_results, "lang": "en"}
        if "user_agent"     in params: kwargs["user_agent"]     = ua
        if "sleep_interval" in params: kwargs["sleep_interval"] = 0
        if "advanced"       in params: kwargs["advanced"]       = False
        if "timeout"        in params: kwargs["timeout"]        = 10

        raw = _gsearch(query, **kwargs)
        for item in raw:
            url = item if isinstance(item, str) else getattr(item, "url", str(item))
            if url and url.startswith("http"):
                urls.append(url)
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc
    return urls


def _dedup(seen: Set[str], new_urls: List[str]) -> List[str]:
    """Return only URLs not yet in `seen`, normalised for comparison."""
    fresh: List[str] = []
    for url in new_urls:
        key = url.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            fresh.append(url)
    return fresh

# ─── Output helpers ───────────────────────────────────────────────────────────

def _save_json(scan: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(scan.to_dict(), indent=2, ensure_ascii=False))


def _save_csv(scan: ScanResult, path: Path) -> None:
    rows: List[Dict] = []
    for dork in scan.dorks:
        for url in dork.results:
            rows.append({
                "target":        scan.target,
                "scan_timestamp": scan.timestamp,
                "category":      dork.category,
                "priority":      dork.priority,
                "query":         dork.query,
                "url":           url,
                "url_hash":      hashlib.md5(url.encode()).hexdigest(),
            })
    if not rows:
        return
    fields = ["target", "scan_timestamp", "category", "priority", "query", "url", "url_hash"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def _banner() -> None:
    print(col("""
╔══════════════════════════════════════════╗
║    recon-dorker — Google Dork Recon      ║
║       Bug Bounty Edition                 ║
║       By RyuuKhagetsu                    ║
╚══════════════════════════════════════════╝""", C.CYAN, C.BOLD))


def _list_categories() -> None:
    print(f"\n{col('Available Categories', C.BOLD, C.WHITE)}\n")
    for key, cat in DORK_CATEGORIES.items():
        pc = PRIORITY_COLORS.get(cat["priority"], C.WHITE)
        ndorks = len(cat["dorks"])
        print(f"  {col(key, C.CYAN):<45} "
              f"[{col(cat['priority'], pc)}]  "
              f"{cat['name']}  "
              f"{col('(' + str(ndorks) + ' dorks)', C.DIM)}")
    print()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Google Dorking for Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("domain", nargs="?",
                   help="Target domain, e.g. example.com")
    p.add_argument("--delay", type=float, default=3.0,
                   help="Base delay between queries in seconds (default: 3)")
    p.add_argument("--jitter", type=float, default=2.0,
                   help="Extra random jitter added to delay (default: 2)")
    p.add_argument("--max-results", type=int, default=10,
                   help="Max results per dork query (default: 10)")
    p.add_argument("--categories", type=str, default=None,
                   help="Comma-separated category keys to run (default: all)")
    p.add_argument("--priority", type=str, default=None, metavar="LEVEL",
                   help="Minimum priority: CRITICAL | HIGH | MEDIUM (default: all)")
    p.add_argument("--output-dir", type=str, default=".",
                   help="Output directory (default: current dir)")
    p.add_argument("--no-csv",  action="store_true", help="Skip CSV output")
    p.add_argument("--no-json", action="store_true", help="Skip JSON output")
    p.add_argument("--list-categories", action="store_true",
                   help="Print available categories and exit")
    # ── Manual / browser mode ──────────────────────────────────────────────
    p.add_argument("--manual", action="store_true",
                   help="Manual mode: open dorks in browser instead of auto-scraping")
    p.add_argument("--open", type=int, default=None, metavar="N",
                   help="(manual) Open N dorks from current position")
    p.add_argument("--open-all", action="store_true",
                   help="(manual) Open ALL remaining dorks in browser tabs at once")
    p.add_argument("--tab-delay", type=float, default=0.6,
                   help="(manual) Delay in seconds between opening each browser tab (default: 0.6)")
    p.add_argument("--reset-progress", action="store_true",
                   help="(manual) Reset saved progress and start from dork #1")
    return p.parse_args()

# ─── Manual / browser mode ────────────────────────────────────────────────────

import contextlib
import io

def _make_google_url(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)


def _build_dork_list(target: str, selected: List[str]) -> List[Dict]:
    """Return a flat ordered list of all dorks for the given selection."""
    dorks: List[Dict] = []
    idx = 0
    for cat_key in selected:
        cat = DORK_CATEGORIES[cat_key]
        for template in cat["dorks"]:
            idx += 1
            query = template.replace("{target}", target)
            dorks.append({
                "index":    idx,
                "category": cat_key,
                "name":     cat["name"],
                "priority": cat["priority"],
                "query":    query,
                "url":      _make_google_url(query),
            })
    return dorks


def _progress_path(output_dir: Path, safe_tgt: str) -> Path:
    return output_dir / f"recon-dorker_{safe_tgt}_progress.json"


def _load_progress(path: Path) -> Optional[Dict]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_progress(path: Path, data: Dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


@contextlib.contextmanager
def _browser_silent():
    """Suppress browser debug output: Python stdout + C-level fd 2 (Chrome stderr)."""
    import os
    # Redirect Python stdout (suppresses "Opening in existing browser session.")
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    # Redirect fd 2 at OS level (suppresses Chrome GTK/GPU debug lines)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    saved_fd2  = os.dup(2)
    os.dup2(devnull_fd, 2)
    try:
        yield
    finally:
        sys.stdout = old_stdout
        os.dup2(saved_fd2, 2)
        os.close(saved_fd2)
        os.close(devnull_fd)


def _open_tabs(all_dorks: List[Dict], start: int, count: int,
               total: int, tab_delay: float) -> None:
    """Open `count` browser tabs starting from index `start` (0-based), silently."""
    end = start + count
    print(col(f"\n  Opening dorks #{start + 1} – #{end} in your browser...\n", C.CYAN))
    for i, dork in enumerate(all_dorks[start:end], start=start + 1):
        pc = PRIORITY_COLORS.get(dork["priority"], C.WHITE)
        print(f"  [{i}/{total}] [{col(dork['priority'], pc)}]  {col(dork['query'], C.YELLOW)}")
        with _browser_silent():
            webbrowser.open_new_tab(dork["url"])
        if i < end:
            time.sleep(tab_delay)


def _print_dork_list(all_dorks: List[Dict], last_opened: int) -> None:
    """Print all dorks with opened/pending status."""
    print(f"\n  {col('Dork List', C.BOLD, C.WHITE)}\n")
    for d in all_dorks:
        pc     = PRIORITY_COLORS.get(d["priority"], C.WHITE)
        status = col("✓", C.GREEN) if d["index"] <= last_opened else col("·", C.DIM)
        print(f"  {status} [{d['index']:>3}] [{col(d['priority'], pc)}]  {col(d['query'], C.DIM)}")
    print()


def _show_options(last_opened: int, total: int) -> None:
    remaining = total - last_opened
    print(f"\n  {col('Progress', C.BOLD)}: {col(str(last_opened), C.YELLOW)}/{total} opened"
          f"  |  {col(str(remaining), C.CYAN)} remaining")
    print(f"  {col('Options:', C.BOLD)}")
    print(f"    {col('[n]', C.CYAN)}  Open N dorks from current position")
    print(f"    {col('[a]', C.CYAN)}  Open ALL remaining ({remaining})")
    print(f"    {col('[l]', C.CYAN)}  List all dorks with status")
    print(f"    {col('[q]', C.CYAN)}  Quit\n")


def _run_manual_mode(
    args:       argparse.Namespace,
    target:     str,
    safe_tgt:   str,
    selected:   List[str],
    output_dir: Path,
) -> None:
    prog_path = _progress_path(output_dir, safe_tgt)

    # ── Build dork list ──────────────────────────────────────────────────────
    all_dorks = _build_dork_list(target, selected)
    total     = len(all_dorks)

    # ── Progress state ───────────────────────────────────────────────────────
    if args.reset_progress and prog_path.exists():
        prog_path.unlink()
        print(col("  [~] Progress reset.", C.YELLOW))

    state = _load_progress(prog_path)
    if state and state.get("target") != target:
        state = None  # different target — fresh start

    last_opened: int = state["last_opened"] if state else 0

    # ── Header ───────────────────────────────────────────────────────────────
    print(f"  {col('Mode', C.BOLD)}        : {col('Manual / Browser', C.CYAN)}")
    print(f"  {col('Target', C.BOLD)}      : {col(target, C.GREEN)}")
    print(f"  {col('Total dorks', C.BOLD)} : {total}")
    print(f"  {col('Opened so far', C.BOLD)}: {col(str(last_opened), C.YELLOW)} / {total}")
    print(f"  {col('Progress file', C.BOLD)}: {prog_path}")

    if last_opened == total:
        print(col("\n  [+] All dorks already opened! Use --reset-progress to start over.", C.GREEN))
        return

    # ── Non-interactive flags ─────────────────────────────────────────────────
    if args.open_all:
        to_open = total - last_opened
        _open_tabs(all_dorks, last_opened, to_open, total, args.tab_delay)
        last_opened += to_open
        _save_progress(prog_path, {"target": target, "total_dorks": total,
                                   "last_opened": last_opened, "categories": selected})
        print(f"\n  {col('[+]', C.GREEN)} All done. Progress: {last_opened}/{total}.")
        print(f"  {col('[*]', C.DIM)} Progress saved → {prog_path}")
        return

    if args.open is not None:
        to_open = min(args.open, total - last_opened)
        _open_tabs(all_dorks, last_opened, to_open, total, args.tab_delay)
        last_opened += to_open
        _save_progress(prog_path, {"target": target, "total_dorks": total,
                                   "last_opened": last_opened, "categories": selected})
        still_left = total - last_opened
        print(f"\n  {col('[+]', C.GREEN)} Opened {to_open} tab(s).  "
              f"Progress: {col(str(last_opened), C.YELLOW)}/{total}.")
        if still_left > 0:
            print(f"  {col('[~]', C.CYAN)} {still_left} remaining. "
                  f"Re-run with --manual to continue from dork #{last_opened + 1}.")
        else:
            print(col("  [+] All dorks opened!", C.GREEN))
        print(f"  {col('[*]', C.DIM)} Progress saved → {prog_path}")
        return

    # ── Interactive loop ──────────────────────────────────────────────────────
    while True:
        if last_opened >= total:
            print(col("\n  [+] All dorks opened!", C.GREEN))
            break

        _show_options(last_opened, total)

        try:
            raw = input(col("  > ", C.CYAN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if raw == "q":
            print(col("  [~] Exiting. Progress saved.", C.YELLOW))
            break

        elif raw == "l":
            _print_dork_list(all_dorks, last_opened)
            # options will be shown again at top of loop

        elif raw == "a":
            to_open = total - last_opened
            _open_tabs(all_dorks, last_opened, to_open, total, args.tab_delay)
            last_opened += to_open
            _save_progress(prog_path, {"target": target, "total_dorks": total,
                                       "last_opened": last_opened, "categories": selected})
            print(f"\n  {col('[+]', C.GREEN)} Opened {to_open} tab(s).  "
                  f"Progress: {col(str(last_opened), C.YELLOW)}/{total}.")
            print(f"  {col('[*]', C.DIM)} Progress saved → {prog_path}")

        elif raw == "n":
            remaining = total - last_opened
            while True:
                try:
                    cnt_raw = input(col(f"  How many dorks to open? (1-{remaining}) > ",
                                        C.CYAN)).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    cnt_raw = ""
                    break
                try:
                    n = int(cnt_raw)
                    if 1 <= n <= remaining:
                        break
                    print(col(f"  [!] Enter a number between 1 and {remaining}.", C.RED))
                except ValueError:
                    if cnt_raw == "":
                        break  # cancelled
                    print(col("  [!] Invalid input — enter a number.", C.RED))
            if not cnt_raw:
                continue  # user cancelled sub-prompt, back to options
            to_open = n
            _open_tabs(all_dorks, last_opened, to_open, total, args.tab_delay)
            last_opened += to_open
            _save_progress(prog_path, {"target": target, "total_dorks": total,
                                       "last_opened": last_opened, "categories": selected})
            still_left = total - last_opened
            print(f"\n  {col('[+]', C.GREEN)} Opened {to_open} tab(s).  "
                  f"Progress: {col(str(last_opened), C.YELLOW)}/{total}.")
            if still_left > 0:
                print(f"  {col('[~]', C.CYAN)} {still_left} remaining — "
                      f"next will start from dork #{last_opened + 1}.")
            print(f"  {col('[*]', C.DIM)} Progress saved → {prog_path}")

        else:
            print(col("  [!] Unknown option. Use n / a / l / q.", C.RED))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()

    if args.list_categories:
        _list_categories()
        sys.exit(0)

    if not args.domain:
        print(col("[!] Domain required.  Usage: python recon-dorker.py <domain>", C.RED))
        sys.exit(1)

    _banner()

    # Normalise target
    target = (args.domain.lower()
              .strip()
              .removeprefix("https://")
              .removeprefix("http://")
              .rstrip("/"))

    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    ts_short   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tgt   = re.sub(r"[^\w.-]", "_", target)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path  = output_dir / f"recon-dorker_{safe_tgt}_{ts_short}.json"
    csv_path   = output_dir / f"recon-dorker_{safe_tgt}_{ts_short}.csv"

    # Build category list
    selected = list(DORK_CATEGORIES.keys())

    if args.categories:
        requested = [c.strip() for c in args.categories.split(",")]
        unknown   = [c for c in requested if c not in DORK_CATEGORIES]
        if unknown:
            print(col(f"[!] Unknown categories: {', '.join(unknown)}", C.RED))
            _list_categories()
            sys.exit(1)
        selected = requested

    if args.priority:
        level = args.priority.upper()
        if level not in PRIORITY_ORDER:
            print(col(f"[!] Invalid priority: {args.priority}  (use CRITICAL | HIGH | MEDIUM)", C.RED))
            sys.exit(1)
        threshold = PRIORITY_ORDER.index(level)
        selected  = [k for k in selected
                     if PRIORITY_ORDER.index(DORK_CATEGORIES[k]["priority"]) <= threshold]

    # Sort CRITICAL first
    selected.sort(key=lambda k: PRIORITY_ORDER.index(DORK_CATEGORIES[k]["priority"]))

    # ── Manual mode early-exit ───────────────────────────────────────────────
    if args.manual:
        _run_manual_mode(args, target, safe_tgt, selected, output_dir)
        return

    total_dorks = sum(len(DORK_CATEGORIES[k]["dorks"]) for k in selected)
    delay       = args.delay  # mutable — increased on rate-limit

    # ── Header ──────────────────────────────────────────────────────────────
    print(f"  {col('Target', C.BOLD)}      : {col(target, C.GREEN)}")
    print(f"  {col('Timestamp', C.BOLD)}   : {timestamp}")
    print(f"  {col('Categories', C.BOLD)}  : {len(selected)}")
    print(f"  {col('Total dorks', C.BOLD)} : {total_dorks}")
    print(f"  {col('Delay', C.BOLD)}       : {delay}s + {args.jitter}s jitter")
    print(f"  {col('Max results', C.BOLD)} : {args.max_results} per dork")
    print(f"  {col('Output dir', C.BOLD)}  : {output_dir}\n")

    scan          = ScanResult(target=target, timestamp=timestamp)
    seen_urls: Set[str] = set()
    counter       = 0
    rl_streak     = 0   # consecutive rate-limit hits — resets on success
    MAX_RL_STREAK = 5   # abort if blocked this many times in a row

    for cat_key in selected:
        cat = DORK_CATEGORIES[cat_key]
        pc  = PRIORITY_COLORS.get(cat["priority"], C.WHITE)

        print(f"\n{col('━'*62, C.DIM)}")
        print(f"  {col('[' + cat['priority'] + ']', pc, C.BOLD)}  "
              f"{col(cat['name'], C.CYAN, C.BOLD)}")
        print(col("━"*62, C.DIM))

        for template in cat["dorks"]:
            counter += 1
            query   = template.replace("{target}", target)
            ua      = random.choice(USER_AGENTS)  # used if library version supports it
            ts_dork = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

            print(f"\n  [{counter}/{total_dorks}] {col(query, C.YELLOW)}")

            entry = DorkEntry(
                category      = cat_key,
                category_name = cat["name"],
                priority      = cat["priority"],
                query         = query,
                timestamp     = ts_dork,
            )

            try:
                raw   = _run_dork(query, args.max_results, ua)
                fresh = _dedup(seen_urls, raw)

                entry.results_count        = len(raw)
                entry.unique_results_count = len(fresh)
                entry.results              = fresh

                scan.total_results += len(raw)
                scan.unique_urls   += len(fresh)
                rl_streak           = 0  # reset on success

                if fresh:
                    scan.dorks_with_results += 1
                    print(f"  {col('[+]', C.GREEN)} "
                          f"{col(str(len(fresh)) + ' unique', C.GREEN)} "
                          f"{col('(' + str(len(raw)) + ' total)', C.DIM)}")
                    for u in fresh[:3]:
                        print(f"      {col('→', C.CYAN)} {u}")
                    if len(fresh) > 3:
                        print(f"      {col('...and ' + str(len(fresh)-3) + ' more', C.DIM)}")
                else:
                    print(f"  {col('[-]', C.DIM)} No results")

            except RuntimeError as exc:
                msg = str(exc)
                entry.error = msg

                is_rate_limit = any(k in msg.lower() for k in
                                    ("429", "rate", "too many", "captcha",
                                     "unusual traffic", "blocked", "timed out",
                                     "connection", "remotedisconnected"))
                if is_rate_limit:
                    rl_streak += 1

                    # Progressive backoff: only raise delay on first hit, then keep it stable
                    if rl_streak == 1:
                        delay = min(delay + 3, 20)   # +3s, hard cap at 20s

                    # Backoff sleep: longer the more consecutive hits
                    backoff = min(10 * rl_streak + random.uniform(5, 15), 90)

                    print(f"  {col('[~] Google rate limit detected', C.YELLOW)} "
                          f"(streak: {rl_streak}/{MAX_RL_STREAK}) — "
                          f"sleeping {backoff:.0f}s  "
                          f"{col('[new base delay: ' + str(round(delay,1)) + 's]', C.DIM)}")

                    if rl_streak >= MAX_RL_STREAK:
                        print(f"\n  {col('[!] Hit rate limit ' + str(MAX_RL_STREAK) + ' times in a row.', C.RED)}")
                        print(f"  {col('    Tip: rerun with --delay 10 or higher, or wait a few minutes.', C.YELLOW)}")
                        print(f"  {col('    Partial results already saved to ' + str(json_path), C.DIM)}")
                        scan.dorks_run += 1
                        if not args.no_json:
                            _save_json(scan, json_path)
                        sys.exit(1)

                    time.sleep(backoff)
                else:
                    print(f"  {col('[!]', C.RED)} Error: {msg}")

            scan.dorks.append(entry)
            scan.dorks_run += 1

            # Incremental save after every dork — safe against mid-run interruption
            if not args.no_json:
                _save_json(scan, json_path)

            # Randomised inter-dork sleep
            time.sleep(delay + random.uniform(0, args.jitter))

    # ── Final output ────────────────────────────────────────────────────────
    if not args.no_json:
        _save_json(scan, json_path)
        print(f"\n  {col('[+]', C.GREEN)} JSON → {json_path}")

    if not args.no_csv:
        _save_csv(scan, csv_path)
        print(f"  {col('[+]', C.GREEN)} CSV  → {csv_path}")

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{col('═'*62, C.BOLD)}")
    print(col("  SUMMARY", C.BOLD, C.WHITE))
    print(col("═"*62, C.BOLD))
    print(f"  Target              : {col(target, C.GREEN)}")
    print(f"  Dorks run           : {scan.dorks_run}")
    print(f"  Dorks with results  : {col(str(scan.dorks_with_results), C.YELLOW)}")
    print(f"  Total results       : {scan.total_results}")
    print(f"  Unique URLs found   : {col(str(scan.unique_urls), C.GREEN)}")

    # Results breakdown by category
    cat_counts: Dict[str, int] = {}
    cat_prio:   Dict[str, str] = {}
    for d in scan.dorks:
        if d.unique_results_count > 0:
            cat_counts[d.category_name] = (cat_counts.get(d.category_name, 0)
                                           + d.unique_results_count)
            cat_prio[d.category_name] = d.priority

    if cat_counts:
        print(f"\n  {col('Results by category:', C.BOLD)}")
        for name, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
            pc = PRIORITY_COLORS.get(cat_prio.get(name, ""), C.WHITE)
            print(f"    {col(name, C.CYAN):<40} "
                  f"{col(str(cnt), C.YELLOW)} unique URLs  "
                  f"[{col(cat_prio.get(name,''), pc)}]")

    print(col("═"*62, C.BOLD))

    # Bug-bounty hint
    if scan.unique_urls > 0:
        print(f"\n  {col('[hint]', C.CYAN)} Review CRITICAL results first.")
        print(f"  {col('[hint]', C.CYAN)} Validate every URL — confirm actual access before reporting.")
        print(f"  {col('[hint]', C.CYAN)} Do not report findings solely based on Google snippet — verify live.\n")


if __name__ == "__main__":
    main()
