# recon-dorker — Google Dork Recon for Bug Bounty

```
╔══════════════════════════════════════════╗
║      recon-dorker — Google Dork Recon        ║
║       Bug Bounty Edition                 ║
║       By RyuuKhagetsu                    ║
╚══════════════════════════════════════════╝
```

A Python-based Google dorking tool designed for bug bounty hunters. Automates
110 curated dorks across 13 categories, with two operating modes: **Auto Mode**
(scrapes Google programmatically) and **Manual/Browser Mode** (opens dorks
directly in your browser to bypass rate limits).

---

## Features

- **110 curated dorks** across 13 bug-bounty-focused categories
- **Priority system** — CRITICAL / HIGH / MEDIUM, run by priority filter
- **Auto Mode** — programmatic search via `googlesearch-python` with adaptive rate limit backoff
- **Manual/Browser Mode** — opens each dork as a Google search tab in your default browser
- **Resume support** — progress is saved per-target; continue where you left off across sessions
- **Incremental saves** — JSON output written after every dork (safe against Ctrl+C)
- **Deduplication** — cross-category URL deduplication with MD5 hash tracking
- **Dual output** — JSON (structured, full metadata) + CSV (flat, spreadsheet-friendly)
- **Colored terminal output** — priority-coded results with clean progress display
- **Category/priority filtering** — run only what you need

---

## Requirements

- Python 3.9+
- `googlesearch-python >= 1.2.3`

```bash
pip install -r requirements-recon-dorker.txt
```

Or install directly:

```bash
pip install googlesearch-python
```

---

## Installation

```bash
git clone https://github.com/RyuuKhagetsu/recon-dorker.git
cd recon-dorker
pip install -r requirements-recon-dorker.txt
python recon-dorker.py --help
```

---

## Usage

### Basic syntax

```
python recon-dorker.py <domain> [options]
```

### All flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `domain` | positional | — | Target domain (e.g. `example.com`) |
| `--delay` | float | `3.0` | Base delay between queries in seconds |
| `--jitter` | float | `2.0` | Random extra jitter added to delay |
| `--max-results` | int | `10` | Max results per dork query |
| `--categories` | str | all | Comma-separated category keys to run |
| `--priority` | str | all | Minimum priority: `CRITICAL` \| `HIGH` \| `MEDIUM` |
| `--output-dir` | str | `.` | Directory for JSON/CSV output |
| `--no-csv` | flag | off | Skip CSV output |
| `--no-json` | flag | off | Skip JSON output |
| `--list-categories` | flag | off | Print all available categories and exit |
| `--manual` | flag | off | Manual/browser mode — open dorks in browser tabs |
| `--open` | int | — | *(manual)* Open next N dorks from current position |
| `--open-all` | flag | off | *(manual)* Open all remaining dorks at once |
| `--tab-delay` | float | `0.6` | *(manual)* Delay in seconds between opening tabs |
| `--reset-progress` | flag | off | *(manual)* Reset saved progress, start from dork #1 |

---

## Dork Categories

| Key | Name | Priority | Dorks |
|-----|------|----------|-------|
| `credentials_exposure` | Credentials & Keys | CRITICAL | 12 |
| `sensitive_files` | Sensitive Files | CRITICAL | 12 |
| `git_exposure` | Git & Source Code | CRITICAL | 10 |
| `api_endpoints` | API Endpoints & Docs | HIGH | 10 |
| `admin_panels` | Admin & Login Panels | HIGH | 10 |
| `directory_listing` | Directory Listings | HIGH | 7 |
| `debug_errors` | Debug & Error Pages | HIGH | 10 |
| `dev_staging` | Dev / Staging / Test | HIGH | 6 |
| `cloud_storage` | Cloud Storage Exposure | HIGH | 7 |
| `exposed_documents` | Exposed Documents | MEDIUM | 6 |
| `monitoring_infra` | Monitoring & Internal Tools | MEDIUM | 8 |
| `subdomains_infra` | Subdomains & Infrastructure | MEDIUM | 6 |
| `oauth_sso` | OAuth / SSO / Auth Flow | MEDIUM | 6 |

**Total: 110 dorks**

---

## Examples

### List all categories

```bash
python recon-dorker.py --list-categories
```

### Run all dorks on a target

```bash
python recon-dorker.py example.com
```

### Run only CRITICAL dorks

```bash
python recon-dorker.py example.com --priority CRITICAL
```

### Run specific categories

```bash
python recon-dorker.py example.com --categories credentials_exposure,git_exposure,api_endpoints
```

### Slower, safer scan (less rate limiting)

```bash
python recon-dorker.py example.com --delay 10 --jitter 5
```

### Save output to a specific directory

```bash
python recon-dorker.py example.com --output-dir ~/results/example
```

### Manual mode — open 20 dorks in browser

```bash
python recon-dorker.py example.com --manual --open 20
```

### Manual mode — open all dorks at once

```bash
python recon-dorker.py example.com --manual --open-all
```

### Manual mode — interactive, continue from last session

```bash
python recon-dorker.py example.com --manual
```

### Manual mode — reset progress and start over

```bash
python recon-dorker.py example.com --manual --reset-progress
```

---

## Example Output

### Auto Mode

```
╔══════════════════════════════════════════╗
║      recon-dorker — Google Dork Recon        ║
║       Bug Bounty Edition                 ║
║       By RyuuKhagetsu                    ║
╚══════════════════════════════════════════╝

  Target      : example.com
  Timestamp   : 2026-03-26T09:15:00
  Categories  : 13
  Total dorks : 110
  Delay       : 3.0s + 2.0s jitter
  Max results : 10 per dork
  Output dir  : .

──────────────────────────────────────────────────────────────
  [CRITICAL]  Credentials & Keys
──────────────────────────────────────────────────────────────

  [1/110] site:example.com intext:"-----BEGIN RSA PRIVATE KEY-----"
  [-] No results

  [2/110] site:example.com intext:"-----BEGIN OPENSSH PRIVATE KEY-----"
  [-] No results

  [3/110] site:example.com intext:DB_PASSWORD OR intext:DB_PASS OR intext:DATABASE_URL
  [+] 3 unique  (4 total)
      → https://example.com/config/database.php
      → https://example.com/app/config.txt
      → https://example.com/backup/env.old

  [4/110] site:example.com intext:aws_access_key_id OR intext:aws_secret_access_key
  [+] 1 unique  (1 total)
      → https://example.com/.env

──────────────────────────────────────────────────────────────
  [CRITICAL]  Sensitive Files
──────────────────────────────────────────────────────────────

  [13/110] site:example.com ext:env
  [+] 2 unique  (2 total)
      → https://example.com/.env
      → https://dev.example.com/.env.backup

  [14/110] site:example.com ext:sql
  [+] 1 unique  (1 total)
      → https://example.com/backup/db_dump_2024.sql

  [~] Google rate limit detected (streak: 1/5) — sleeping 15s  [new base delay: 6.0s]

  [15/110] site:example.com ext:log intext:error OR intext:exception OR intext:password
  [-] No results

──────────────────────────────────────────────────────────────
  [HIGH]  API Endpoints & Docs
──────────────────────────────────────────────────────────────

  [34/110] site:example.com inurl:swagger OR inurl:swagger-ui OR inurl:swagger.json
  [+] 1 unique  (2 total)
      → https://api.example.com/swagger-ui/index.html

  [35/110] site:example.com intitle:"Swagger UI"
  [-] No results

══════════════════════════════════════════════════════════════
  SUMMARY
══════════════════════════════════════════════════════════════
  Target              : example.com
  Dorks run           : 110
  Dorks with results  : 18
  Total results       : 47
  Unique URLs found   : 31

  Results by category:
    Sensitive Files                          9 unique URLs  [CRITICAL]
    Credentials & Keys                       7 unique URLs  [CRITICAL]
    Git & Source Code                        5 unique URLs  [CRITICAL]
    API Endpoints & Docs                     4 unique URLs  [HIGH]
    Admin & Login Panels                     3 unique URLs  [HIGH]
    Directory Listings                       2 unique URLs  [HIGH]
    Debug & Error Pages                      1 unique URLs  [HIGH]

══════════════════════════════════════════════════════════════

  [hint] Review CRITICAL results first.
  [hint] Validate every URL — confirm actual access before reporting.
  [hint] Do not report findings solely based on Google snippet — verify live.
```

---

### Manual Mode — Interactive Session

```
╔══════════════════════════════════════════╗
║      recon-dorker — Google Dork Recon        ║
║       Bug Bounty Edition                 ║
║       By RyuuKhagetsu                    ║
╚══════════════════════════════════════════╝

  Mode        : Manual / Browser
  Target      : example.com
  Total dorks : 110
  Opened so far: 0 / 110
  Progress file: ./recon-dorker_example.com_progress.json

  Progress: 0/110 opened  |  110 remaining
  Options:
    [n]  Open N dorks from current position
    [a]  Open ALL remaining (110)
    [l]  List all dorks with status
    [q]  Quit

  > n
  How many dorks to open? (1-110) > 20

  Opening dorks #1 – #20 in your browser...

  [1/110] [CRITICAL]  site:example.com intext:"-----BEGIN RSA PRIVATE KEY-----"
  [2/110] [CRITICAL]  site:example.com intext:"-----BEGIN OPENSSH PRIVATE KEY-----"
  [3/110] [CRITICAL]  site:example.com intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----"
  [4/110] [CRITICAL]  site:example.com intext:DB_PASSWORD OR intext:DB_PASS OR intext:DATABASE_URL
  [5/110] [CRITICAL]  site:example.com intext:aws_access_key_id OR intext:aws_secret_access_key
  [6/110] [CRITICAL]  site:example.com intext:"AKIA" filetype:env OR filetype:txt OR filetype:log
  [7/110] [CRITICAL]  site:example.com intext:client_secret OR intext:client_id intext:oauth
  [8/110] [CRITICAL]  site:example.com intext:access_token OR intext:refresh_token filetype:json
  [9/110] [CRITICAL]  site:example.com intext:"api_key" OR intext:"apikey" OR intext:"secret_key"
  [10/110] [CRITICAL]  site:example.com inurl:token= OR inurl:secret= OR inurl:api_key=
  [11/110] [CRITICAL]  site:example.com intext:"password" filetype:log
  [12/110] [CRITICAL]  site:example.com intext:"Authorization: Bearer" OR intext:"Authorization: Basic"
  [13/110] [CRITICAL]  site:example.com ext:env
  [14/110] [CRITICAL]  site:example.com ext:env.local OR ext:env.production OR ext:env.backup
  [15/110] [CRITICAL]  site:example.com ext:log intext:error OR intext:exception OR intext:password
  [16/110] [CRITICAL]  site:example.com ext:sql
  [17/110] [CRITICAL]  site:example.com ext:bak OR ext:backup OR ext:old OR ext:orig
  [18/110] [CRITICAL]  site:example.com ext:config OR ext:conf intext:password
  [19/110] [CRITICAL]  site:example.com ext:yaml OR ext:yml intext:password OR intext:secret
  [20/110] [CRITICAL]  site:example.com ext:ini intext:password

  [+] Opened 20 tab(s).  Progress: 20/110.
  [~] 90 remaining — next will start from dork #21.
  [*] Progress saved → ./recon-dorker_example.com_progress.json

  Progress: 20/110 opened  |  90 remaining
  Options:
    [n]  Open N dorks from current position
    [a]  Open ALL remaining (90)
    [l]  List all dorks with status
    [q]  Quit

  > l

  Dork List

  ✓ [  1] [CRITICAL]  site:example.com intext:"-----BEGIN RSA PRIVATE KEY-----"
  ✓ [  2] [CRITICAL]  site:example.com intext:"-----BEGIN OPENSSH PRIVATE KEY-----"
  ✓ [  3] [CRITICAL]  site:example.com intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----"
  ✓ [  4] [CRITICAL]  site:example.com intext:DB_PASSWORD OR intext:DB_PASS OR intext:DATABASE_URL
  ...
  ✓ [ 20] [CRITICAL]  site:example.com ext:ini intext:password
  · [ 21] [CRITICAL]  site:example.com filetype:json intext:secret OR intext:password OR intext:api_key
  · [ 22] [CRITICAL]  site:example.com filetype:xml intext:password OR intext:credential
  · [ 23] [CRITICAL]  site:example.com filetype:txt intext:password OR intext:username
  · [ 24] [CRITICAL]  site:example.com ext:properties intext:password
  · [ 25] [CRITICAL]  site:example.com inurl:/.git
  ...
  · [110] [MEDIUM]   site:example.com inurl:register OR inurl:signup

  Progress: 20/110 opened  |  90 remaining
  Options:
    [n]  Open N dorks from current position
    [a]  Open ALL remaining (90)
    [l]  List all dorks with status
    [q]  Quit

  > n
  How many dorks to open? (1-90) > 10

  Opening dorks #21 – #30 in your browser...

  [21/110] [CRITICAL]  site:example.com filetype:json intext:secret OR intext:password OR intext:api_key
  [22/110] [CRITICAL]  site:example.com filetype:xml intext:password OR intext:credential
  ...
  [30/110] [CRITICAL]  site:example.com inurl:/.env intext:DB_

  [+] Opened 10 tab(s).  Progress: 30/110.
  [~] 80 remaining — next will start from dork #31.
  [*] Progress saved → ./recon-dorker_example.com_progress.json

  > q
  [~] Exiting. Progress saved.
```

### Resume next session

```bash
python recon-dorker.py example.com --manual
```

```
  Mode        : Manual / Browser
  Target      : example.com
  Total dorks : 110
  Opened so far: 30 / 110      ← picks up exactly where you left off
  Progress file: ./recon-dorker_example.com_progress.json
```

---

### `--list-categories` output

```
Available Categories

  credentials_exposure                      [CRITICAL]  Credentials & Keys  (12 dorks)
  sensitive_files                           [CRITICAL]  Sensitive Files  (12 dorks)
  git_exposure                              [CRITICAL]  Git & Source Code  (10 dorks)
  api_endpoints                             [HIGH]      API Endpoints & Docs  (10 dorks)
  admin_panels                              [HIGH]      Admin & Login Panels  (10 dorks)
  directory_listing                         [HIGH]      Directory Listings  (7 dorks)
  debug_errors                              [HIGH]      Debug & Error Pages  (10 dorks)
  dev_staging                               [HIGH]      Dev / Staging / Test  (6 dorks)
  cloud_storage                             [HIGH]      Cloud Storage Exposure  (7 dorks)
  exposed_documents                         [MEDIUM]    Exposed Documents  (6 dorks)
  monitoring_infra                          [MEDIUM]    Monitoring & Internal Tools  (8 dorks)
  subdomains_infra                          [MEDIUM]    Subdomains & Infrastructure  (6 dorks)
  oauth_sso                                 [MEDIUM]    OAuth / SSO / Auth Flow  (6 dorks)
```

---

## Output Files

### JSON output — `recon-dorker_<target>_<timestamp>.json`

```json
{
  "target": "example.com",
  "timestamp": "2026-03-26T09:15:00",
  "summary": {
    "total_results": 47,
    "unique_urls": 31,
    "dorks_run": 110,
    "dorks_with_results": 18
  },
  "dorks": [
    {
      "category": "credentials_exposure",
      "category_name": "Credentials & Keys",
      "priority": "CRITICAL",
      "query": "site:example.com intext:DB_PASSWORD OR intext:DB_PASS",
      "results_count": 4,
      "unique_results_count": 3,
      "results": [
        "https://example.com/config/database.php",
        "https://example.com/app/config.txt",
        "https://example.com/backup/env.old"
      ],
      "error": null,
      "timestamp": "2026-03-26T09:17:32"
    }
  ]
}
```

### CSV output — `recon-dorker_<target>_<timestamp>.csv`

| target | scan_timestamp | category | priority | query | url | url_hash |
|--------|---------------|----------|----------|-------|-----|----------|
| example.com | 2026-03-26T09:15:00 | credentials_exposure | CRITICAL | site:example.com intext:DB_PASSWORD | https://example.com/config/database.php | `a3f9...` |
| example.com | 2026-03-26T09:15:00 | sensitive_files | CRITICAL | site:example.com ext:sql | https://example.com/backup/db.sql | `c821...` |

### Progress file (manual mode) — `recon-dorker_<target>_progress.json`

```json
{
  "target": "example.com",
  "total_dorks": 110,
  "last_opened": 30,
  "categories": [
    "credentials_exposure",
    "sensitive_files",
    "git_exposure",
    "..."
  ]
}
```

---

## Rate Limiting (Auto Mode)

Google aggressively rate-limits programmatic scraping. The tool handles this automatically:

| Situation | Behavior |
|-----------|----------|
| First rate-limit hit | Base delay increases by +3s (capped at 20s) |
| Consecutive hits | Progressive backoff sleep: `10 × streak + jitter` seconds (max 90s) |
| 5 consecutive blocks | Abort with tip, save partial results |

**Tips to avoid rate limits:**

```bash
# Conservative scan — good for first run
python recon-dorker.py example.com --delay 10 --jitter 5

# Only run CRITICAL dorks — fewer requests
python recon-dorker.py example.com --priority CRITICAL --delay 8

# Use manual mode entirely — zero rate limit risk
python recon-dorker.py example.com --manual --open-all
```

> **Recommended:** Use `--manual` mode for targets behind CAPTCHA protection or when running a large scope. The browser opens real Google searches under your logged-in session — no scraping involved.

---

## Workflow Recommendation

### Phase 1 — Quick CRITICAL sweep (auto)

```bash
python recon-dorker.py target.com --priority CRITICAL --delay 8 --output-dir ./results
```

### Phase 2 — Manual coverage of remaining HIGH dorks

```bash
python recon-dorker.py target.com --priority HIGH --manual --open 20
# review, then continue:
python recon-dorker.py target.com --priority HIGH --manual
```

### Phase 3 — MEDIUM recon

```bash
python recon-dorker.py target.com --categories monitoring_infra,subdomains_infra,oauth_sso --manual --open-all
```

---

## Dork Operator Reference

| Operator | Meaning | Example |
|----------|---------|---------|
| `site:` | Restrict to domain | `site:example.com` |
| `inurl:` | Keyword in URL | `inurl:/admin` |
| `intext:` | Keyword in page body | `intext:"DB_PASSWORD"` |
| `intitle:` | Keyword in page title | `intitle:"index of"` |
| `filetype:` | Match file extension | `filetype:env` |
| `ext:` | Alias for filetype | `ext:sql` |
| `site:*.domain` | All subdomains | `site:*.example.com` |
| `-keyword` | Exclude results | `-blog -npm` |

---

## Legal Disclaimer

This tool is intended **only for authorized security testing, bug bounty programs,
and educational purposes**. Using Google dorks against targets you do not have
explicit permission to test may violate:

- The target's Terms of Service
- Google's Terms of Service
- Computer fraud and abuse laws in your jurisdiction (CFAA, UU ITE, etc.)

**You are solely responsible for how you use this tool.**
Always ensure you are operating within the scope defined by the bug bounty program.

---

## Author

**RyuuKhagetsu** — Bug Bounty Hunter

---

## License

MIT License — see [LICENSE](LICENSE) for details.
