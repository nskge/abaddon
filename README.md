# OkrScann

```
     ____  _        ____
    / __ \| | _____/ ___|  ___ __ _ _ __  _ __
   | |  | | |/ / __\___ \ / __/ _` | '_ \| '_ \
   | |__| |   <| |  ___) | (_| (_| | | | | | | |
    \____/|_|\_\_| |____/ \___\__,_|_| |_|_| |_|
```

**Modular web vulnerability scanner** built for penetration testers and bug bounty hunters.
Fast, accurate, and report-ready.

> **Authorized targets ONLY.** The author assumes **no liability** for any misuse.

---

## Modules

| Module | What it detects |
|--------|-----------------|
| **SQLi** | Error-based, Boolean-blind, Time-blind (MySQL / MSSQL / Oracle / PostgreSQL / SQLite) |
| **XSS** | Reflected XSS with context detection (HTML / attribute / JavaScript) |
| **LFI** | Path traversal, PHP filter wrappers, encoding bypass, null-byte |
| **CMDi** | OS command injection — output-based + time-based (Unix & Windows) |
| **SSTI** | Template injection (Jinja2, Twig, Freemarker, Mako, ERB, Smarty, Velocity) |
| **CRLF** | Header injection, Set-Cookie injection, response splitting |
| **Redirect** | Open redirect via Location, meta-refresh, JavaScript |
| **Headers** | Missing security headers, server disclosure, CORS misconfiguration |
| **JWT** | alg:none bypass, weak HS256 secret brute-force, sensitive payload fields |
| **SSRF** | Cloud metadata (AWS/GCP/Azure), localhost, internal services (Redis/ES/k8s) — parallel probes |
| **XXE** | Raw XML POST, XML param injection, XML-hinted params — 6 payload variants |
| **403 Bypass** | Header spoofing (X-Original-URL, X-Forwarded-For, …), path manipulation (16 variants), verb tampering |
| **CVE Detection** | 34 CVEs across 14 services (Apache, Nginx, PHP, IIS, Tomcat, OpenSSL, jQuery, WordPress, Drupal, Struts, Spring, WebLogic, Confluence, Joomla) with CVSS, Metasploit modules, NVD links |

---

## Features

- **Recon phase** — DNS, IP, latency, server/tech fingerprint, CVE check before every scan
- **Port scanner** — concurrent TCP probe of 31 common ports with banner grab (`--port-scan`)
- **Path discovery** — 130 common paths probed concurrently (`--discover-paths`)
- **Subdomain enumeration** — 80 common prefixes resolved via DNS (`--discover-subs`)
- **WAF evasion** — 6 payload transforms across 3 escalating levels (`--waf-evasion 1|2|3`)
- **Adaptive rate limiter** — exponential back-off on 429/503, auto-recovery on 200 (`--rate-limit`)
- **Bug bounty mode** — scope validation, X-Bug-Bounty header, UA program tag (`--bb-note`, `--scope`)
- **Ctrl+C recovery** — graceful interrupt returns all findings collected so far
- **Concurrent scanning** — modules run in parallel (configurable `--threads`)
- **Report export** — TXT and JSON formats with curl + msfconsole reproduction steps
- **230+ unit tests**

---

## Install

```bash
git clone https://github.com/nskge/OkrScann.git
cd OkrScann/vuln_scanner
pip install -r requirements.txt
```

**Requires:** Python 3.10+

---

## Usage

```bash
# Full scan on all modules
python main.py -u "http://target/page?id=1"

# Auto-detect and test HTML forms
python main.py -u "http://target/search.php" --crawl

# Specific module on a specific param
python main.py -u "http://target/page?id=1" --scan-type sqli -p id

# POST form
python main.py -u "http://target/login" -m POST -d "user=admin&pass=x" --scan-type xss

# Recon extras: port scan + path discovery
python main.py -u "http://target/?id=1" --port-scan --discover-paths --discover-subs

# WAF evasion level 2
python main.py -u "http://target/?q=1" --waf-evasion 2

# Adaptive rate limiter (min 0.3s between requests)
python main.py -u "http://target/?id=1" --rate-limit --rate-delay 0.3

# Bug bounty mode with scope check
python main.py -u "http://api.target.com/?url=x" \
  --scan-type ssrf \
  --bb-note researcher@example.com \
  --bb-program h1/target-slug \
  --scope "*.target.com"

# 403 bypass on a protected endpoint
python main.py -u "http://target/admin?x=1" --scan-type bypass403

# Route through Burp Suite
python main.py -u "http://target/?q=test" --proxy http://127.0.0.1:8080

# Export JSON report
python main.py -u "http://target/?id=1" -o report.json --format json
```

### Options

```
Target:
  -u, --url URL         Target URL (required)
  -m, --method GET|POST HTTP method (default: GET)
  -d, --data            POST body  e.g. 'user=admin&pass=test'
  -p, --param NAME      Test only this parameter

Scan options:
  --scan-type TYPE      sqli|xss|lfi|redirect|cmdi|crlf|ssti|headers|
                        jwt|ssrf|xxe|bypass403|all  (default: all)
  --crawl               Auto-detect HTML forms
  --payloads FILE       Custom payload file (one per line)
  --delay SECS          Time-based detection threshold (default: 5.0)
  --threads N           Concurrent module threads (default: 4)
  --waf-evasion LEVEL   0=off 1=url+null 2=+double+case 3=+html+sql (default: 0)

Recon extras:
  --port-scan           Fast TCP port scan during recon
  --discover-paths      Probe 130 common URL paths
  --discover-subs       Enumerate 80 common subdomains

Rate limiting:
  --rate-limit          Enable adaptive rate limiter (auto back-off on 429/503)
  --rate-delay SECS     Minimum delay between requests (default: 0.0)

Bug bounty:
  --bb-note EMAIL       Add X-Bug-Bounty header identifying you as the researcher
  --bb-program SLUG     Append BugBounty/slug to User-Agent
  --scope PATTERNS      Comma-separated glob patterns  e.g. '*.example.com'
                        Aborts scan if target is out of scope

HTTP options:
  --headers HEADER ...  Extra headers  e.g. 'Authorization: Bearer tok'
  --cookies COOKIES     Cookie string  e.g. 'session=abc; role=admin'
  --proxy URL           HTTP proxy  e.g. http://127.0.0.1:8080
  --timeout N           Request timeout in seconds (default: 10)
  --user-agent UA       Override User-Agent
  --follow-redirects    Follow HTTP redirects

Output:
  -o, --output FILE     Save report to file
  --format txt|json     Report format (default: txt)
  -v, --verbose         Debug logging
  -q, --quiet           Findings only (no banner/recon)
  --no-color            Disable ANSI colors
```

---

## Tests

```bash
python -m pytest tests/ -v     # 230+ tests
```

---

## Architecture

```
scanner/
├── __init__.py          version
├── core.py              Scanner orchestrator (recon + parallel module dispatch)
├── http_client.py       HTTPClient with rate limiter integration
├── rate_limiter.py      AdaptiveRateLimiter (exponential back-off)
├── waf_evasion.py       Payload transforms (6 strategies, 3 levels)
├── port_scanner.py      Concurrent TCP port scanner
├── discovery.py         Subdomain enumeration + URL path discovery
├── cve_db.py            CVE database + version matching
├── banner.py            ASCII banner
├── parser.py            URL/form parsing helpers
├── reporter.py          TXT/JSON report writer
├── logger.py            Logging setup
└── modules/
    ├── base.py          BaseModule ABC + Finding dataclass
    ├── sqli.py
    ├── xss.py
    ├── lfi.py
    ├── cmdi.py
    ├── ssti.py
    ├── crlf.py
    ├── open_redirect.py
    ├── headers.py
    ├── jwt_analyzer.py
    ├── ssrf.py
    ├── xxe.py
    └── bypass403.py
```

### Adding a module

1. Create `scanner/modules/mymodule.py` — subclass `BaseModule`, implement `scan_parameter()`
2. Register in `scanner/core.py` `_MODULE_MAP`
3. Add to `--scan-type` choices in `main.py`

---

## Disclaimer

**OkrScann is for legal, authorized security testing only.**

1. **Authorized use only.** Only test systems you own or have explicit written permission to test.
2. **No liability.** Provided "as is" with no warranty. The author accepts no responsibility for damage or legal consequences from use or misuse.
3. **Your responsibility.** Ensure compliance with all applicable laws before testing any target.
4. **No accuracy guarantee.** Validate all findings manually before reporting.

Unauthorized access is a crime (CFAA, Computer Misuse Act, Art. 154-A Brazilian Penal Code).

---

## License

[MIT License](LICENSE)
