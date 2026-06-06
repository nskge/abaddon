# OkrScann

```
   ___  _          ____
  / _ \| | ___ __ / ___|  ___ __ _ _ __  _ __
 | | | | |/ / '__\___ \ / __/ _` | '_ \| '_ \
 | |_| |   <| |   ___) | (_| (_| | | | | | | |
  \___/|_|\_\_|  |____/ \___\__,_|_| |_|_| |_|
```

**Modular web vulnerability scanner** for penetration testing and security assessments.

> **Legal:** Only run against systems you own or have **explicit written permission** to test.

---

## Features

| Module | Techniques |
|--------|------------|
| **SQLi** | Error-based (MySQL/MSSQL/Oracle/PostgreSQL/SQLite), Boolean-based blind (AND + OR), Time-based blind (SLEEP/WAITFOR/pg_sleep) |
| **XSS** | Reflected -- probe + context detection (HTML/attribute/script), context-aware payloads, unencoded-reflection validation |
| **LFI** | Path traversal, absolute paths, null byte, URL-encoding bypass, PHP filter wrappers (base64-decode validation) |
| **CMDi** | Output-based (echo token + /etc/passwd), Time-based (sleep/ping/timeout), Unix + Windows payloads |
| **Open Redirect** | Location header analysis, meta-refresh, JavaScript redirect detection, URL scheme bypass variants |

**Additional capabilities**

- Auto-crawl: `--crawl` auto-detects HTML forms on the page (no need to know field names or method)
- WAF detection: warns when Cloudflare/Incapsula/ModSecurity is blocking requests
- Session-based HTTP client with custom headers, cookies, proxy support (Burp Suite)
- GET and POST request support with append-mode injection (critical for numeric params)
- Custom payload files per module
- JSON and TXT report export
- 56 unit tests covering all 5 modules

---

## Installation

```bash
git clone https://github.com/nskge/OkrScann.git
cd OkrScann/vuln_scanner
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, `requests`, `colorama`

---

## Quick Start

```bash
# Full scan on all GET parameters
python main.py -u "http://target.local/page?id=1"

# Auto-detect forms (discovers fields + method automatically)
python main.py -u "http://target.local/search.php" --crawl

# SQLi only on specific param
python main.py -u "http://target.local/page?id=1&cat=2" --scan-type sqli -p id

# XSS on a POST form
python main.py -u "http://target.local/search.php" -m POST -d "q=test" --scan-type xss

# Command injection
python main.py -u "http://target.local/ping?host=127.0.0.1" --scan-type cmdi

# Open redirect
python main.py -u "http://target.local/login?redirect=/dashboard" --scan-type redirect

# Route through Burp Suite
python main.py -u "http://target.local/?q=test" --proxy http://127.0.0.1:8080

# Custom cookies + headers
python main.py -u "http://target.local/page?id=1" \
  --cookies "session=abc123; role=admin" \
  --headers "X-Forwarded-For: 127.0.0.1"

# Export to JSON
python main.py -u "http://target.local/?id=1" -o report.json --format json
```

---

## CLI Reference

```
usage: okrscann [-h] -u URL [-m {GET,POST}] [-d POST_DATA] [-p PARAM]
                [--scan-type {sqli,xss,lfi,redirect,cmdi,all}] [--crawl]
                [--payloads FILE] [--delay DELAY] [--headers HEADER ...]
                [--cookies COOKIES] [--proxy URL] [--timeout N]
                [--user-agent UA] [--follow-redirects]
                [-o FILE] [--format {txt,json}] [-v] [--no-color]

Target:
  -u, --url           Target URL (include query params for GET)
  -m, --method        HTTP method: GET or POST  (default: GET)
  -d, --data          POST body  e.g. 'user=admin&pass=test'
  -p, --param         Test only this parameter

Scan options:
  --scan-type         sqli | xss | lfi | redirect | cmdi | all  (default: all)
  --crawl             Auto-detect HTML forms on the page
  --payloads FILE     Custom payload file (one per line, # = comment)
  --delay FLOAT       Time-based threshold in seconds  (default: 5.0)

HTTP options:
  --headers           Extra HTTP headers
  --cookies           Cookie string  e.g. 'session=abc; role=admin'
  --proxy URL         Proxy  e.g. http://127.0.0.1:8080
  --timeout N         Request timeout  (default: 10)
  --user-agent UA     Custom User-Agent
  --follow-redirects  Follow HTTP redirects

Output:
  -o, --output FILE   Save report to file
  --format            txt | json  (default: txt)
  -v, --verbose       Debug logging
  --no-color          Disable ANSI colours
```

---

## Test Targets

| Target | URL |
|--------|-----|
| DVWA | `docker run -p 80:80 vulnerables/web-dvwa` |
| WebGoat | `docker run -p 8080:8080 webgoat/webgoat` |
| bWAPP | `docker run -p 80:80 raesene/bwapp` |
| HackTheBox / TryHackMe | Various web challenges |

---

## Payload Reference

### SQLi
| Technique | Payload | Notes |
|-----------|---------|-------|
| Error-based | `1'` | Appended to numeric param -- syntax error |
| Boolean blind | `1 AND 1=1` vs `1 AND 1=2` | AND-mode for numeric params |
| Time (MySQL) | `1 AND SLEEP(5)--` | Delay-based detection |
| Time (MSSQL) | `1; WAITFOR DELAY '0:0:5'--` | MSSQL delay |
| Time (PgSQL) | `1; SELECT pg_sleep(5)--` | PostgreSQL delay |

### XSS
| Context | Payload |
|---------|---------|
| HTML | `<script>alert(1)</script>` |
| HTML | `<img src=x onerror=alert(1)>` |
| Attribute | `" onmouseover="alert(1)` |
| Script block | `</script><script>alert(1)</script>` |

### LFI
| Technique | Payload |
|-----------|---------|
| Traversal | `../../../../etc/passwd` |
| PHP filter | `php://filter/convert.base64-encode/resource=index.php` |
| Null byte | `../../../etc/passwd%00` |
| URL-encoded | `..%2F..%2F..%2Fetc%2Fpasswd` |

### CMDi
| Technique | Payload |
|-----------|---------|
| Semicolon | `; echo token` |
| Pipe | `\| cat /etc/passwd` |
| Backtick | `` `sleep 5` `` |
| Subshell | `$(sleep 5)` |

### Open Redirect
| Technique | Payload |
|-----------|---------|
| Direct | `https://evil.com` |
| Protocol-relative | `//evil.com` |
| At-sign bypass | `https://legitimate.com@evil.com` |

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Expected: **56 passed**

---

## Project Structure

```
vuln_scanner/
  main.py                        CLI entry point
  requirements.txt
  scanner/
    __init__.py                  Version info
    banner.py                    ASCII art + branding
    core.py                      Scan orchestration + WAF detection
    http_client.py               requests wrapper (session, proxy, retry)
    parser.py                    URL/form/POST parsing
    reporter.py                  Console + JSON/TXT output
    logger.py                    Logging setup
    modules/
      base.py                   Finding dataclass + BaseModule ABC
      sqli.py                   SQL Injection (error/boolean/time)
      xss.py                    XSS (reflected, context-aware)
      lfi.py                    LFI (traversal + PHP wrappers)
      cmdi.py                   OS Command Injection
      open_redirect.py          Open Redirect
  payloads/
    sqli.txt                    Reference SQLi payloads
    xss.txt                     Reference XSS payloads
    lfi.txt                     Reference LFI payloads
    cmdi.txt                    Reference CMDi payloads
    redirect.txt                Reference redirect payloads
  tests/
    test_sqli.py                SQLi tests (17)
    test_xss.py                 XSS tests (12)
    test_lfi.py                 LFI tests (11)
    test_cmdi.py                CMDi tests (7)
    test_redirect.py            Open Redirect tests (7)
```

---

## Extending

To add a new module:

1. Create `scanner/modules/mymodule.py` subclassing `BaseModule`
2. Implement `scan_parameter(url, method, params, param_name) -> List[Finding]`
3. Register in `scanner/core.py` `_MODULE_MAP`
4. Add `--scan-type mymodule` to argparse choices in `main.py`
