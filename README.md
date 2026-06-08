# OkrScann

```
     ____  _        ____
    / __ \| | _____/ ___|  ___ __ _ _ __  _ __
   | |  | | |/ / __\___ \ / __/ _` | '_ \| '_ \
   | |__| |   <| |  ___) | (_| (_| | | | | | | |
    \____/|_|\_\_| |____/ \___\__,_|_| |_|_| |_|
```

**Modular web vulnerability scanner** for penetration testing and security assessments.
Built for speed, accuracy, and real-world pentest reports.

> **Authorized targets ONLY.** The author assumes **no liability** for any misuse.
> See [Disclaimer](#disclaimer) below.

---

## Modules

| Module | What it detects |
|--------|----------------|
| **SQLi** | Error-based, Boolean-blind, Time-blind (MySQL, MSSQL, Oracle, PostgreSQL, SQLite) |
| **XSS** | Reflected XSS with context detection (HTML / attribute / script) |
| **LFI** | Path traversal, PHP filter wrappers, encoding bypass, null byte |
| **CMDi** | OS command injection -- output-based + time-based (Unix & Windows) |
| **SSTI** | Template injection (Jinja2, Twig, Freemarker, Mako, ERB, Smarty, Velocity) |
| **CRLF** | Header injection, Set-Cookie injection, response splitting |
| **Redirect** | Open redirect via Location header, meta-refresh, JavaScript |
| **Headers** | Missing security headers, server version disclosure, CORS misconfig |
| **CVE Detection** | Outdated service version matching against 35 known CVEs (Apache, Nginx, PHP, IIS, Tomcat, OpenSSL, jQuery, WordPress, Drupal, Struts, Spring, WebLogic, Confluence, Joomla) with CVSS scores, Metasploit modules, and NVD advisory links |

**Key features:** target recon (IP/server/tech fingerprinting), CVE detection with Metasploit integration (35 CVEs, 14 services), auto-crawl forms, WAF detection, concurrent scanning (configurable threads), finding deduplication, reproduction steps (curl + msfconsole commands), JSON/TXT export, 150+ unit tests.

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
# Full scan
python main.py -u "http://target/page?id=1"

# Auto-detect forms
python main.py -u "http://target/search.php" --crawl

# Specific module
python main.py -u "http://target/page?id=1" --scan-type sqli -p id

# POST form
python main.py -u "http://target/search" -m POST -d "q=test" --scan-type xss

# With proxy (Burp Suite)
python main.py -u "http://target/?q=test" --proxy http://127.0.0.1:8080

# Export JSON report
python main.py -u "http://target/?id=1" -o report.json --format json
```

### Options

```
-u, --url           Target URL (required)
-m, --method        GET or POST (default: GET)
-d, --data          POST body
-p, --param         Test only this parameter
--scan-type         sqli|xss|lfi|cmdi|ssti|crlf|redirect|headers|all
--crawl             Auto-detect HTML forms
--payloads FILE     Custom payload file
--cookies           Cookie string
--proxy URL         HTTP proxy
--threads N         Concurrent module threads (default: 4)
--timeout N         Request timeout (default: 10s)
-o, --output FILE   Save report to file
--format            txt or json
-v, --verbose       Debug logging
-q, --quiet         Findings only (no banner/recon/info)
```

---

## Tests

```bash
python -m pytest tests/ -v     # 150+ tests
```

---

## Extending

1. Create `scanner/modules/mymodule.py` subclassing `BaseModule`
2. Implement `scan_parameter(url, method, params, param_name) -> List[Finding]`
3. Register in `scanner/core.py` `_MODULE_MAP`
4. Add to argparse choices in `main.py`

---

## Disclaimer

**OkrScann is for legal, authorized security testing only.**

1. **Authorized use only.** Only test systems you own or have explicit written permission to test. Unauthorized access is a crime (CFAA, Computer Misuse Act, Art. 154-A Brazilian Penal Code).
2. **No liability.** The author provides this software "as is" with no warranty. The author accepts no responsibility for any damage or legal consequences from use or misuse.
3. **Your responsibility.** Ensure compliance with all applicable laws before testing any target.
4. **Educational purpose.** Created as a portfolio piece to demonstrate offensive-security concepts.
5. **No accuracy guarantee.** Always validate findings manually before reporting.

---

## License

[MIT License](LICENSE)
