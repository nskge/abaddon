"""Known CVE database for outdated service version detection.

Extracts service versions from HTTP response headers and body, then matches
them against a curated database of high-impact vulnerabilities.  Each entry
includes CVSS score, impact description, and Metasploit module path (when
available) so pentesters can quickly validate and exploit findings.
"""

import re
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

def _ver(s: str) -> Tuple[int, ...]:
    """Parse '2.4.49' or '1.0.1f' into a comparable int tuple.

    Letters are silently dropped -- only the numeric components are kept.
    This is sufficient for Apache, Nginx, PHP, IIS, Tomcat, etc.  For
    OpenSSL-style letter suffixes (e.g. 1.0.1f) the check lambdas do
    their own letter-level matching.
    """
    parts: List[int] = []
    for segment in re.split(r"[.\-_+]", s.strip()):
        m = re.match(r"(\d+)", segment)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) if parts else (0,)


def _lt(v: str, ceiling: str) -> bool:
    """True when version *v* is strictly less than *ceiling*."""
    return _ver(v) < _ver(ceiling)


def _eq(v: str, target: str) -> bool:
    """True when version *v* equals *target* (numeric parts only)."""
    return _ver(v) == _ver(target)


def _between(v: str, low: str, high: str) -> bool:
    """True when *low* <= *v* <= *high* (inclusive on both ends)."""
    parsed = _ver(v)
    return _ver(low) <= parsed <= _ver(high)


# ---------------------------------------------------------------------------
# Version extraction from HTTP response
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(
    r"\b(Apache(?:\s+Tomcat)?|nginx|Microsoft-IIS|PHP|OpenSSL|LiteSpeed|"
    r"Werkzeug|Python|gunicorn|Tomcat|Express|Jetty|Caddy)"
    r"[/ ](\d+(?:\.\d+)*[a-z]?)",
    re.IGNORECASE,
)

_BODY_VERSION_PATTERNS = [
    (re.compile(r'content=["\']WordPress\s+(\d+(?:\.\d+)*)', re.I), "wordpress"),
    (re.compile(r'jquery[/-](\d+(?:\.\d+)*)', re.I), "jquery"),
]

_SERVICE_ALIASES: Dict[str, str] = {
    "apache tomcat": "tomcat",
    "apache": "apache",
    "nginx": "nginx",
    "microsoft-iis": "iis",
    "php": "php",
    "openssl": "openssl",
    "litespeed": "litespeed",
    "werkzeug": "werkzeug",
    "python": "python",
    "gunicorn": "gunicorn",
    "tomcat": "tomcat",
    "express": "express",
    "jetty": "jetty",
    "caddy": "caddy",
}


def extract_versions(resp) -> List[Tuple[str, str]]:
    """Extract ``(service, version)`` pairs from response headers and body.

    Checks the ``Server``, ``X-Powered-By``, and ``X-AspNet-Version``
    headers for ``Name/Version`` patterns, and scans the first 50 KB of
    the response body for WordPress and jQuery version strings.
    """
    found: List[Tuple[str, str]] = []
    seen: set = set()

    for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
        value = resp.headers.get(header, "")
        if not value:
            continue
        for match in _VERSION_RE.finditer(value):
            raw_name = match.group(1).lower()
            svc = _SERVICE_ALIASES.get(raw_name, raw_name)
            version = match.group(2)
            key = (svc, version)
            if key not in seen:
                seen.add(key)
                found.append(key)

    body = resp.text[:51200]
    for pattern, svc in _BODY_VERSION_PATTERNS:
        m = pattern.search(body)
        if m:
            version = m.group(1)
            key = (svc, version)
            if key not in seen:
                seen.add(key)
                found.append(key)

    return found


# ---------------------------------------------------------------------------
# CVE database  (18 high-impact entries, sorted by service)
# ---------------------------------------------------------------------------

_CVE_DB: List[Dict] = [
    # ----------------------------------------------------------------
    # Apache httpd
    # ----------------------------------------------------------------
    {
        "service": "apache",
        "check": lambda v: _eq(v, "2.4.49"),
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Path traversal + RCE via URL-encoded dot-dot sequences. "
            "If mod_cgi/mod_cgid is enabled, attacker achieves full "
            "remote code execution with httpd privileges. Otherwise "
            "reads arbitrary files outside the document root."
        ),
        "msf": "exploit/multi/http/apache_normalize_path_rce",
    },
    {
        "service": "apache",
        "check": lambda v: _between(v, "2.4.49", "2.4.50"),
        "cve": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Incomplete fix bypass for CVE-2021-41773. Double-encoded "
            "path traversal allows unauthenticated remote code execution. "
            "Trivially exploitable with a single curl command."
        ),
        "msf": "exploit/multi/http/apache_normalize_path_rce",
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.28"),
        "cve": "CVE-2017-9798",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Optionsbleed -- OPTIONS method leaks fragments of server "
            "memory via corrupted Allow header. May expose credentials, "
            "session tokens, and data from other requests."
        ),
        "msf": "auxiliary/scanner/http/apache_optionsbleed",
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.52"),
        "cve": "CVE-2021-44790",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Heap buffer overflow in mod_lua multipart parser. Crafted "
            "Content-Type boundary triggers overflow. Potential RCE if "
            "mod_lua is loaded (uncommon in default installs)."
        ),
        "msf": None,
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.56"),
        "cve": "CVE-2023-25690",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "HTTP request smuggling when mod_proxy + RewriteRule is "
            "enabled. Bypasses access controls, poisons proxy cache, "
            "and can reach internal backend services."
        ),
        "msf": None,
    },
    # ----------------------------------------------------------------
    # Nginx
    # ----------------------------------------------------------------
    {
        "service": "nginx",
        "check": lambda v: _between(v, "0.6.18", "1.20.0"),
        "cve": "CVE-2021-23017",
        "cvss": 7.7,
        "severity": "HIGH",
        "impact": (
            "Off-by-one write in DNS resolver. Attacker-controlled DNS "
            "response overwrites one byte on the heap. Denial of service "
            "or potential remote code execution."
        ),
        "msf": None,
    },
    {
        "service": "nginx",
        "check": lambda v: _lt(v, "1.13.3"),
        "cve": "CVE-2017-7529",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Integer overflow in range filter module. Crafted Range "
            "request leaks up to 64 KB of server memory per request, "
            "similar impact to Heartbleed for Nginx."
        ),
        "msf": None,
    },
    # ----------------------------------------------------------------
    # PHP
    # ----------------------------------------------------------------
    {
        "service": "php",
        "check": lambda v: (
            _between(v, "8.1.0", "8.1.28") or
            _between(v, "8.2.0", "8.2.19") or
            _between(v, "8.3.0", "8.3.7") or
            _between(v, "5.0.0", "7.4.99")
        ),
        "cve": "CVE-2024-4577",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "PHP-CGI argument injection on Windows via Best-Fit character "
            "mapping. Bypass of CVE-2012-1823 fix allows unauthenticated "
            "remote code execution. Actively exploited by ransomware groups."
        ),
        "msf": "exploit/multi/http/php_cgi_arg_injection",
    },
    {
        "service": "php",
        "check": lambda v: (
            _between(v, "7.1.0", "7.1.32") or
            _between(v, "7.2.0", "7.2.23") or
            _between(v, "7.3.0", "7.3.10")
        ),
        "cve": "CVE-2019-11043",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "PHP-FPM underflow in path handling. With nginx + php-fpm "
            "and specific fastcgi_split_path_info config, attacker "
            "overwrites FCGI env variables to achieve remote code execution."
        ),
        "msf": "exploit/multi/http/php_fpm_rce",
    },
    {
        "service": "php",
        "check": lambda v: _lt(v, "5.4.2"),
        "cve": "CVE-2012-1823",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "PHP-CGI query string passed as command-line arguments. "
            "Allows source code disclosure (-s flag) and remote code "
            "execution via -d auto_prepend_file injection."
        ),
        "msf": "exploit/multi/http/php_cgi_arg_injection",
    },
    # ----------------------------------------------------------------
    # Microsoft IIS
    # ----------------------------------------------------------------
    {
        "service": "iis",
        "check": lambda v: _eq(v, "6.0"),
        "cve": "CVE-2017-7269",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "WebDAV ScStoragePathFromUrl buffer overflow. Unauthenticated "
            "RCE via crafted PROPFIND request with long If header. "
            "Wormable vulnerability -- widely exploited in the wild."
        ),
        "msf": "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
    },
    {
        "service": "iis",
        "check": lambda v: _between(v, "7.5", "8.5"),
        "cve": "CVE-2015-1635",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "impact": (
            "HTTP.sys integer overflow via crafted Range header (MS15-034). "
            "Unauthenticated remote code execution or instant BSOD. Affects "
            "all unpatched Windows with IIS 7.5 through 8.5."
        ),
        "msf": "auxiliary/dos/http/ms15_034_ulonglongadd",
    },
    # ----------------------------------------------------------------
    # OpenSSL  (detected from Server header, e.g. Apache/... OpenSSL/1.0.1f)
    # ----------------------------------------------------------------
    {
        "service": "openssl",
        "check": lambda v: (
            _ver(v)[:3] == (1, 0, 1) and
            not re.search(r"1\.0\.1[g-z]", v)
        ),
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Heartbleed -- TLS heartbeat extension leaks 64 KB of server "
            "memory per request. Exposes private keys, session tokens, "
            "passwords, and encrypted traffic. Widely exploited."
        ),
        "msf": "auxiliary/scanner/ssl/openssl_heartbleed",
    },
    # ----------------------------------------------------------------
    # Apache Tomcat
    # ----------------------------------------------------------------
    {
        "service": "tomcat",
        "check": lambda v: (
            _between(v, "7.0.0", "7.0.81") or
            _between(v, "8.0.0", "8.0.46") or
            _between(v, "8.5.0", "8.5.22") or
            _eq(v, "9.0.0")
        ),
        "cve": "CVE-2017-12617",
        "cvss": 8.1,
        "severity": "HIGH",
        "impact": (
            "JSP upload via PUT method when readonly=false on the default "
            "servlet. Attacker uploads malicious .jsp and achieves remote "
            "code execution as the Tomcat service account."
        ),
        "msf": "exploit/multi/http/tomcat_jsp_upload_bypass",
    },
    {
        "service": "tomcat",
        "check": lambda v: (
            _between(v, "6.0.0", "7.0.99") or
            _between(v, "8.0.0", "8.5.50") or
            _between(v, "9.0.0", "9.0.30")
        ),
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Ghostcat -- AJP connector file read and inclusion. "
            "Unauthenticated attacker reads any file in the webapp "
            "directory. Combined with file upload, achieves RCE."
        ),
        "msf": "auxiliary/admin/http/tomcat_ghostcat",
    },
    # ----------------------------------------------------------------
    # jQuery  (detected from response body)
    # ----------------------------------------------------------------
    {
        "service": "jquery",
        "check": lambda v: _between(v, "1.2.0", "3.4.99"),
        "cve": "CVE-2020-11022",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "impact": (
            "XSS in jQuery.htmlPrefilter. Untrusted HTML passed to DOM "
            "manipulation methods (html(), append()) allows script "
            "injection even with server-side sanitization."
        ),
        "msf": None,
    },
    # ----------------------------------------------------------------
    # WordPress  (detected from response body meta generator tag)
    # ----------------------------------------------------------------
    {
        "service": "wordpress",
        "check": lambda v: _lt(v, "5.8.3"),
        "cve": "CVE-2022-21661",
        "cvss": 8.0,
        "severity": "HIGH",
        "impact": (
            "SQL injection via WP_Query. Attacker with subscriber role "
            "exploits tax_query to extract database contents including "
            "user credentials and private post data."
        ),
        "msf": None,
    },
]


def match_cves(versions: List[Tuple[str, str]]) -> List[Dict]:
    """Match detected versions against the CVE database.

    Returns a list of dicts with keys: service, version, cve, cvss,
    severity, impact, msf.  Sorted by CVSS score descending (most
    critical first).
    """
    matches: List[Dict] = []
    seen_cves: set = set()

    for service, version in versions:
        if not version:
            continue
        for entry in _CVE_DB:
            if entry["service"] != service:
                continue
            if entry["cve"] in seen_cves:
                continue
            try:
                if entry["check"](version):
                    seen_cves.add(entry["cve"])
                    matches.append({
                        "service": service,
                        "version": version,
                        "cve": entry["cve"],
                        "cvss": entry["cvss"],
                        "severity": entry["severity"],
                        "impact": entry["impact"],
                        "msf": entry["msf"],
                    })
            except Exception:
                continue

    matches.sort(key=lambda m: m["cvss"], reverse=True)
    return matches
