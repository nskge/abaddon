"""Known CVE database for outdated service version detection.

Extracts service versions from HTTP response headers and body, then matches
them against a curated database of high-impact vulnerabilities.  Each entry
includes CVSS score, impact description, Metasploit module path, and a
recommended payload so pentesters can validate and exploit findings quickly.
"""

import re
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

def _ver(s: str) -> Tuple[int, ...]:
    """Parse '2.4.49' or '1.0.1f' into a comparable int tuple.

    Splits on '.', '-', '_', '+'.  Letters break the chain and are dropped
    (so '1.0.1f' → (1, 0, 1)).  Sufficient for Apache, Nginx, PHP, IIS,
    Tomcat, etc.  OpenSSL letter-suffix checks use their own regex guards.
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
    r"Werkzeug|Python|gunicorn|Tomcat|Express|Jetty|Caddy|"
    r"WebLogic|Struts|Struts2|Confluence|JBoss|WildFly|Joomla)"
    r"[/\s](\d+(?:\.\d+)*[a-z]?)",
    re.IGNORECASE,
)

# Body patterns: (compiled_regex, service_name)
_BODY_VERSION_PATTERNS = [
    # WordPress meta generator
    (re.compile(r'content=["\']WordPress\s+(\d+(?:\.\d+)*)', re.I), "wordpress"),
    # jQuery filename in script src
    (re.compile(r'jquery[/-](\d+(?:\.\d+)*)', re.I), "jquery"),
    # Joomla meta generator
    (re.compile(r'content=["\']Joomla!\s+(\d+(?:\.\d+)*)', re.I), "joomla"),
    # Drupal meta generator
    (re.compile(r'content=["\']Drupal\s+(\d+(?:\.\d+)*)', re.I), "drupal"),
    # Confluence AJS version tag in HTML
    (re.compile(r'ajs-version-number["\s]+content=["\'](\d+(?:\.\d+)*)', re.I), "confluence"),
    # Spring Boot error pages
    (re.compile(r'Spring\s+Boot\s+(?:v|Version\s+)?(\d+(?:\.\d+)*)', re.I), "spring"),
    # Struts error pages / viewId
    (re.compile(r'Struts\s+(?:Problem|Version\s+)?(?:v|Report\s+)?(\d+(?:\.\d+)*)', re.I), "struts"),
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
    "weblogic": "weblogic",
    "struts": "struts",
    "struts2": "struts",
    "confluence": "confluence",
    "jboss": "jboss",
    "wildfly": "wildfly",
    "joomla": "joomla",
    "spring": "spring",
}


def extract_versions(resp) -> List[Tuple[str, str]]:
    """Extract (service, version) pairs from response headers and body.

    Checks Server, X-Powered-By, X-AspNet-Version, X-Confluence-Version,
    and X-Application-Context headers, plus scans the first 50 KB of the
    response body for CMS and framework version strings.
    """
    found: List[Tuple[str, str]] = []
    seen: set = set()

    headers_to_check = (
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Confluence-Version",
        "X-Application-Context",
        "X-Generator",
    )
    for header in headers_to_check:
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
# CVE database  (35 high-impact entries)
# ---------------------------------------------------------------------------
# Each entry:
#   service     -- normalised service name (matches _SERVICE_ALIASES output)
#   check       -- lambda(version_str) -> bool
#   cve         -- CVE identifier
#   cvss        -- CVSS v3 base score
#   severity    -- CRITICAL / HIGH / MEDIUM / LOW
#   impact      -- 1-3 sentence description (first sentence used as summary)
#   msf         -- Metasploit module path or None
#   msf_payload -- recommended payload for the MSF module (optional)

_CVE_DB: List[Dict] = [
    # ================================================================
    # Apache httpd
    # ================================================================
    {
        "service": "apache",
        "check": lambda v: _eq(v, "2.4.49"),
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Path traversal + RCE via URL-encoded dot-dot sequences. "
            "If mod_cgi/mod_cgid is enabled, attacker achieves full "
            "remote code execution with httpd privileges."
        ),
        "msf": "exploit/multi/http/apache_normalize_path_rce",
        "msf_payload": "linux/x64/meterpreter/reverse_tcp",
    },
    {
        "service": "apache",
        "check": lambda v: _between(v, "2.4.49", "2.4.50"),
        "cve": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Incomplete fix bypass for CVE-2021-41773 via double-encoded "
            "path traversal. Unauthenticated remote code execution. "
            "Trivially exploitable with a single curl command."
        ),
        "msf": "exploit/multi/http/apache_normalize_path_rce",
        "msf_payload": "linux/x64/meterpreter/reverse_tcp",
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.28"),
        "cve": "CVE-2017-9798",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Optionsbleed -- OPTIONS method response leaks fragments of "
            "server memory via a corrupted Allow header. "
            "May expose credentials, session tokens, and data from other requests."
        ),
        "msf": "auxiliary/scanner/http/apache_optionsbleed",
        "msf_payload": None,
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.52"),
        "cve": "CVE-2021-44790",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Heap buffer overflow in mod_lua multipart parser. "
            "A crafted Content-Type boundary triggers the overflow. "
            "Potential RCE if mod_lua is loaded."
        ),
        "msf": None,
        "msf_payload": None,
    },
    {
        "service": "apache",
        "check": lambda v: _lt(v, "2.4.56"),
        "cve": "CVE-2023-25690",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "HTTP request smuggling when mod_proxy and RewriteRule are "
            "enabled together. Bypasses access controls and poisons the "
            "proxy cache, reaching internal backend services."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # Nginx
    # ================================================================
    {
        "service": "nginx",
        "check": lambda v: _between(v, "0.6.18", "1.20.0"),
        "cve": "CVE-2021-23017",
        "cvss": 7.7,
        "severity": "HIGH",
        "impact": (
            "Off-by-one write in the DNS resolver module. "
            "An attacker-controlled DNS response overwrites one byte on the "
            "heap, enabling denial of service or potential RCE."
        ),
        "msf": None,
        "msf_payload": None,
    },
    {
        "service": "nginx",
        "check": lambda v: _lt(v, "1.13.3"),
        "cve": "CVE-2017-7529",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Integer overflow in the range filter module. "
            "A crafted Range request leaks up to 64 KB of server memory "
            "per request -- similar in impact to Heartbleed for Nginx."
        ),
        "msf": None,
        "msf_payload": None,
    },
    {
        "service": "nginx",
        "check": lambda v: _lt(v, "1.17.7"),
        "cve": "CVE-2019-20372",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "impact": (
            "HTTP request smuggling via a crafted request to an upstream "
            "server. Allows cache poisoning and bypassing of security "
            "controls in multi-tier architectures."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # PHP
    # ================================================================
    {
        "service": "php",
        "check": lambda v: (
            _between(v, "8.1.0", "8.1.28")
            or _between(v, "8.2.0", "8.2.19")
            or _between(v, "8.3.0", "8.3.7")
            or _between(v, "5.0.0", "7.4.99")
        ),
        "cve": "CVE-2024-4577",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "PHP-CGI argument injection on Windows via Best-Fit character "
            "mapping, bypassing the CVE-2012-1823 fix. "
            "Unauthenticated RCE -- actively exploited by ransomware groups."
        ),
        "msf": "exploit/multi/http/php_cgi_arg_injection",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "php",
        "check": lambda v: (
            _between(v, "7.1.0", "7.1.32")
            or _between(v, "7.2.0", "7.2.23")
            or _between(v, "7.3.0", "7.3.10")
        ),
        "cve": "CVE-2019-11043",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "PHP-FPM underflow in path handling. With nginx + php-fpm and "
            "specific fastcgi_split_path_info config, attacker overwrites "
            "FCGI environment variables to achieve RCE."
        ),
        "msf": "exploit/multi/http/php_fpm_rce",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "php",
        "check": lambda v: _lt(v, "5.4.2"),
        "cve": "CVE-2012-1823",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "PHP-CGI query string passed as command-line arguments. "
            "Allows source code disclosure (-s flag) and RCE "
            "via -d auto_prepend_file injection."
        ),
        "msf": "exploit/multi/http/php_cgi_arg_injection",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "php",
        "check": lambda v: (
            _between(v, "8.0.0", "8.0.29")
            or _between(v, "8.1.0", "8.1.21")
            or _between(v, "8.2.0", "8.2.7")
        ),
        "cve": "CVE-2023-3824",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Heap buffer overflow in phar_dir_read() when reading a "
            "crafted phar archive. Can lead to remote code execution "
            "on affected PHP installations."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # Microsoft IIS
    # ================================================================
    {
        "service": "iis",
        "check": lambda v: _eq(v, "6.0"),
        "cve": "CVE-2017-7269",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "WebDAV ScStoragePathFromUrl buffer overflow. "
            "Unauthenticated RCE via a crafted PROPFIND request. "
            "Wormable -- widely exploited in the wild."
        ),
        "msf": "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
        "msf_payload": "windows/x64/meterpreter/reverse_tcp",
    },
    {
        "service": "iis",
        "check": lambda v: _between(v, "7.5", "8.5"),
        "cve": "CVE-2015-1635",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "impact": (
            "HTTP.sys integer overflow via a crafted Range header (MS15-034). "
            "Unauthenticated RCE or instant BSOD on Windows. "
            "Affects all unpatched Windows with IIS 7.5 through 8.5."
        ),
        "msf": "auxiliary/dos/http/ms15_034_ulonglongadd",
        "msf_payload": None,
    },
    # ================================================================
    # OpenSSL
    # ================================================================
    {
        "service": "openssl",
        "check": lambda v: (
            _ver(v)[:3] == (1, 0, 1)
            and not re.search(r"1\.0\.1[g-z]", v)
        ),
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Heartbleed -- TLS heartbeat extension leaks up to 64 KB of "
            "server memory per request. Exposes private keys, session "
            "tokens, passwords, and encrypted traffic. Widely exploited."
        ),
        "msf": "auxiliary/scanner/ssl/openssl_heartbleed",
        "msf_payload": None,
    },
    {
        "service": "openssl",
        "check": lambda v: (
            (_ver(v)[:3] == (1, 0, 2) and not re.search(r"1\.0\.2z[d-z]", v))
            or (_ver(v)[:3] == (1, 1, 1) and not re.search(r"1\.1\.1[n-z]", v)
                and _ver(v) >= _ver("1.1.1"))
            or _between(v, "3.0.0", "3.0.1")
        ),
        "cve": "CVE-2022-0778",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Infinite loop in BN_mod_sqrt() when parsing crafted "
            "certificates with an invalid prime. Triggers a denial of "
            "service affecting TLS servers that parse client certificates."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # Apache Tomcat
    # ================================================================
    {
        "service": "tomcat",
        "check": lambda v: (
            _between(v, "7.0.0", "7.0.81")
            or _between(v, "8.0.0", "8.0.46")
            or _between(v, "8.5.0", "8.5.22")
            or _eq(v, "9.0.0")
        ),
        "cve": "CVE-2017-12617",
        "cvss": 8.1,
        "severity": "HIGH",
        "impact": (
            "JSP upload via HTTP PUT when readonly=false on the default "
            "servlet. Attacker uploads a malicious .jsp and achieves "
            "remote code execution as the Tomcat service account."
        ),
        "msf": "exploit/multi/http/tomcat_jsp_upload_bypass",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    {
        "service": "tomcat",
        "check": lambda v: (
            _between(v, "6.0.0", "7.0.99")
            or _between(v, "8.0.0", "8.5.50")
            or _between(v, "9.0.0", "9.0.30")
        ),
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Ghostcat -- AJP connector file read and inclusion. "
            "Unauthenticated attacker reads any file in the webapp directory. "
            "Combined with file upload, achieves RCE."
        ),
        "msf": "auxiliary/admin/http/tomcat_ghostcat",
        "msf_payload": None,
    },
    {
        "service": "tomcat",
        "check": lambda v: (
            _between(v, "7.0.0", "7.0.93")
            or _between(v, "8.5.0", "8.5.39")
            or _between(v, "9.0.0", "9.0.17")
        ),
        "cve": "CVE-2019-0232",
        "cvss": 8.1,
        "severity": "HIGH",
        "impact": (
            "CGI servlet RCE on Windows when enableCmdLineArguments=true. "
            "A crafted URL passes command-line arguments to the CGI script, "
            "achieving remote code execution on Windows hosts."
        ),
        "msf": "exploit/windows/http/tomcat_cgi_cmdlineargs",
        "msf_payload": "windows/x64/meterpreter/reverse_tcp",
    },
    # ================================================================
    # jQuery
    # ================================================================
    {
        "service": "jquery",
        "check": lambda v: _between(v, "1.2.0", "3.4.99"),
        "cve": "CVE-2020-11022",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "impact": (
            "XSS in jQuery.htmlPrefilter. Untrusted HTML passed to DOM "
            "manipulation methods (html(), append()) allows script injection "
            "even with server-side sanitization."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # WordPress
    # ================================================================
    {
        "service": "wordpress",
        "check": lambda v: _lt(v, "5.8.3"),
        "cve": "CVE-2022-21661",
        "cvss": 8.0,
        "severity": "HIGH",
        "impact": (
            "SQL injection via WP_Query. An attacker with subscriber role "
            "exploits tax_query to extract database contents, including "
            "user credentials and private post data."
        ),
        "msf": None,
        "msf_payload": None,
    },
    {
        "service": "wordpress",
        "check": lambda v: _lt(v, "6.2.1"),
        "cve": "CVE-2023-2745",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "impact": (
            "Directory traversal in theme loading via the block editor. "
            "Authenticated (Contributor+) attacker reads arbitrary PHP "
            "file paths outside the intended theme directory."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # Drupal
    # ================================================================
    {
        "service": "drupal",
        "check": lambda v: (
            _lt(v, "7.58")
            or _between(v, "8.0.0", "8.3.8")
            or _between(v, "8.4.0", "8.4.5")
            or _between(v, "8.5.0", "8.5.0")
        ),
        "cve": "CVE-2018-7600",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Drupalgeddon2 -- remote code execution via the Form API. "
            "Unauthenticated attacker injects PHP through request parameters. "
            "Actively mass-exploited within hours of disclosure."
        ),
        "msf": "exploit/unix/webapp/drupal_drupalgeddon2",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "drupal",
        "check": lambda v: (
            _lt(v, "7.59")
            or _between(v, "8.0.0", "8.5.2")
        ),
        "cve": "CVE-2018-7602",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Remote code execution in Drupal core (SA-CORE-2018-004). "
            "Expands on CVE-2018-7600 to affect additional code paths. "
            "Unauthenticated exploitation possible on affected configurations."
        ),
        "msf": "exploit/unix/webapp/drupal_restws_unserialize",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "drupal",
        "check": lambda v: _lt(v, "7.32"),
        "cve": "CVE-2014-3704",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "Drupalgeddon -- SQL injection in the user login form. "
            "Unauthenticated attacker bypasses authentication and injects "
            "arbitrary SQL via crafted username arrays."
        ),
        "msf": "exploit/multi/http/drupal_drupageddon",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    # ================================================================
    # Apache Struts
    # ================================================================
    {
        "service": "struts",
        "check": lambda v: (
            _between(v, "2.3.5", "2.3.31")
            or _between(v, "2.5.0", "2.5.10")
        ),
        "cve": "CVE-2017-5638",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "impact": (
            "Struts2 S2-045: RCE via malicious Content-Type header in "
            "file upload requests. OGNL expression executed in the context "
            "of the JVM -- widely exploited (Equifax breach)."
        ),
        "msf": "exploit/multi/http/struts2_content_type_ognl",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    {
        "service": "struts",
        "check": lambda v: (
            _between(v, "2.3.0", "2.3.34")
            or _between(v, "2.5.0", "2.5.16")
        ),
        "cve": "CVE-2018-11776",
        "cvss": 8.1,
        "severity": "HIGH",
        "impact": (
            "Struts2 S2-057: OGNL injection via namespace value in "
            "result definitions. No prior authentication required when "
            "alwaysSelectFullNamespace is true."
        ),
        "msf": "exploit/multi/http/struts2_namespace_ognl",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    # ================================================================
    # Spring Framework
    # ================================================================
    {
        "service": "spring",
        "check": lambda v: (
            _between(v, "5.3.0", "5.3.17")
            or _between(v, "5.2.0", "5.2.19")
        ),
        "cve": "CVE-2022-22965",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Spring4Shell -- RCE via data binding in Spring MVC on JDK 9+. "
            "Attacker manipulates class.classLoader to write a malicious "
            "JSP via Tomcat's AccessLogValve."
        ),
        "msf": "exploit/multi/http/spring_framework_rce_spring4shell",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    # ================================================================
    # Oracle WebLogic
    # ================================================================
    {
        "service": "weblogic",
        "check": lambda v: (
            _between(v, "10.3.6", "10.3.6")
            or _between(v, "12.1.3", "12.1.3")
            or _between(v, "12.2.1.3", "12.2.1.3")
        ),
        "cve": "CVE-2019-2725",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Deserialization RCE via wls9-async_response and wls-wsat "
            "components. Unauthenticated attacker sends a crafted XML "
            "request to achieve OS-level command execution."
        ),
        "msf": "exploit/multi/misc/weblogic_deserialize_asyncresponseservice",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    {
        "service": "weblogic",
        "check": lambda v: (
            _between(v, "10.3.6", "10.3.6")
            or _between(v, "12.1.3", "12.1.3")
            or _between(v, "12.2.1.3", "12.2.1.4")
            or _eq(v, "14.1.1.0")
        ),
        "cve": "CVE-2020-14882",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "Unauthorized access to the WebLogic console via URL encoding "
            "bypass, combined with CVE-2020-14883 for RCE. "
            "Unauthenticated attacker gains full admin console access."
        ),
        "msf": "exploit/multi/http/oracle_weblogic_wls_wsat_deserialization",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    # ================================================================
    # Atlassian Confluence
    # ================================================================
    {
        "service": "confluence",
        "check": lambda v: (
            _between(v, "1.3.0", "7.4.16")
            or _between(v, "7.13.0", "7.13.6")
            or _between(v, "7.14.0", "7.14.2")
            or _between(v, "7.15.0", "7.15.1")
            or _between(v, "7.16.0", "7.16.3")
            or _between(v, "7.17.0", "7.17.3")
            or _eq(v, "7.18.0")
        ),
        "cve": "CVE-2022-26134",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "impact": (
            "OGNL injection in Confluence Server and Data Center. "
            "Unauthenticated attacker injects OGNL via the URI, achieving "
            "remote code execution. Exploited as zero-day in the wild."
        ),
        "msf": "exploit/multi/http/atlassian_confluence_namespaceaccessfilter_ognl_injection",
        "msf_payload": "java/meterpreter/reverse_tcp",
    },
    {
        "service": "confluence",
        "check": lambda v: (
            _between(v, "8.0.0", "8.3.2")
            or _between(v, "8.4.0", "8.4.2")
            or _between(v, "8.5.0", "8.5.1")
        ),
        "cve": "CVE-2023-22515",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "impact": (
            "Broken access control allows unauthenticated attacker to "
            "create an admin account via /setup/setupadministrator.action. "
            "Trivial to exploit -- used by nation-state actors."
        ),
        "msf": None,
        "msf_payload": None,
    },
    # ================================================================
    # Joomla
    # ================================================================
    {
        "service": "joomla",
        "check": lambda v: (
            _between(v, "1.5.0", "1.5.25")
            or _between(v, "2.5.0", "2.5.21")
            or _between(v, "3.0.0", "3.4.4")
        ),
        "cve": "CVE-2015-8562",
        "cvss": 7.5,
        "severity": "HIGH",
        "impact": (
            "PHP object injection via crafted HTTP User-Agent header. "
            "Attacker triggers deserialization of a malicious object, "
            "achieving remote code execution without authentication."
        ),
        "msf": "exploit/multi/http/joomla_http_header_rce",
        "msf_payload": "php/meterpreter/reverse_tcp",
    },
    {
        "service": "joomla",
        "check": lambda v: _between(v, "4.0.0", "4.2.7"),
        "cve": "CVE-2023-23752",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "impact": (
            "Improper access check in the Joomla API exposes configuration "
            "data (database credentials, SMTP passwords) to unauthenticated "
            "requests to /api/index.php/v1/config/application."
        ),
        "msf": None,
        "msf_payload": None,
    },
]


def match_cves(versions: List[Tuple[str, str]]) -> List[Dict]:
    """Match detected service versions against the CVE database.

    Returns a list of dicts with keys: service, version, cve, cvss,
    severity, impact, msf, msf_payload, advisory.
    Sorted by CVSS score descending (most critical first).
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
                        "msf_payload": entry.get("msf_payload"),
                        "advisory": f"https://nvd.nist.gov/vuln/detail/{entry['cve']}",
                    })
            except Exception:
                continue

    matches.sort(key=lambda m: m["cvss"], reverse=True)
    return matches
