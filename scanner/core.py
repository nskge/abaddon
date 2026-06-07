"""Core scanner orchestration -- coordinates modules and manages the scan flow."""

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse
import logging

from .http_client import HTTPClient
from .modules.base import Finding
from .modules.cmdi import CommandInjectionScanner
from .modules.crlf import CRLFScanner
from .modules.headers import HeaderScanner
from .modules.lfi import LFIScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.sqli import SQLiScanner
from .modules.ssti import SSTIScanner
from .modules.xss import XSSScanner
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
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "lfi": LFIScanner,
    "redirect": OpenRedirectScanner,
    "cmdi": CommandInjectionScanner,
    "crlf": CRLFScanner,
    "ssti": SSTIScanner,
    "headers": HeaderScanner,
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
    (r"react", "React"),
    (r"ng-version=", "Angular"),
    (r"vue\.js", "Vue.js"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
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

        self.http = HTTPClient(
            headers=config.get("headers", {}),
            cookies=config.get("cookies", {}),
            proxy=config.get("proxy"),
            timeout=config.get("timeout", 10),
            follow_redirects=config.get("follow_redirects", True),
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
            self._print_recon(url)

            logger.info("Target  : %s [%s]", url, method)
            logger.info("Modules : %s", [cls.NAME for cls in self.module_classes])

            baseline_resp = self._preflight_check(url, method, data_string)

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

        # Quick GET request for server info + fingerprinting
        server = ""
        status = ""
        techs: List[str] = []
        resp = None
        try:
            resp = self.http.get(url)
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
        print(self._c("   | Scheme   : ", _DIM) + self._c(parsed.scheme.upper(), _CYAN))
        print(self._c("   +----------------------", _DIM))
        print()

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

        return resp

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

        # Each module gets its own HTTPClient so they can scan in parallel
        # without sharing state (e.g. redirect following toggle)
        def _run_module(module_cls):
            http_copy = HTTPClient(
                headers=self.config.get("headers", {}),
                cookies=self.config.get("cookies", {}),
                proxy=self.config.get("proxy"),
                timeout=self.config.get("timeout", 10),
                follow_redirects=self.config.get("follow_redirects", True),
            )
            module = module_cls(http_copy, self.config)
            return module.scan_parameter(url, method, params, param_name)

        # Run modules concurrently for speed
        max_workers = self.config.get("threads", _DEFAULT_WORKERS)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run_module, cls): cls.NAME
                for cls in self.module_classes
            }
            try:
                for future in as_completed(futures):
                    mod_name = futures[future]
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
