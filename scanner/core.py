"""Core scanner orchestration -- coordinates modules and manages the scan flow."""

import re
from typing import Dict, List, Optional
import logging

from .http_client import HTTPClient
from .modules.base import Finding
from .modules.cmdi import CommandInjectionScanner
from .modules.headers import HeaderScanner
from .modules.lfi import LFIScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.sqli import SQLiScanner
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
    "headers": HeaderScanner,
}


class Scanner:
    """Orchestrates vulnerability scanning across one or more modules.

    Usage::

        config = {"url": "http://target/page?id=1", "scan_type": "all", ...}
        findings = Scanner(config).run()
    """

    def __init__(self, config: Dict, app_logger=None) -> None:
        self.config = config
        self.findings: List[Finding] = []

        self.http = HTTPClient(
            headers=config.get("headers", {}),
            cookies=config.get("cookies", {}),
            proxy=config.get("proxy"),
            timeout=config.get("timeout", 10),
            follow_redirects=config.get("follow_redirects", True),
        )

        scan_type = config.get("scan_type", "all")
        if scan_type == "all":
            self.modules = [cls(self.http, config) for cls in _MODULE_MAP.values()]
        elif scan_type in _MODULE_MAP:
            self.modules = [_MODULE_MAP[scan_type](self.http, config)]
        else:
            raise ValueError(f"Unknown scan type: {scan_type!r}")

    def run(self) -> List[Finding]:
        """Execute the scan and return all findings."""
        url = self.config["url"]
        method = self.config.get("method", "GET").upper()
        data_string = self.config.get("data") or ""
        target_param = self.config.get("param")
        crawl = self.config.get("crawl", False)

        logger.info("Target  : %s [%s]", url, method)
        logger.info("Modules : %s", [m.NAME for m in self.modules])

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

        n = len(self.findings)
        logger.info("Scan complete -- %d finding%s.", n, "" if n == 1 else "s")
        return self.findings

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

        for module in self.modules:
            logger.debug("    Module: %s", module.NAME)
            new_findings = module.scan_parameter(url, method, params, param_name)
            for f in new_findings:
                logger.info(
                    "    [VULN] %s  param=%r  confidence=%s",
                    f.vuln_type, f.parameter, f.confidence,
                )
            self.findings.extend(new_findings)
