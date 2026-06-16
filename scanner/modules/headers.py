"""Security Headers analysis module.

Checks for missing or misconfigured HTTP security headers that can lead to
clickjacking, MIME-sniffing, XSS, information disclosure, and other attacks.

This module operates differently from the injection-based modules: it does NOT
fuzz parameters. Instead it inspects the baseline response headers and body for
security misconfigurations and information leaks.
"""

import re
from typing import Dict, List, Optional, Tuple

import logging

from .base import BaseModule, Finding

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Security headers that should be present
# ---------------------------------------------------------------------------
_EXPECTED_HEADERS: List[Tuple[str, str, str]] = [
    # (header_name, risk_if_missing, remediation)
    (
        "X-Frame-Options",
        "Clickjacking -- page can be embedded in malicious iframes",
        "Set X-Frame-Options: DENY or SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options",
        "MIME-sniffing -- browser may interpret files as executable content",
        "Set X-Content-Type-Options: nosniff",
    ),
    (
        "Strict-Transport-Security",
        "No HSTS -- connections can be downgraded to HTTP (MITM)",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "No CSP -- no defence against XSS and data injection attacks",
        "Define a strict Content-Security-Policy header",
    ),
    (
        "X-XSS-Protection",
        "Missing XSS filter header (legacy browsers)",
        "Set X-XSS-Protection: 1; mode=block (or rely on CSP)",
    ),
    (
        "Referrer-Policy",
        "Sensitive URLs may leak via Referer header to third parties",
        "Set Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "Browser features (camera, mic, geolocation) not restricted",
        "Set Permissions-Policy to restrict unnecessary features",
    ),
]

# ---------------------------------------------------------------------------
# Server banners / version disclosure patterns
# ---------------------------------------------------------------------------
_VERSION_PATTERNS: List[Tuple[str, str]] = [
    (r"Apache/[\d.]+", "Apache version"),
    (r"nginx/[\d.]+", "Nginx version"),
    (r"Microsoft-IIS/[\d.]+", "IIS version"),
    (r"PHP/[\d.]+", "PHP version"),
    (r"OpenSSL/[\d.\w]+", "OpenSSL version"),
    (r"Express", "Express.js framework"),
    (r"ASP\.NET", "ASP.NET framework"),
    (r"Werkzeug/[\d.]+", "Werkzeug/Flask version"),
    (r"Jetty\([\d.]+\)", "Jetty version"),
    (r"Python/[\d.]+", "Python version"),
]

# Headers that commonly leak server info
_INFO_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
]

# CORS misconfigurations
_DANGEROUS_CORS_ORIGINS = [
    "*",
    "null",
]


class HeaderScanner(BaseModule):
    """Checks HTTP security headers, info disclosure, and CORS config."""

    NAME = "headers"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self._scanned = False  # only scan once per target URL

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Header scan runs once per URL, not per-parameter.

        We use scan_parameter's first call to trigger the analysis and return
        an empty list on subsequent calls for the same URL.
        """
        if self._scanned:
            return []
        self._scanned = True

        resp = self.http.get(url)
        if resp is None:
            return []

        findings: List[Finding] = []
        findings.extend(self._check_missing_headers(url, resp))
        findings.extend(self._check_info_disclosure(url, resp))
        findings.extend(self._check_cors(url, resp))

        return findings

    # ------------------------------------------------------------------
    # Missing security headers
    # ------------------------------------------------------------------

    def _check_missing_headers(self, url, resp) -> List[Finding]:
        findings = []
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # CSP value (needed for several X-Frame-Options / X-XSS-Protection exemptions)
        csp_value = resp_headers_lower.get("content-security-policy", "")

        for header_name, risk, remediation in _EXPECTED_HEADERS:
            if header_name.lower() in resp_headers_lower:
                continue

            # HSTS only matters for HTTPS
            if header_name == "Strict-Transport-Security" and not url.startswith("https"):
                continue

            # X-Frame-Options: skip if CSP already sets frame-ancestors.
            # frame-ancestors in CSP takes precedence over X-Frame-Options in all
            # modern browsers and is the recommended modern mechanism.
            if header_name == "X-Frame-Options":
                if "frame-ancestors" in csp_value.lower():
                    logger.debug(
                        "[Headers] Skipping X-Frame-Options: CSP frame-ancestors present (%s)",
                        csp_value[:80],
                    )
                    continue

            # X-XSS-Protection: skip if CSP is present (CSP supersedes the legacy header)
            if header_name == "X-XSS-Protection" and csp_value:
                continue

            findings.append(Finding(
                vuln_type=f"Missing Security Header: {header_name}",
                url=url,
                method="GET",
                parameter="(response headers)",
                payload="N/A",
                evidence=f"Header '{header_name}' is absent from the response",
                confidence="low",
                details=f"{risk}. {remediation}.",
                reproduction=(
                    f"# 1. Inspect the response headers:\n"
                    f"$ curl -s -k -I \"{url}\" | grep -i \"{header_name}\"\n"
                    f"# 2. If no output, the header is missing.\n"
                    f"# 3. Fix: {remediation}."
                ),
            ))

        # CSP present but WEAK. A header being present isn't enough — a policy
        # that allows 'unsafe-inline' script or wildcard sources doesn't actually
        # stop XSS. Report this as its own finding (medium), separate from the
        # "missing CSP" case, so a reflected-XSS that fires *despite* a CSP is
        # explained rather than looking contradictory.
        weak = self._weak_csp_reasons(csp_value)
        if csp_value and weak:
            findings.append(Finding(
                vuln_type="Weak Content-Security-Policy",
                url=url,
                method="GET",
                parameter="(response headers)",
                payload="N/A",
                evidence=f"CSP present but permissive: {', '.join(weak)} — policy: {csp_value[:120]}",
                confidence="medium",
                details=(
                    "A Content-Security-Policy is set but does not meaningfully "
                    f"constrain script execution ({'; '.join(weak)}). With "
                    "'unsafe-inline' or wildcard sources, injected inline scripts "
                    "still run, so the CSP provides little protection against XSS. "
                    "Remediation: remove 'unsafe-inline'/'unsafe-eval', avoid '*' "
                    "in script/default-src, and use nonces or hashes for inline scripts."
                ),
                reproduction=(
                    f"# 1. Read the CSP header:\n"
                    f"$ curl -s -k -I \"{url}\" | grep -i content-security-policy\n"
                    f"# 2. Look for 'unsafe-inline' / 'unsafe-eval' / '*' in script-src\n"
                    f"#    or default-src — these let injected inline script execute.\n"
                    f"# 3. An XSS payload like <script>alert(1)</script> still fires."
                ),
            ))

        return findings

    @staticmethod
    def _weak_csp_reasons(csp: str):
        """Return the list of reasons a CSP is too permissive to stop XSS, or []."""
        if not csp:
            return []
        low = csp.lower()
        reasons = []
        # Pull the directive that governs scripts (script-src, else default-src).
        directives = {}
        for part in low.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, val = part.partition(" ")
            directives[name.strip()] = val.strip()
        script_policy = directives.get("script-src", directives.get("default-src", ""))
        if "'unsafe-inline'" in script_policy:
            reasons.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in script_policy:
            reasons.append("script-src allows 'unsafe-eval'")
        # Bare wildcard host source (not the safe 'self'); ignore data: scheme etc.
        for tok in script_policy.split():
            if tok == "*" or tok.endswith("://*") or tok == "http:" or tok == "https:":
                reasons.append(f"script source is wildcard ({tok})")
                break
        # default-src * with no script-src override leaves scripts wide open.
        if "script-src" not in directives and directives.get("default-src", "") .strip() in ("*", "http:", "https:"):
            reasons.append("default-src is a wildcard with no script-src")
        return reasons

    # ------------------------------------------------------------------
    # Information disclosure
    # ------------------------------------------------------------------

    def _check_info_disclosure(self, url, resp) -> List[Finding]:
        findings = []

        for header_name in _INFO_HEADERS:
            value = resp.headers.get(header_name, "")
            if not value:
                continue

            # Check for version numbers in the value
            for pattern, tech in _VERSION_PATTERNS:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    findings.append(Finding(
                        vuln_type="Information Disclosure (Server Header)",
                        url=url,
                        method="GET",
                        parameter=header_name,
                        payload="N/A",
                        evidence=f"{header_name}: {value} -- exposes {tech}",
                        confidence="low",
                        details=(
                            f"Server header '{header_name}' reveals {tech} ({match.group()}). "
                            f"Remediation: suppress version info in {header_name} header."
                        ),
                        reproduction=(
                            f"# 1. Check the {header_name} header:\n"
                            f"$ curl -s -k -I \"{url}\" | grep -i \"{header_name}\"\n"
                            f"# 2. If output shows version info (e.g. '{match.group()}'),\n"
                            f"#    the server is leaking technology details.\n"
                            f"# 3. Use this info for targeted exploits (search CVEs for {tech})."
                        ),
                    ))
                    break
            else:
                # Header present but no known version pattern -- still log X-Powered-By
                if header_name.lower() in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                    findings.append(Finding(
                        vuln_type="Information Disclosure (Technology)",
                        url=url,
                        method="GET",
                        parameter=header_name,
                        payload="N/A",
                        evidence=f"{header_name}: {value}",
                        confidence="low",
                        details=f"Remove or suppress the {header_name} header.",
                        reproduction=(
                            f"# 1. Check the {header_name} header:\n"
                            f"$ curl -s -k -I \"{url}\" | grep -i \"{header_name}\"\n"
                            f"# 2. Output '{header_name}: {value}' reveals the technology stack.\n"
                            f"# 3. Search for known CVEs targeting this technology."
                        ),
                    ))

        return findings

    # ------------------------------------------------------------------
    # CORS misconfiguration
    # ------------------------------------------------------------------

    def _check_cors(self, url, resp) -> List[Finding]:
        findings = []
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        # --- Passive check: wildcard / null ACAO on the baseline response ---
        if acao in _DANGEROUS_CORS_ORIGINS:
            confidence = "high" if acac == "true" else "medium"
            findings.append(Finding(
                vuln_type="CORS Misconfiguration",
                url=url,
                method="GET",
                parameter="Access-Control-Allow-Origin",
                payload="N/A",
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}"
                    + (f" + Allow-Credentials: true" if acac == "true" else "")
                ),
                confidence=confidence,
                details=(
                    f"Wildcard or null CORS origin allows any site to read responses"
                    + (". Combined with credentials=true, this enables full account takeover via CORS." if acac == "true" else ".")
                    + " Remediation: restrict to specific trusted origins."
                ),
                reproduction=(
                    f"# 1. Send a cross-origin request with an Origin header:\n"
                    f"$ curl -s -k -I -H \"Origin: https://attacker.com\" \"{url}\"\n"
                    f"# 2. Check the CORS headers in the response:\n"
                    f"$ # Look for: Access-Control-Allow-Origin: {acao}\n"
                    + (f"$ # And: Access-Control-Allow-Credentials: true\n"
                       f"# 3. CRITICAL: credentials=true + wildcard/null origin = full account takeover.\n"
                       f"#    Any malicious site can make authenticated requests on behalf of the user."
                       if acac == "true" else
                       f"# 3. If the response reflects your Origin header or uses '*',\n"
                       f"#    any website can read the response cross-origin.")
                ),
            ))

        # --- Active check: probe for origin reflection ---
        # Many servers reflect the caller's Origin header back, even when ACAO
        # was not present on the baseline response. Test with a canary origin.
        _CANARY_ORIGIN = "https://attacker-cors-probe.com"
        probe_resp = self.http.get(url, headers={"Origin": _CANARY_ORIGIN})
        if probe_resp is not None:
            probe_acao = probe_resp.headers.get("Access-Control-Allow-Origin", "")
            probe_acac = probe_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if probe_acao == _CANARY_ORIGIN:
                # Server reflected our injected Origin back — CORS misconfiguration
                confidence = "high" if probe_acac == "true" else "medium"
                findings.append(Finding(
                    vuln_type="CORS Misconfiguration (Reflected Origin)",
                    url=url,
                    method="GET",
                    parameter="Origin",
                    payload=_CANARY_ORIGIN,
                    evidence=(
                        f"Server reflected injected Origin: Access-Control-Allow-Origin: {probe_acao}"
                        + (f" + Allow-Credentials: true" if probe_acac == "true" else "")
                    ),
                    confidence=confidence,
                    details=(
                        "The server reflects any Origin header back in Access-Control-Allow-Origin, "
                        "allowing any website to make cross-origin requests and read the response"
                        + (". Combined with Allow-Credentials: true, this enables full account takeover." if probe_acac == "true" else ".")
                        + " Remediation: validate Origin against an explicit allow-list; never reflect arbitrary origins."
                    ),
                    reproduction=(
                        f"# 1. Send request with arbitrary Origin and check reflection:\n"
                        f"$ curl -s -I -H \"Origin: {_CANARY_ORIGIN}\" \"{url}\"\n"
                        f"# 2. Look for: Access-Control-Allow-Origin: {_CANARY_ORIGIN}\n"
                        + (f"# 3. CRITICAL: also check for Access-Control-Allow-Credentials: true\n"
                           f"#    This combination allows reading authenticated responses from any origin."
                           if probe_acac == "true" else
                           f"# 3. Any attacker domain can now read responses from this endpoint.")
                    ),
                ))

        return findings
