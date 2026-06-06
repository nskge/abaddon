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

        for header_name, risk, remediation in _EXPECTED_HEADERS:
            if header_name.lower() not in resp_headers_lower:
                # HSTS only matters for HTTPS
                if header_name == "Strict-Transport-Security" and not url.startswith("https"):
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
                ))

        return findings

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
                    ))

        return findings

    # ------------------------------------------------------------------
    # CORS misconfiguration
    # ------------------------------------------------------------------

    def _check_cors(self, url, resp) -> List[Finding]:
        findings = []
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            return findings

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
            ))

        return findings
