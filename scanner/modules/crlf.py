"""CRLF Injection (HTTP Response Splitting) detection module.

Detection strategy:
  Inject CRLF sequences (%0d%0a) followed by a custom header marker.
  If the injected header appears in the HTTP response headers, the server
  is vulnerable to header injection / response splitting.

  Also checks for CRLF in the body (reflected in HTML) which can lead to
  XSS via header injection when combined with other vectors.

Impact:
  - HTTP response splitting
  - Cache poisoning
  - Session fixation via Set-Cookie injection
  - XSS via injected Content-Type or body content
"""

import re
from typing import Dict, List, Optional

import logging

from .base import BaseModule, Finding
from ..parser import inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# CRLF payloads
# ---------------------------------------------------------------------------
# Each tuple: (payload_suffix, description, marker_header)
# The marker header is what we look for in response headers
_MARKER_HEADER = "OkrInjected"
_MARKER_VALUE = "true"

_CRLF_PAYLOADS = [
    # Standard CRLF
    (f"%0d%0a{_MARKER_HEADER}:%20{_MARKER_VALUE}", "URL-encoded CRLF"),
    (f"%0d%0a{_MARKER_HEADER}: {_MARKER_VALUE}", "URL-encoded CRLF (space)"),
    # Double-encoded
    (f"%250d%250a{_MARKER_HEADER}:%20{_MARKER_VALUE}", "Double URL-encoded CRLF"),
    # Unicode variants
    (f"%0d%0a%20{_MARKER_HEADER}:%20{_MARKER_VALUE}", "CRLF with leading space"),
    (f"%0a{_MARKER_HEADER}:%20{_MARKER_VALUE}", "LF only"),
    (f"%0d{_MARKER_HEADER}:%20{_MARKER_VALUE}", "CR only"),
    # UTF-8 line separators
    (f"%e5%98%8a%e5%98%8d{_MARKER_HEADER}:%20{_MARKER_VALUE}", "UTF-8 encoded CRLF"),
    # Response splitting for body injection
    (f"%0d%0a%0d%0a<okrscann>injected</okrscann>", "CRLF body injection"),
    # Set-Cookie injection
    (f"%0d%0aSet-Cookie:%20okrtest=injected", "Set-Cookie injection"),
]

# For body reflection detection
_BODY_MARKERS = [
    "<okrscann>injected</okrscann>",
    "okrtest=injected",
]


class CRLFScanner(BaseModule):
    """Detects CRLF injection / HTTP response splitting."""

    NAME = "crlf"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self.custom_payloads: Optional[str] = config.get("custom_payloads")

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Test *param_name* for CRLF injection."""
        findings: List[Finding] = []
        original_value = params.get(param_name, "")

        for payload_suffix, description in _CRLF_PAYLOADS:
            # Append mode: original_value + CRLF payload
            injected = original_value + payload_suffix
            finding = self._test_injection(
                url, method, params, param_name, injected, description,
            )
            if finding:
                findings.append(finding)
                return findings  # One confirmed finding is enough

            # Replace mode
            finding = self._test_injection(
                url, method, params, param_name, payload_suffix, description,
            )
            if finding:
                findings.append(finding)
                return findings

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _test_injection(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        payload: str,
        description: str,
    ) -> Optional[Finding]:
        """Send the payload and check for injected header or body marker."""
        resp = self._send(
            url, method, inject_into_params(params, param_name, payload),
        )
        if resp is None:
            return None

        # Check 1: injected header in response headers
        for header_name in resp.headers:
            if _MARKER_HEADER.lower() in header_name.lower():
                return Finding(
                    vuln_type="CRLF Injection (Header Injection)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"Injected header '{_MARKER_HEADER}' found in response "
                        f"headers via {description}"
                    ),
                    confidence="high",
                    details=(
                        f"CRLF characters in parameter {param_name!r} allow injecting "
                        f"arbitrary HTTP response headers. This can lead to cache "
                        f"poisoning, session fixation, and XSS. "
                        f"Remediation: strip or reject CR/LF characters in all "
                        f"user input that flows into HTTP headers or redirects."
                    ),
                )

        # Check 2: Set-Cookie injection
        set_cookie = resp.headers.get("Set-Cookie", "")
        if "okrtest=injected" in set_cookie:
            return Finding(
                vuln_type="CRLF Injection (Set-Cookie Injection)",
                url=url,
                method=method,
                parameter=param_name,
                payload=payload,
                evidence=f"Injected Set-Cookie header found: {set_cookie[:100]}",
                confidence="high",
                details=(
                    f"CRLF injection via {description} allows injecting Set-Cookie "
                    f"headers, enabling session fixation attacks. "
                    f"Remediation: sanitize CR/LF from user input in header values."
                ),
            )

        # Check 3: body injection marker
        for marker in _BODY_MARKERS:
            if marker in resp.text:
                return Finding(
                    vuln_type="CRLF Injection (Response Splitting)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Injected body content found in response: {marker!r}",
                    confidence="high",
                    details=(
                        f"CRLF response splitting via {description} allows injecting "
                        f"arbitrary content into the HTTP response body. This can "
                        f"lead to XSS and cache poisoning. "
                        f"Remediation: reject CR/LF characters in user input."
                    ),
                )

        return None
