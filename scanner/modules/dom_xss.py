"""DOM-based XSS detection module.

Reflected-XSS scanners see only server-rendered HTML. DOM XSS happens entirely
in the browser: a JavaScript *source* the attacker controls (location.hash,
window.name, postMessage…) flows into a dangerous *sink* (innerHTML, eval,
document.write…) without sanitisation. The payload often never touches the
server, so it can't be found by inspecting the HTTP response body alone.

Two layers, degrading gracefully:

  1. Static taint analysis (always runs): fetch the page + same-origin scripts
     and flag source→sink pairs. High signal, but can't prove exploitability —
     reported at low/medium confidence.

  2. Dynamic confirmation (when Playwright is installed): load the page in real
     Chromium with a canary payload in the URL fragment/params and hook the
     dialog event. An ``alert()`` firing is proof of execution → high confidence.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .base import BaseModule, Finding

logger = logging.getLogger("vulnscanner")

# Attacker-controllable DOM sources.
_SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\.pathname",
    r"document\.URL", r"document\.documentURI", r"document\.baseURI",
    r"document\.referrer", r"window\.name", r"history\.pushState", r"history\.replaceState",
    r"localStorage", r"sessionStorage", r"document\.cookie",
    r"addEventListener\(['\"]message['\"]",  # postMessage handler
]

# Dangerous sinks that execute or render markup.
_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(?:ln)?\s*\(", "document.write"),
    (r"\beval\s*\(", "eval"),
    (r"\bsetTimeout\s*\(\s*[\"']", "setTimeout(string)"),
    (r"\bsetInterval\s*\(\s*[\"']", "setInterval(string)"),
    (r"\bnew\s+Function\s*\(", "Function constructor"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\.html\s*\(", "jQuery .html()"),
    (r"\$\s*\(\s*location", "jQuery $(location)"),
    (r"\.after\s*\(", "jQuery .after()"),
    (r"\.append\s*\(", "jQuery .append()"),
    (r"\.before\s*\(", "jQuery .before()"),
    (r"\.add\s*\(", "jQuery .add()"),
]

# Canary that, if reflected unsanitised into an HTML sink, fires alert.
_CANARY_TOKEN = "domx9731"
_DYNAMIC_PAYLOADS = [
    f'"><img src=x onerror=alert("{_CANARY_TOKEN}")>',
    f"<img src=x onerror=alert('{_CANARY_TOKEN}')>",
    f"javascript:alert('{_CANARY_TOKEN}')",
    f"'-alert('{_CANARY_TOKEN}')-'",
]


def analyze_sources_sinks(js_text: str) -> List[Tuple[str, str]]:
    """Return (source, sink) pairs co-occurring in *js_text*.

    Pure function — the testable heart of the static layer. A pair is reported
    when a controllable source and a dangerous sink both appear; proximity isn't
    proven (that needs real taint tracking) so callers report it conservatively.
    """
    found_sources = [s for s in _SOURCES if re.search(s, js_text)]
    if not found_sources:
        return []
    pairs: List[Tuple[str, str]] = []
    for sink_re, sink_name in _SINKS:
        if re.search(sink_re, js_text):
            for src in found_sources:
                # Clean the regex escaping for display.
                src_display = src.replace("\\", "").replace("['\"]message['\"]", "(message)")
                pairs.append((src_display, sink_name))
    return pairs


class DOMXSSScanner(BaseModule):
    """Detects DOM-based XSS via static taint analysis + optional dynamic proof."""

    NAME = "domxss"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self._scanned_urls: set = set()

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        # DOM XSS is a page property, not a param property — scan each URL once.
        if url in self._scanned_urls:
            return []
        self._scanned_urls.add(url)

        findings: List[Finding] = []

        resp = self.http.get(url)
        if resp is None:
            return findings

        # ---- Layer 1: static taint analysis over page + same-origin scripts ----
        js_blob = self._collect_js(url, resp)
        pairs = analyze_sources_sinks(js_blob)
        if pairs:
            # Collapse to the most dangerous unique sinks for a concise finding.
            unique = sorted(set(pairs))[:6]
            pretty = ", ".join(f"{src}→{sink}" for src, sink in unique)
            findings.append(Finding(
                vuln_type="DOM XSS (Potential — static taint)",
                url=url,
                method="GET",
                parameter="(client-side JS)",
                payload="source→sink flow",
                evidence=f"Controllable source reaches a dangerous sink: {pretty}",
                confidence="low",
                details=(
                    "Client-side JavaScript reads an attacker-controllable source "
                    "and passes data to a sink that renders HTML or executes code. "
                    "If the path isn't sanitised this is DOM XSS — exploitable "
                    "without the payload ever reaching the server (it can live in "
                    "the URL fragment). Confirm dynamically (see steps). "
                    "Remediation: use textContent not innerHTML, avoid eval, and "
                    "sanitise with Trusted Types / DOMPurify."
                ),
                reproduction=(
                    f"# 1. Open with a fragment payload (server never sees the hash):\n"
                    f"#    {url}#<img src=x onerror=alert(document.domain)>\n"
                    f"# 2. Set a JS breakpoint on the sink and trace the source:\n"
                    f"#    DevTools → Sources → search for the sink, add a DOM breakpoint.\n"
                    f"# 3. Automate with DOM Invader (Burp) or:\n"
                    f"$ npx @hahwul/dalfox url '{url}' --deep-domxss"
                ),
            ))

        # ---- Layer 2: dynamic confirmation (Playwright) ----
        if self.config.get("js_crawl") or self.config.get("dom_dynamic"):
            confirmed = self._dynamic_confirm(url)
            findings.extend(confirmed)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_js(self, url: str, resp) -> str:
        """Concatenate inline scripts + same-origin external scripts."""
        body = resp.text
        blob = [body]
        target_host = urlparse(url).hostname or ""
        seen = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I):
            src = urljoin(url, m.group(1))
            if src in seen or (urlparse(src).hostname or "") != target_host:
                continue
            seen.add(src)
            try:
                r = self.http.get(src)
            except Exception:
                r = None
            if r is not None:
                blob.append(r.text)
        return "\n".join(blob)

    def _dynamic_confirm(self, url: str) -> List[Finding]:
        """Load *url* with canary payloads in Chromium; report alerts as proof."""
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            logger.debug("[dom-xss] Playwright not installed — dynamic layer skipped.")
            return []

        findings: List[Finding] = []
        proxy_url = self.config.get("proxy")
        pw_kwargs = {"proxy": {"server": proxy_url}} if proxy_url else {}

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, **pw_kwargs)
                for payload in _DYNAMIC_PAYLOADS:
                    fired = {"hit": False, "payload": payload}
                    page = browser.new_context().new_page()

                    def _on_dialog(dialog):
                        if _CANARY_TOKEN in (dialog.message or ""):
                            fired["hit"] = True
                        try:
                            dialog.dismiss()
                        except Exception:
                            pass
                    page.on("dialog", _on_dialog)

                    # Try the payload in the fragment and as a ?q= param.
                    for variant in (f"{url}#{payload}", f"{url}{'&' if '?' in url else '?'}q={payload}"):
                        try:
                            page.goto(variant, wait_until="load", timeout=self.config.get("timeout", 15) * 1000)
                            page.wait_for_timeout(500)
                        except PWTimeout:
                            pass
                        except Exception as exc:
                            logger.debug("[dom-xss] nav error: %s", exc)
                        if fired["hit"]:
                            break

                    if fired["hit"]:
                        findings.append(Finding(
                            vuln_type="DOM XSS (Confirmed)",
                            url=url,
                            method="GET",
                            parameter="(URL fragment/param)",
                            payload=payload,
                            evidence=f"alert('{_CANARY_TOKEN}') executed in Chromium with payload: {payload}",
                            confidence="high",
                            details=(
                                "A canary payload placed in the URL executed JavaScript "
                                "in a real browser — confirmed DOM XSS. This fires with "
                                "zero server interaction when delivered via the fragment."
                            ),
                            reproduction=(
                                f"# Open in a browser — the alert fires on load:\n"
                                f"#   {url}#{payload}\n"
                                f"# The payload in the fragment is never sent to the server,\n"
                                f"# so server-side WAFs and logs never see it."
                            ),
                        ))
                        break  # one confirmed proof is enough
                    page.close()
                browser.close()
        except Exception as exc:
            logger.debug("[dom-xss] dynamic layer error: %s", exc)

        return findings
