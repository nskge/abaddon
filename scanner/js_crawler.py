"""JavaScript-aware crawler using Playwright.

Used when ``--js-crawl`` is passed.  Renders the page in a real Chromium
browser, simulates common user interactions (button clicks that reveal modal
forms), intercepts all XHR/Fetch requests, and returns injectable targets
alongside discovered form fields -- including those that only appear after
JavaScript executes.

Why this is necessary
---------------------
Traditional HTML parsing (BeautifulSoup) sees only the *static* HTML
returned by the server.  Single Page Applications (SPAs) like Firebase,
React, Vue, and Angular apps render their UI entirely in the browser.
Form fields often:
  - Have no ``name`` attribute (controlled via JS ``getElementById``).
  - Only appear after a user action (button click, route change).
  - Submit data to a completely different domain (e.g. Firebase Auth API).

This crawler handles all three cases.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Selectors for buttons / links that commonly reveal hidden forms
# ---------------------------------------------------------------------------
_REVEAL_SELECTORS = [
    # English
    "button:has-text('Register')",   "button:has-text('Sign up')",
    "button:has-text('Sign Up')",    "button:has-text('Signup')",
    "button:has-text('Login')",      "button:has-text('Log in')",
    "button:has-text('Log In')",     "button:has-text('Signin')",
    "button:has-text('Sign in')",    "button:has-text('Contact')",
    "button:has-text('Submit')",     "button:has-text('Search')",
    # Portuguese
    "button:has-text('Cadastrar')",  "button:has-text('Cadastro')",
    "button:has-text('Registrar')",  "button:has-text('Entrar')",
    "button:has-text('Acessar')",    "button:has-text('Buscar')",
    "button:has-text('Pesquisar')",  "button:has-text('Contato')",
    "button:has-text('Enviar')",
    # Generic tab/nav patterns
    "[role='tab']",  "[data-tab]",  "[data-bs-toggle='tab']",
    "[data-bs-toggle='modal']",     ".tab",  ".tab-link",
    "a[href='#register']", "a[href='#login']", "a[href='#signup']",
    "a[href='#cadastro']", "a[href='#entrar']",
]

# How long to wait after each click for the DOM to settle (ms)
_SETTLE_MS = 600


def _collect_inputs(page) -> List[Dict]:
    """Return all input fields visible on the current page state."""
    return page.evaluate("""() => {
        const inputs = [];
        for (const el of document.querySelectorAll('input, textarea, select')) {
            const rect = el.getBoundingClientRect();
            const visible = rect.width > 0 && rect.height > 0 &&
                            window.getComputedStyle(el).visibility !== 'hidden' &&
                            window.getComputedStyle(el).display !== 'none';
            inputs.push({
                id:          el.id || '',
                name:        el.name || el.id || '',
                type:        el.type || 'text',
                placeholder: el.placeholder || '',
                value:       el.value || '',
                visible:     visible,
                formId:      el.form ? (el.form.id || el.form.action || '') : '',
                formAction:  el.form ? el.form.action : '',
                formMethod:  el.form ? (el.form.method || 'get').toUpperCase() : 'GET',
            });
        }
        return inputs;
    }""")


def js_crawl(
    url: str,
    config: Dict,
    timeout: int = 20,
) -> List[Dict]:
    """Render *url* in Playwright, interact with the page, return injectable targets.

    Returns a list of dicts compatible with Scanner._scan_target:
        ``{url, method, params, param_name}``

    Each visible input becomes one target entry so every field gets
    individually scanned.

    Also returns intercepted XHR/Fetch request data so the scanner can
    test the actual API endpoints the app uses.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error(
            "[js-crawl] Playwright not installed. Run: pip install playwright && python -m playwright install chromium"
        )
        return []

    targets: List[Dict] = []
    intercepted_requests: List[Dict] = []
    visited_inputs: set = set()  # dedup by (name, formAction)

    cookies_str = config.get("cookies_raw", "")
    headers_extra = config.get("headers", {})
    proxy_url = config.get("proxy")

    playwright_kwargs = {}
    if proxy_url:
        playwright_kwargs["proxy"] = {"server": proxy_url}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, **playwright_kwargs)
        ctx_kwargs = {}
        if cookies_str:
            # Parse "k=v; k2=v2" into Playwright cookie format
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            ctx_kwargs["storage_state"] = {
                "cookies": [
                    {"name": k.strip(), "value": v.strip(),
                     "domain": domain, "path": "/"}
                    for pair in cookies_str.split(";")
                    if "=" in pair
                    for k, v in [pair.split("=", 1)]
                ]
            }
        if headers_extra:
            ctx_kwargs["extra_http_headers"] = headers_extra

        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()

        # ── Intercept XHR/Fetch requests ──────────────────────────────────
        def _on_request(req):
            if req.resource_type in ("xhr", "fetch"):
                try:
                    body = req.post_data or ""
                except Exception:
                    body = ""
                intercepted_requests.append({
                    "url": req.url,
                    "method": req.method,
                    "body": body,
                    "headers": dict(req.headers),
                })
        page.on("request", _on_request)

        try:
            page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        except PWTimeout:
            logger.debug("[js-crawl] networkidle timeout — proceeding with partial load")
        except Exception as exc:
            logger.warning("[js-crawl] Page load failed: %s", exc)
            browser.close()
            return []

        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        def _harvest(label: str) -> None:
            """Collect all currently visible inputs and add as targets."""
            inputs = _collect_inputs(page)
            for inp in inputs:
                if not inp["visible"]:
                    continue
                field_name = inp["name"] or inp["id"]
                if not field_name:
                    continue
                # Use the form's action URL, or fall back to current page URL
                form_url = inp["formAction"] or page.url
                if form_url.startswith("/") or not form_url.startswith("http"):
                    form_url = base_url + ("" if form_url.startswith("/") else "/") + form_url.lstrip("/")
                method = inp["formMethod"] if inp["formMethod"] in ("GET", "POST") else "GET"

                key = (field_name, form_url, method)
                if key in visited_inputs:
                    continue
                visited_inputs.add(key)

                # Build a minimal params dict for this field
                params = {field_name: inp["value"] or "test"}

                targets.append({
                    "url": form_url,
                    "method": method,
                    "params": params,
                    "param_name": field_name,
                    "_source": f"js-crawl:{label}",
                })
                logger.debug(
                    "[js-crawl] Found field %r (%s %s) via %s",
                    field_name, method, form_url, label,
                )

        # ── Initial harvest (fields visible without any interaction) ───────
        _harvest("initial")

        # ── Click reveal buttons and harvest again ─────────────────────────
        for selector in _REVEAL_SELECTORS:
            try:
                els = page.locator(selector).all()
            except Exception:
                continue
            for el in els[:3]:  # at most 3 per selector to avoid loops
                try:
                    if not el.is_visible():
                        continue
                    el.click(timeout=2000)
                    page.wait_for_timeout(_SETTLE_MS)
                    label = selector[:40]
                    _harvest(label)
                except Exception:
                    pass

        # ── Convert intercepted API requests into injectable targets ────────
        for req in intercepted_requests:
            req_url = req["url"]
            method = req["method"].upper()
            body = req["body"]
            if method not in ("GET", "POST"):
                continue
            # Try to parse body as form-encoded or JSON
            params: Dict[str, str] = {}
            if body:
                # JSON body
                try:
                    parsed_body = json.loads(body)
                    if isinstance(parsed_body, dict):
                        params = {k: str(v) for k, v in parsed_body.items() if isinstance(v, (str, int, float, bool))}
                except Exception:
                    pass
                # form-encoded
                if not params:
                    for pair in body.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            params[k] = v

            for param_name in params:
                key = (param_name, req_url, method)
                if key in visited_inputs:
                    continue
                visited_inputs.add(key)
                targets.append({
                    "url": req_url,
                    "method": method,
                    "params": params,
                    "param_name": param_name,
                    "_source": "js-crawl:xhr",
                })
                logger.debug(
                    "[js-crawl] XHR field %r (%s %s)",
                    param_name, method, req_url,
                )

        browser.close()

    logger.info(
        "[js-crawl] Done — %d injectable targets found (%d from XHR interception)",
        len(targets),
        sum(1 for t in targets if t.get("_source") == "js-crawl:xhr"),
    )
    return targets
