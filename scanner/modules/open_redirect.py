"""Open Redirect detection module.

Detection strategy:
  1. Inject external URLs (e.g. https://evil.com) into parameters commonly used
     for redirects (url, redirect, next, return, goto, dest, redir, etc.).
  2. Check if the response is a 3xx redirect whose Location header points to the
     injected domain.
  3. Also check for meta-refresh and javascript-based redirects in the response body.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import logging

from .base import BaseModule, Finding
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# Canary domains -- must not match any real application domain
_CANARY_DOMAIN = "evil.com"

_REDIRECT_PAYLOADS = [
    f"https://{_CANARY_DOMAIN}",
    f"http://{_CANARY_DOMAIN}",
    f"//{_CANARY_DOMAIN}",
    f"https://{_CANARY_DOMAIN}/%2f..",
    f"/////{_CANARY_DOMAIN}",
    f"https://{_CANARY_DOMAIN}@legitimate.com",
    f"https://legitimate.com@{_CANARY_DOMAIN}",
    f"/{_CANARY_DOMAIN}",
    f"https:{_CANARY_DOMAIN}",
    f"/\\/{_CANARY_DOMAIN}",
    f"htTps://{_CANARY_DOMAIN}",
    f"https://{_CANARY_DOMAIN}#",
    f"https://{_CANARY_DOMAIN}?",
    f"https://{_CANARY_DOMAIN}\\",
]


class OpenRedirectScanner(BaseModule):
    """Detects open redirect vulnerabilities via redirect-chain analysis."""

    NAME = "redirect"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self.custom_payloads: Optional[str] = config.get("custom_payloads")
        # Disable redirect following so we can inspect the Location header
        self._orig_follow = self.http.follow_redirects
        self.http.follow_redirects = False

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Test *param_name* for open redirect."""
        payloads = self.load_payloads(_REDIRECT_PAYLOADS, self.custom_payloads)

        for payload in payloads:
            injected = inject_into_params(params, param_name, payload)

            if method == "GET":
                resp = self.http.get(rebuild_url_with_params(url, injected))
            else:
                resp = self.http.post(url, data=injected)

            if resp is None:
                continue

            finding = self._check_redirect(resp, url, method, params, param_name, payload)
            if finding:
                # Restore original follow-redirects setting
                self.http.follow_redirects = self._orig_follow
                return [finding]

        self.http.follow_redirects = self._orig_follow
        return []

    def _check_redirect(self, resp, url, method, params, param_name, payload) -> Optional[Finding]:
        """Validate if the response redirects to our canary domain."""
        # Check Location header on 3xx
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "")
            if self._points_to_canary(location):
                logger.debug(
                    "[Redirect] %s=%r -> Location: %s (HTTP %d)",
                    param_name, payload, location, resp.status_code,
                )
                curl = build_curl_command(url, method, params, param_name, payload)
                return Finding(
                    vuln_type="Open Redirect",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"HTTP {resp.status_code} redirect to external domain: "
                        f"Location: {location}"
                    ),
                    confidence="high",
                    details=(
                        f"Server responds with HTTP {resp.status_code} and redirects to "
                        f"attacker-controlled domain ({_CANARY_DOMAIN}). "
                        "Remediation: validate redirect targets against an allow-list "
                        "of trusted domains; use relative paths only."
                    ),
                    reproduction=(
                        f"# 1. Send the redirect payload and check the Location header:\n"
                        f"{curl.replace('curl -s', 'curl -s -D -')} -o /dev/null | head -20\n"
                        f"# 2. Look for 'Location:' header pointing to {_CANARY_DOMAIN}.\n"
                        f"#    If present, the server redirects to an attacker-controlled domain.\n"
                        f"# 3. In a browser: paste the full URL and observe the redirect.\n"
                        f"# 4. Replace '{_CANARY_DOMAIN}' with your own domain for PoC."
                    ),
                )

        # Check meta-refresh / JS redirect in body
        body = resp.text.lower()
        meta_pattern = r'<meta[^>]*http-equiv=["\']?refresh[^>]*content=["\']?\d+;\s*url=' + re.escape(_CANARY_DOMAIN.lower())
        js_patterns = [
            r'window\.location\s*=\s*["\'][^"\']*' + re.escape(_CANARY_DOMAIN.lower()),
            r'location\.href\s*=\s*["\'][^"\']*' + re.escape(_CANARY_DOMAIN.lower()),
            r'location\.replace\s*\(\s*["\'][^"\']*' + re.escape(_CANARY_DOMAIN.lower()),
        ]

        if re.search(meta_pattern, body, re.IGNORECASE):
            curl = build_curl_command(url, method, params, param_name, payload)
            return Finding(
                vuln_type="Open Redirect (Meta Refresh)",
                url=url,
                method=method,
                parameter=param_name,
                payload=payload,
                evidence=f"Meta-refresh redirect to {_CANARY_DOMAIN} found in response body",
                confidence="high",
                details="Remediation: validate redirect targets against an allow-list.",
                reproduction=(
                    f"# 1. Send the payload and inspect the HTML body:\n"
                    f"{curl}\n"
                    f"# 2. Search for '<meta http-equiv=\"refresh\"' pointing to {_CANARY_DOMAIN}.\n"
                    f"#    If present, the server embeds a client-side redirect to an external domain.\n"
                    f"# 3. Open the URL in a browser to see the redirect happen."
                ),
            )

        for pat in js_patterns:
            if re.search(pat, body, re.IGNORECASE):
                curl = build_curl_command(url, method, params, param_name, payload)
                return Finding(
                    vuln_type="Open Redirect (JavaScript)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"JavaScript redirect to {_CANARY_DOMAIN} found in response body",
                    confidence="medium",
                    details="Remediation: validate redirect targets against an allow-list.",
                    reproduction=(
                        f"# 1. Send the payload and check response body for JS redirect:\n"
                        f"{curl}\n"
                        f"# 2. Search for 'window.location' or 'location.href' pointing\n"
                        f"#    to {_CANARY_DOMAIN} in the response.\n"
                        f"# 3. Open the URL in a browser with JS enabled to confirm redirect."
                    ),
                )

        return None

    @staticmethod
    def _points_to_canary(location: str) -> bool:
        """Check whether *location* resolves to the canary domain."""
        if not location:
            return False
        loc_lower = location.lower()
        if _CANARY_DOMAIN in loc_lower:
            return True
        try:
            parsed = urlparse(location)
            if parsed.hostname and _CANARY_DOMAIN in parsed.hostname:
                return True
        except Exception:
            pass
        return False
