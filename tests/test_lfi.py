"""Unit tests for the LFI detection module.

All HTTP calls are mocked — no live network required.
Run with:  python -m pytest tests/ -v
"""

import base64
import unittest
from unittest.mock import MagicMock

from scanner.modules.lfi import LFIScanner


def _make_response(text: str, status: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


class TestLFIEtcPasswd(unittest.TestCase):
    """/etc/passwd content detection."""

    def _scanner(self):
        return LFIScanner(MagicMock(), {})

    def test_etc_passwd_content_detected(self):
        """Classic /etc/passwd content triggers a high-confidence finding."""
        body = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        )
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"file": "index.php"},
            param_name="file",
        )

        self.assertGreater(len(findings), 0)
        f = findings[0]
        self.assertIn("LFI", f.vuln_type)
        self.assertEqual(f.confidence, "high")
        self.assertEqual(f.parameter, "file")

    def test_generic_passwd_line_pattern(self):
        """A generic username:x:uid:gid: line is enough to confirm /etc/passwd."""
        body = "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"path": "home"},
            param_name="path",
        )

        self.assertGreater(len(findings), 0)

    def test_clean_response_no_finding(self):
        """Normal application responses do not produce LFI findings."""
        body = "<html><body><h1>Welcome to my app</h1></body></html>"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"file": "home"},
            param_name="file",
        )

        self.assertEqual(findings, [])

    def test_none_response_handled_gracefully(self):
        """Network errors (None response) do not raise exceptions."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"file": "x"},
            param_name="file",
        )

        self.assertEqual(findings, [])


class TestLFIWindowsWinIni(unittest.TestCase):
    """Windows win.ini detection."""

    def _scanner(self):
        return LFIScanner(MagicMock(), {})

    def test_win_ini_fonts_section_detected(self):
        """[fonts] section in response indicates windows/win.ini read."""
        body = "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"page": "home"},
            param_name="page",
        )

        self.assertGreater(len(findings), 0)
        self.assertIn("LFI", findings[0].vuln_type)

    def test_16bit_signature_detected(self):
        """'for 16-bit app support' line from win.ini triggers detection."""
        body = "; for 16-bit app support\n[fonts]\n[extensions]\n"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"page": "home"},
            param_name="page",
        )

        self.assertGreater(len(findings), 0)


class TestLFIPHPFilter(unittest.TestCase):
    """PHP filter wrapper base64 detection."""

    def _scanner(self):
        return LFIScanner(MagicMock(), {})

    def _b64_php(self, source: str) -> str:
        """Return base64-encoded *source* as it would appear in a PHP filter response."""
        return base64.b64encode(source.encode()).decode()

    def test_php_source_decoded_from_base64(self):
        """Base64-encoded PHP source in response is decoded and validated."""
        php_source = "<?php\n$conn = mysqli_connect('localhost','root','secret','db');\n?>"
        b64_blob = self._b64_php(php_source)

        # Simulate a PHP filter response: page content wraps the base64 blob
        body = f"<html><body>{b64_blob}</body></html>"

        scanner = self._scanner()
        # Always return the body containing the base64 blob.
        # Non-filter payloads won't match the /etc/passwd signatures, so only
        # the PHP filter decoder will produce a finding.
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"file": "index.php"},
            param_name="file",
        )

        php_findings = [f for f in findings if "PHP Filter" in f.vuln_type]
        self.assertGreater(len(php_findings), 0)
        self.assertEqual(php_findings[0].confidence, "high")
        self.assertIn("<?php", php_findings[0].evidence)

    def test_non_php_base64_ignored(self):
        """Large base64 blobs that do not decode to PHP source are ignored."""
        non_php = base64.b64encode(b"Just some binary data, not PHP!").decode()
        body = f"<html><body>{non_php}</body></html>"

        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        finding = LFIScanner._check_php_filter(
            body, "php://filter/convert.base64-encode/resource=x",
            "http://target.local/", "GET", "file",
        )

        self.assertIsNone(finding)


class TestLFIPostMethod(unittest.TestCase):
    """LFI detection via POST requests."""

    def test_lfi_detected_via_post(self):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n"
        scanner = LFIScanner(MagicMock(), {})
        scanner.http.post.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/download",
            method="POST",
            params={"filename": "report.pdf"},
            param_name="filename",
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].method, "POST")


class TestLFISnippetExtraction(unittest.TestCase):
    """Internal helper _snippet_around."""

    def test_snippet_returns_surrounding_text(self):
        body = "aaa bbb root:x:0:0:root:/root:/bin/bash ccc ddd"
        snippet = LFIScanner._snippet_around(body, r"root:x?:0:0:")
        self.assertIn("root:", snippet)
        self.assertIn("bin/bash", snippet)

    def test_snippet_returns_empty_on_no_match(self):
        snippet = LFIScanner._snippet_around("unrelated content", r"nomatch")
        self.assertEqual(snippet, "")


if __name__ == "__main__":
    unittest.main()
