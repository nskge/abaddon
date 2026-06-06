"""Unit tests for the CRLF Injection module."""

import unittest
from unittest.mock import MagicMock

from scanner.modules.crlf import CRLFScanner


def _make_response(text: str = "<html></html>", status: int = 200,
                   headers: dict = None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    return resp


class TestCRLFHeaderInjection(unittest.TestCase):
    """Detection of injected headers in response."""

    def _scanner(self):
        return CRLFScanner(MagicMock(), {})

    def test_injected_header_detected(self):
        """OkrInjected header in response triggers finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={"OkrInjected": "true", "Content-Type": "text/html"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("CRLF", findings[0].vuln_type)
        self.assertIn("Header Injection", findings[0].vuln_type)
        self.assertEqual(findings[0].confidence, "high")

    def test_clean_headers_no_finding(self):
        """No injected header = no finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={"Content-Type": "text/html"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 0)

    def test_case_insensitive_header_match(self):
        """Header name matching is case-insensitive."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={"okrinjected": "true"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)


class TestCRLFSetCookieInjection(unittest.TestCase):
    """Detection of injected Set-Cookie headers."""

    def _scanner(self):
        return CRLFScanner(MagicMock(), {})

    def test_set_cookie_injection_detected(self):
        """Injected Set-Cookie with marker value triggers finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "okrtest=injected; Path=/",
            },
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Set-Cookie", findings[0].vuln_type)

    def test_normal_cookie_no_finding(self):
        """Regular Set-Cookie header (no marker) produces no finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "session=abc123; HttpOnly",
            },
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 0)


class TestCRLFBodyInjection(unittest.TestCase):
    """Detection of response splitting (body injection)."""

    def _scanner(self):
        return CRLFScanner(MagicMock(), {})

    def test_body_marker_detected(self):
        """Injected body content triggers response splitting finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            text="<html><okrscann>injected</okrscann></html>",
            headers={"Content-Type": "text/html"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Response Splitting", findings[0].vuln_type)


class TestCRLFEdgeCases(unittest.TestCase):
    """Edge cases and error handling."""

    def _scanner(self):
        return CRLFScanner(MagicMock(), {})

    def test_none_response_handled(self):
        """None response (timeout) does not crash."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(findings, [])

    def test_post_method_supported(self):
        """CRLF detection works via POST."""
        scanner = self._scanner()
        scanner.http.post.return_value = _make_response(
            headers={"OkrInjected": "true"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "POST", {"name": "test"}, "name",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].method, "POST")

    def test_stops_after_first_finding(self):
        """Scanner returns after first confirmed CRLF finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            headers={"OkrInjected": "true"},
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        # Should only return 1 finding even though multiple payloads match
        self.assertEqual(len(findings), 1)

    def test_has_name(self):
        """Module NAME is set."""
        scanner = self._scanner()
        self.assertEqual(scanner.NAME, "crlf")


if __name__ == "__main__":
    unittest.main()
