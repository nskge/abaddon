"""Unit tests for the Open Redirect detection module."""

import unittest
from unittest.mock import MagicMock

from scanner.modules.open_redirect import OpenRedirectScanner


def _make_response(text: str = "", status: int = 200, headers: dict = None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    return resp


class TestOpenRedirectLocationHeader(unittest.TestCase):

    def _scanner(self):
        client = MagicMock()
        client.follow_redirects = True
        return OpenRedirectScanner(client, {})

    def test_302_redirect_to_evil_detected(self):
        """HTTP 302 with Location pointing to canary domain triggers finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            status=302,
            headers={"Location": "https://evil.com/phished"},
        )

        findings = scanner.scan_parameter(
            url="http://target.local/redir",
            method="GET",
            params={"url": "http://safe.com"},
            param_name="url",
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].vuln_type, "Open Redirect")
        self.assertEqual(findings[0].confidence, "high")

    def test_301_redirect_to_evil_detected(self):
        """HTTP 301 also triggers detection."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            status=301,
            headers={"Location": "http://evil.com"},
        )

        findings = scanner.scan_parameter(
            url="http://target.local/redir",
            method="GET",
            params={"next": "/"},
            param_name="next",
        )

        self.assertGreater(len(findings), 0)

    def test_302_to_safe_domain_no_finding(self):
        """Redirect to the application's own domain does not trigger."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            status=302,
            headers={"Location": "http://target.local/dashboard"},
        )

        findings = scanner.scan_parameter(
            url="http://target.local/redir",
            method="GET",
            params={"url": "http://safe.com"},
            param_name="url",
        )

        self.assertEqual(findings, [])

    def test_200_no_redirect_no_finding(self):
        """Normal 200 page without redirect does not trigger."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            text="<html><body>Welcome</body></html>",
            status=200,
        )

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"ref": "/home"},
            param_name="ref",
        )

        self.assertEqual(findings, [])

    def test_none_response_handled(self):
        """None response does not raise."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"url": "/"},
            param_name="url",
        )

        self.assertEqual(findings, [])


class TestOpenRedirectMetaJS(unittest.TestCase):

    def _scanner(self):
        client = MagicMock()
        client.follow_redirects = True
        return OpenRedirectScanner(client, {})

    def test_js_redirect_detected(self):
        """JavaScript window.location redirect to canary triggers finding."""
        scanner = self._scanner()
        body = '<html><script>window.location = "https://evil.com/phish";</script></html>'
        scanner.http.get.return_value = _make_response(text=body, status=200)

        findings = scanner.scan_parameter(
            url="http://target.local/redir",
            method="GET",
            params={"url": "/"},
            param_name="url",
        )

        self.assertGreater(len(findings), 0)
        self.assertIn("JavaScript", findings[0].vuln_type)

    def test_post_method_supported(self):
        """Open redirect via POST is detected."""
        scanner = self._scanner()
        scanner.http.post.return_value = _make_response(
            status=302,
            headers={"Location": "https://evil.com"},
        )

        findings = scanner.scan_parameter(
            url="http://target.local/login",
            method="POST",
            params={"redirect_to": "/dashboard"},
            param_name="redirect_to",
        )

        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
