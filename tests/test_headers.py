"""Unit tests for the Header Security analysis module."""

import unittest
from unittest.mock import MagicMock

from scanner.modules.headers import HeaderScanner


def _make_response(text: str = "<html></html>", status: int = 200, headers: dict = None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    return resp


class TestMissingHeaders(unittest.TestCase):
    """Detection of missing security headers."""

    def _scanner(self):
        return HeaderScanner(MagicMock(), {})

    def test_missing_xframe_detected(self):
        """Missing X-Frame-Options is flagged."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "Content-Type": "text/html",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        types = [f.vuln_type for f in findings]
        self.assertTrue(any("X-Frame-Options" in t for t in types))

    def test_missing_csp_detected(self):
        """Missing Content-Security-Policy is flagged."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={})

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        types = [f.vuln_type for f in findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in types))

    def test_all_headers_present_no_finding(self):
        """When all security headers are set, no missing-header findings."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
            # HSTS not required for HTTP
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        missing = [f for f in findings if "Missing" in f.vuln_type]
        self.assertEqual(len(missing), 0)

    def test_hsts_not_flagged_on_http(self):
        """HSTS is not flagged for plain HTTP URLs."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={})

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        types = [f.vuln_type for f in findings]
        self.assertFalse(any("Strict-Transport-Security" in t for t in types))

    def test_hsts_flagged_on_https(self):
        """HSTS IS flagged for HTTPS URLs."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={})

        findings = scanner.scan_parameter("https://t.local/", "GET", {"x": "1"}, "x")
        types = [f.vuln_type for f in findings]
        self.assertTrue(any("Strict-Transport-Security" in t for t in types))

    def test_scans_only_once(self):
        """Header scan runs only on the first call."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={})

        f1 = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        f2 = scanner.scan_parameter("http://t.local/", "GET", {"y": "2"}, "y")

        self.assertGreater(len(f1), 0)
        self.assertEqual(len(f2), 0)


class TestInfoDisclosure(unittest.TestCase):
    """Server version and technology disclosure."""

    def _scanner(self):
        return HeaderScanner(MagicMock(), {})

    def test_apache_version_detected(self):
        """Apache/X.Y.Z in Server header triggers info disclosure."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "Server": "Apache/2.4.51 (Unix)",
            # Add enough to suppress missing-header noise
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        info = [f for f in findings if "Information Disclosure" in f.vuln_type]
        self.assertGreater(len(info), 0)
        self.assertIn("Apache", info[0].evidence)

    def test_xpoweredby_detected(self):
        """X-Powered-By header triggers technology disclosure."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "X-Powered-By": "PHP/7.4.3",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        info = [f for f in findings if "Information Disclosure" in f.vuln_type]
        self.assertGreater(len(info), 0)

    def test_no_info_disclosure_clean_headers(self):
        """No Server/X-Powered-By = no info disclosure findings."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        info = [f for f in findings if "Information Disclosure" in f.vuln_type]
        self.assertEqual(len(info), 0)


class TestCORS(unittest.TestCase):
    """CORS misconfiguration detection."""

    def _scanner(self):
        return HeaderScanner(MagicMock(), {})

    def test_wildcard_cors_detected(self):
        """Access-Control-Allow-Origin: * is flagged."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "Access-Control-Allow-Origin": "*",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        cors = [f for f in findings if "CORS" in f.vuln_type]
        self.assertGreater(len(cors), 0)

    def test_wildcard_cors_with_credentials_high_confidence(self):
        """Wildcard CORS + credentials=true is HIGH confidence."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        cors = [f for f in findings if "CORS" in f.vuln_type]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0].confidence, "high")

    def test_no_cors_header_no_finding(self):
        """No ACAO header = no CORS finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        })

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        cors = [f for f in findings if "CORS" in f.vuln_type]
        self.assertEqual(len(cors), 0)

    def test_none_response_handled(self):
        """None response does not raise."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter("http://t.local/", "GET", {"x": "1"}, "x")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
