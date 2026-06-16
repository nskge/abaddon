"""Tests for weak-CSP detection and the CSP-aware XSS->session attack path."""

import unittest
from unittest.mock import MagicMock

from scanner.modules.headers import HeaderScanner
from scanner.modules.base import Finding
from scanner.correlate import correlate_findings


def _resp(headers):
    r = MagicMock()
    r.status_code = 200
    r.text = "<html>ok</html>"
    r.headers = headers
    return r


class TestWeakCSP(unittest.TestCase):
    def _reasons(self, csp):
        return HeaderScanner._weak_csp_reasons(csp)

    def test_unsafe_inline_is_weak(self):
        self.assertTrue(self._reasons("default-src 'self'; script-src 'self' 'unsafe-inline'"))

    def test_wildcard_script_src_is_weak(self):
        self.assertTrue(self._reasons("script-src *"))

    def test_strong_csp_is_not_weak(self):
        self.assertEqual(self._reasons("default-src 'self'; script-src 'self'"), [])

    def test_unsafe_eval_is_weak(self):
        self.assertTrue(any("eval" in r for r in self._reasons("script-src 'self' 'unsafe-eval'")))

    def test_scan_emits_weak_csp_finding(self):
        http = MagicMock()
        # baseline + active CORS probe both return the weak-CSP headers
        http.get.return_value = _resp({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
        mod = HeaderScanner(http, {})
        findings = mod.scan_parameter("http://t.local/", "GET", {}, "x")
        self.assertTrue(any(f.vuln_type == "Weak Content-Security-Policy" for f in findings))
        # and it must NOT also claim CSP is *missing*
        self.assertFalse(any("Missing Security Header: Content-Security-Policy" in f.vuln_type
                             for f in findings))


class TestCspAwareCorrelation(unittest.TestCase):
    def _xss(self):
        return Finding("Cross-Site Scripting (Reflected XSS)", "http://t.com/shop?q=1",
                       "GET", "q", "<script>", "reflected", "high")

    def test_no_session_chain_when_csp_strong(self):
        # XSS present but no missing/weak-CSP and no cookie finding -> we must NOT
        # fabricate a 'no CSP' session-hijack path.
        paths = correlate_findings([self._xss()])
        self.assertFalse(any("session hijack" in p.name.lower() for p in paths))

    def test_session_chain_when_csp_weak(self):
        weak = Finding("Weak Content-Security-Policy", "http://t.com/shop?q=1",
                       "GET", "(response headers)", "N/A", "script-src 'unsafe-inline'", "medium")
        paths = correlate_findings([self._xss(), weak])
        hijack = [p for p in paths if "session hijack" in p.name.lower()]
        self.assertTrue(hijack)
        # The narrative must reference the *weak* CSP, not claim it's absent.
        self.assertIn("weak", hijack[0].steps[1].lower())

    def test_session_chain_when_csp_missing(self):
        missing = Finding("Missing Security Header: Content-Security-Policy",
                          "http://t.com/shop?q=1", "GET", "(response headers)",
                          "N/A", "absent", "low")
        paths = correlate_findings([self._xss(), missing])
        self.assertTrue(any("session hijack" in p.name.lower() for p in paths))


if __name__ == "__main__":
    unittest.main()
