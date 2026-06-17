"""Unit tests for attack-path correlation (BloodHound-style chaining)."""

import unittest

from scanner.modules.base import Finding
from scanner.correlate import correlate_findings


def _f(vuln_type, url="http://t.com/p?id=1", param="id", evidence="", confidence="high", details=""):
    return Finding(
        vuln_type=vuln_type,
        url=url,
        method="GET",
        parameter=param,
        payload="x",
        evidence=evidence,
        confidence=confidence,
        details=details,
    )


class TestCorrelate(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(correlate_findings([]), [])

    def test_single_finding_no_path(self):
        paths = correlate_findings([_f("SQL Injection (Error-based)")])
        self.assertEqual(paths, [])

    def test_sqli_plus_jwt_is_account_takeover(self):
        findings = [
            _f("SQL Injection (Error-based)"),
            _f("Weak HMAC Secret (JWT)", param="token"),
        ]
        paths = correlate_findings(findings)
        self.assertTrue(any("Account Takeover" in p.name for p in paths))
        atos = [p for p in paths if "Account Takeover" in p.name]
        self.assertEqual(atos[0].severity, "critical")

    def test_ssrf_plus_metadata_is_cloud_theft(self):
        findings = [
            _f("SSRF (Server-Side Request Forgery)", param="url",
               evidence="reached 169.254.169.254 ami-id instance-id"),
        ]
        # SSRF alone with metadata evidence is enough for the cloud chain
        paths = correlate_findings(findings)
        self.assertTrue(any("cloud credential" in p.name.lower() for p in paths))

    def test_ssrf_without_metadata_no_cloud_path(self):
        findings = [_f("SSRF (Server-Side Request Forgery)", param="url",
                       evidence="connection refused")]
        paths = correlate_findings(findings)
        self.assertFalse(any("cloud credential" in p.name.lower() for p in paths))

    def test_xss_plus_header_is_session_hijack(self):
        findings = [
            _f("Cross-Site Scripting (Reflected XSS)", param="q"),
            _f("Missing Security Header", param="(headers)",
               evidence="Set-Cookie without HttpOnly"),
        ]
        paths = correlate_findings(findings)
        self.assertTrue(any("session hijack" in p.name.lower() for p in paths))

    def test_missing_xss_protection_header_not_treated_as_xss(self):
        """Regression: 'Missing Security Header: X-XSS-Protection' must NOT be
        chained into a reflected-XSS session-hijack path (the 'xss' substring
        in 'X-XSS-Protection' previously caused a false positive)."""
        findings = [
            _f("Missing Security Header: X-XSS-Protection", param="(response headers)",
               confidence="low", evidence="Header 'X-XSS-Protection' is absent"),
            _f("Missing Security Header: Content-Security-Policy",
               param="(response headers)", confidence="low",
               evidence="No Content-Security-Policy"),
        ]
        paths = correlate_findings(findings)
        self.assertFalse(
            any("session hijack" in p.name.lower() for p in paths),
            "A missing X-XSS-Protection header must not fabricate an XSS chain",
        )

    def test_low_confidence_dom_xss_not_chained(self):
        """A low-confidence potential DOM-XSS hint must not assert a hijack chain."""
        findings = [
            _f("DOM XSS (Potential — static taint)", param="(client-side JS)",
               confidence="low"),
            _f("Missing Security Header: Content-Security-Policy",
               param="(response headers)", confidence="low"),
        ]
        paths = correlate_findings(findings)
        self.assertFalse(any("session hijack" in p.name.lower() for p in paths))

    def test_lfi_plus_log_is_rce(self):
        findings = [
            _f("Local File Inclusion (LFI)", param="file",
               evidence="root:x:0:0", details="read /var/log/apache2/access.log"),
        ]
        paths = correlate_findings(findings)
        self.assertTrue(any("rce" in p.name.lower() for p in paths))

    def test_paths_sorted_by_severity(self):
        findings = [
            _f("Cross-Site Scripting (Reflected XSS)", param="q"),
            _f("Missing Security Header", evidence="no HttpOnly"),
            _f("SQL Injection (Error-based)"),
            _f("Weak HMAC Secret (JWT)", param="token"),
        ]
        paths = correlate_findings(findings)
        self.assertGreaterEqual(len(paths), 2)
        ranks = ["critical", "high", "medium"]
        idxs = [ranks.index(p.severity) for p in paths]
        self.assertEqual(idxs, sorted(idxs), "paths must be ordered most-severe first")

    def test_different_hosts_not_chained(self):
        findings = [
            _f("SQL Injection (Error-based)", url="http://a.com/p?id=1"),
            _f("Weak HMAC Secret (JWT)", url="http://b.com/p?token=x", param="token"),
        ]
        paths = correlate_findings(findings)
        self.assertFalse(any("Account Takeover" in p.name for p in paths))

    def test_to_dict_shape(self):
        findings = [
            _f("SQL Injection (Error-based)"),
            _f("Weak HMAC Secret (JWT)", param="token"),
        ]
        d = correlate_findings(findings)[0].to_dict()
        for key in ("name", "severity", "host", "steps", "narrative", "recommendation"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
