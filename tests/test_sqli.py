"""Unit tests for the SQL Injection detection module.

All HTTP calls are mocked — no live network required.
Run with:  python -m pytest tests/ -v
"""

import time
import unittest
from unittest.mock import MagicMock, patch
from typing import Dict

from scanner.modules.sqli import SQLiScanner


def _make_response(text: str, status: int = 200):
    """Create a minimal mock response object."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


class TestSQLiErrorBased(unittest.TestCase):
    """Error-based SQLi detection — both append-mode and replace-mode."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 5.0})

    def test_mysql_error_on_numeric_param(self):
        """Append-mode: id=1' triggers MySQL syntax error (most common case)."""
        body = "Warning: mysql_fetch_array() expects parameter 1 to be resource"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/cat.php",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.vuln_type, "SQL Injection (Error-based)")
        self.assertEqual(f.confidence, "high")
        # Payload should show 1' (original value + appended quote)
        self.assertIn("1'", f.payload)

    def test_mysql_syntax_error_in_response(self):
        """'you have an error in your sql syntax' triggers MySQL detection."""
        body = "You have an error in your SQL syntax; check the manual"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 1)
        self.assertIn("MySQL", findings[0].evidence)

    def test_mssql_error_detected(self):
        """MSSQL 'incorrect syntax near' triggers error-based detection."""
        body = "Incorrect syntax near the keyword 'OR'."
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 1)
        self.assertIn("MSSQL", findings[0].evidence)

    def test_oracle_error_detected(self):
        """ORA-xxxxx error pattern triggers Oracle detection."""
        body = "ORA-01756: quoted string not properly terminated"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 1)
        self.assertIn("Oracle", findings[0].evidence)

    def test_clean_response_no_finding(self):
        """A normal HTML page does not produce findings."""
        body = "<html><body><p>Welcome!</p></body></html>"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 0)

    def test_none_response_skipped(self):
        """None (timeout/network error) is handled gracefully."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 0)

    def test_post_method(self):
        """Error-based detection works with POST requests."""
        body = "You have an error in your SQL syntax near 'OR'"
        scanner = self._scanner()
        scanner.http.post.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/login",
            method="POST",
            params={"username": "admin", "password": "test"},
            param_name="username",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].method, "POST")


class TestSQLiBooleanBased(unittest.TestCase):
    """Boolean-based blind SQLi — both AND (numeric) and OR (string) patterns."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 5.0})

    def test_and_injection_numeric_param(self):
        """AND-mode: id=1 AND 1=1 matches baseline; id=1 AND 1=2 returns empty page."""
        # Baseline: 500 bytes
        baseline = _make_response("A" * 500)
        # TRUE (1 AND 1=1): same as baseline ≈ 500 bytes
        true_resp = _make_response("A" * 498)
        # FALSE (1 AND 1=2): empty / much smaller
        false_resp = _make_response("A" * 80)

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None  # skip error phase

        # baseline + all AND pairs true/false
        scanner.http.get.side_effect = [baseline] + [true_resp, false_resp] * 10

        finding = scanner._test_boolean_based(
            url="http://target.local/cat.php",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding.vuln_type, "SQL Injection (Boolean-based Blind)")
        self.assertIn("AND", finding.evidence)

    def test_identical_responses_no_finding(self):
        """When all responses are identical no false positive is raised."""
        page = _make_response("Same content " * 30)

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None
        scanner.http.get.return_value = page

        finding = scanner._test_boolean_based(
            url="http://target.local/page",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertIsNone(finding)

    def test_status_code_difference_detected(self):
        """Different HTTP status codes between TRUE/FALSE conditions signal blind SQLi."""
        baseline = _make_response("Page content", 200)
        true_resp  = _make_response("Page content", 200)
        false_resp = _make_response("Page content", 500)

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None
        scanner.http.get.side_effect = [baseline] + [true_resp, false_resp] * 10

        finding = scanner._test_boolean_based(
            url="http://target.local/page",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertIsNotNone(finding)


class TestSQLiTimeBased(unittest.TestCase):
    """Time-based blind SQLi detection."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 2.0})

    def test_time_delay_detected(self):
        """Simulated 3-second response triggers time-based detection."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Normal page")

        # Patch perf_counter: baseline=0.1s, first payload=3.5s
        times = iter([0.0, 0.1,   # baseline start/end
                      0.0, 3.5])  # payload start/end

        with patch("scanner.modules.sqli.time.perf_counter", side_effect=times):
            finding = scanner._test_time_based(
                url="http://target.local/page",
                method="GET",
                params={"id": "1"},
                param_name="id",
            )

        self.assertIsNotNone(finding)
        self.assertEqual(finding.vuln_type, "SQL Injection (Time-based Blind)")
        self.assertIn("3.50", finding.evidence)

    def test_fast_response_no_finding(self):
        """Fast responses (< threshold) do not trigger time-based detection."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Fast response")

        with patch("scanner.modules.sqli.time.perf_counter", side_effect=iter([0.0, 0.05] * 30)):
            finding = scanner._test_time_based(
                url="http://target.local/page",
                method="GET",
                params={"id": "1"},
                param_name="id",
            )

        self.assertIsNone(finding)

    def test_append_mode_payload_shows_original_value(self):
        """Time-based append-mode payload displays the full injected value."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Normal")

        times = iter([0.0, 0.05,  # baseline
                      0.0, 3.0])  # first append payload triggers

        with patch("scanner.modules.sqli.time.perf_counter", side_effect=times):
            finding = scanner._test_time_based(
                url="http://target.local/page",
                method="GET",
                params={"id": "1"},
                param_name="id",
            )

        self.assertIsNotNone(finding)
        # Payload should contain the original value prefix
        self.assertIn("1", finding.payload)


class TestSQLiInjectHelpers(unittest.TestCase):
    """Unit tests for _append and _replace injection helpers."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {})

    def test_append_adds_suffix_to_value(self):
        scanner = self._scanner()
        result = scanner._append({"id": "1", "cat": "2"}, "id", "'")
        self.assertEqual(result["id"], "1'")
        self.assertEqual(result["cat"], "2")   # unchanged

    def test_replace_overwrites_value(self):
        scanner = self._scanner()
        result = scanner._replace({"id": "1"}, "id", "' OR '1'='1")
        self.assertEqual(result["id"], "' OR '1'='1")

    def test_append_does_not_mutate_original(self):
        scanner = self._scanner()
        original = {"id": "1"}
        scanner._append(original, "id", "'")
        self.assertEqual(original["id"], "1")  # original unchanged


class TestSQLiPayloadLoading(unittest.TestCase):
    """Custom payload file loading."""

    def test_custom_payload_file_used(self):
        import tempfile, os
        payloads = "custom_payload_1\ncustom_payload_2\n# comment\n\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write(payloads)
            path = tf.name
        try:
            scanner = SQLiScanner(MagicMock(), {"delay_threshold": 5.0})
            loaded = scanner.load_payloads(["default"], path)
            self.assertIn("custom_payload_1", loaded)
            self.assertIn("custom_payload_2", loaded)
            self.assertNotIn("# comment", loaded)
        finally:
            os.unlink(path)

    def test_missing_payload_file_falls_back(self):
        scanner = SQLiScanner(MagicMock(), {})
        defaults = ["default_payload"]
        result = scanner.load_payloads(defaults, "/nonexistent/path.txt")
        self.assertEqual(result, defaults)


if __name__ == "__main__":
    unittest.main()
