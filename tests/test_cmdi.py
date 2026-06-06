"""Unit tests for the Command Injection detection module."""

import unittest
from unittest.mock import MagicMock, patch

from scanner.modules.cmdi import CommandInjectionScanner, _ECHO_TOKEN


def _make_response(text: str = "", status: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


class TestCMDiOutputBased(unittest.TestCase):

    def _scanner(self):
        return CommandInjectionScanner(MagicMock(), {"delay_threshold": 3.0})

    def test_echo_token_reflected(self):
        """Echo token in response body triggers high-confidence finding."""
        body = f"Result: {_ECHO_TOKEN}\n"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "127.0.0.1"},
            param_name="host",
        )

        self.assertGreater(len(findings), 0)
        self.assertIn("Command Injection", findings[0].vuln_type)
        self.assertEqual(findings[0].confidence, "high")

    def test_etc_passwd_in_response(self):
        """/etc/passwd content triggers command injection finding."""
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n"
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "127.0.0.1"},
            param_name="host",
        )

        self.assertGreater(len(findings), 0)

    def test_clean_response_no_finding(self):
        """Normal response does not trigger."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("<html>Normal page</html>")

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "127.0.0.1"},
            param_name="host",
        )

        self.assertEqual(findings, [])

    def test_none_response_handled(self):
        """None response does not raise."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "x"},
            param_name="host",
        )

        self.assertEqual(findings, [])

    def test_post_method(self):
        """CMDi detection works with POST."""
        body = f"Output: {_ECHO_TOKEN}"
        scanner = self._scanner()
        scanner.http.post.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/exec",
            method="POST",
            params={"cmd": "ls"},
            param_name="cmd",
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].method, "POST")


class TestCMDiTimeBased(unittest.TestCase):

    def _scanner(self):
        return CommandInjectionScanner(MagicMock(), {"delay_threshold": 2.0})

    def test_sleep_delay_detected(self):
        """Simulated delay triggers time-based finding."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Normal")

        times = iter([0.0, 0.1,   # baseline
                      0.0, 3.5])  # first payload

        with patch("scanner.modules.cmdi.time.perf_counter", side_effect=times):
            finding = scanner._test_time_based(
                url="http://target.local/ping",
                method="GET",
                params={"host": "127.0.0.1"},
                param_name="host",
            )

        self.assertIsNotNone(finding)
        self.assertIn("Command Injection", finding.vuln_type)
        self.assertIn("3.50", finding.evidence)

    def test_fast_response_no_finding(self):
        """Fast responses do not trigger."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Fast")

        with patch("scanner.modules.cmdi.time.perf_counter", side_effect=iter([0.0, 0.05] * 30)):
            finding = scanner._test_time_based(
                url="http://target.local/ping",
                method="GET",
                params={"host": "x"},
                param_name="host",
            )

        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
