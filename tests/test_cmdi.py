"""Unit tests for the Command Injection detection module."""

import unittest
from unittest.mock import MagicMock, patch

from scanner.modules.cmdi import CommandInjectionScanner

# Fixed token for deterministic tests
_FIXED_TOKEN = "okrscann_fixedtest1"


def _make_response(text: str = "", status: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


def _scanner():
    return CommandInjectionScanner(MagicMock(), {"delay_threshold": 3.0})


class TestCMDiOutputBased(unittest.TestCase):

    def test_echo_token_reflected_as_execution(self):
        """Echo token appears in response WITHOUT the 'echo TOKEN' prefix → real execution."""
        with patch("scanner.modules.cmdi._make_echo_token", return_value=_FIXED_TOKEN):
            scanner = _scanner()
            call_count = [0]

            def get_side(url):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call = baseline check with just token appended
                    # Baseline should be CLEAN — no token present
                    return _make_response("clean page without token")
                # Subsequent calls = real payloads; token appears as bare output (NOT 'echo TOKEN')
                return _make_response(f"Command output:\n{_FIXED_TOKEN}\nEnd")

            scanner.http.get.side_effect = get_side

            findings = scanner.scan_parameter(
                url="http://target.local/ping",
                method="GET",
                params={"host": "127.0.0.1"},
                param_name="host",
            )

        self.assertGreater(len(findings), 0)
        self.assertIn("Command Injection", findings[0].vuln_type)
        self.assertEqual(findings[0].confidence, "high")
        self.assertIn(_FIXED_TOKEN, findings[0].evidence)

    def test_search_term_reflection_not_flagged(self):
        """If the FULL payload including 'echo TOKEN' appears verbatim, it's search-term
        reflection (not command execution) — no finding should be raised."""
        with patch("scanner.modules.cmdi._make_echo_token", return_value=_FIXED_TOKEN):
            scanner = _scanner()

            def get_side(url):
                # Return the full echo string as if it was reflected as a search term
                return _make_response(
                    f"Sorry, no results match echo {_FIXED_TOKEN}"
                )

            scanner.http.get.side_effect = get_side

            findings = scanner.scan_parameter(
                url="http://search.example.com/search",
                method="GET",
                params={"q": "test"},
                param_name="q",
            )

        # The full "echo TOKEN" string appeared — should NOT be flagged as execution
        cmdi_findings = [f for f in findings if "OS Command" in f.vuln_type]
        self.assertEqual(len(cmdi_findings), 0, "Search-term reflection must NOT be flagged as CMDi")

    def test_reflects_input_param_skipped(self):
        """If the bare token appears in the BASELINE (param reflects everything), skip echo checks."""
        with patch("scanner.modules.cmdi._make_echo_token", return_value=_FIXED_TOKEN):
            scanner = _scanner()

            # ALL responses contain the token — including the baseline check
            # This simulates a param that reflects everything back
            scanner.http.get.return_value = _make_response(
                f"Search results for: {_FIXED_TOKEN}"
            )

            findings = scanner.scan_parameter(
                url="http://search.example.com/search",
                method="GET",
                params={"q": "test"},
                param_name="q",
            )

        cmdi_findings = [f for f in findings if "OS Command" in f.vuln_type]
        self.assertEqual(len(cmdi_findings), 0, "Params that reflect all input must not trigger CMDi")

    def test_etc_passwd_in_response(self):
        """/etc/passwd content triggers command injection finding regardless of token logic."""
        scanner = _scanner()
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n"
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "127.0.0.1"},
            param_name="host",
        )

        self.assertGreater(len(findings), 0)
        self.assertIn("Command Injection", findings[0].vuln_type)

    def test_clean_response_no_finding(self):
        """Normal response does not trigger."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response("<html>Normal page</html>")

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "127.0.0.1"},
            param_name="host",
        )

        self.assertEqual(findings, [])

    def test_none_response_handled(self):
        """None response (timeout) does not raise."""
        scanner = _scanner()
        scanner.http.get.return_value = None

        findings = scanner.scan_parameter(
            url="http://target.local/ping",
            method="GET",
            params={"host": "x"},
            param_name="host",
        )

        self.assertEqual(findings, [])

    def test_post_method(self):
        """CMDi echo detection works with POST (token appears without 'echo' prefix)."""
        with patch("scanner.modules.cmdi._make_echo_token", return_value=_FIXED_TOKEN):
            scanner = _scanner()
            call_count = [0]

            def post_side(url, data=None):
                call_count[0] += 1
                if call_count[0] == 1:
                    return _make_response("baseline clean page")
                return _make_response(f"Output: {_FIXED_TOKEN}")

            scanner.http.post.side_effect = post_side

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
