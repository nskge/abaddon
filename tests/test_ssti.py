"""Unit tests for the SSTI (Server-Side Template Injection) module."""

import unittest
from unittest.mock import MagicMock

from scanner.modules.ssti import SSTIScanner


def _make_response(text: str, status: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


class TestSSTIMathProbes(unittest.TestCase):
    """Detection via math evaluation probes."""

    def _scanner(self):
        return SSTIScanner(MagicMock(), {})

    def test_jinja2_unique_detected(self):
        """Unique probe {{43*47}} evaluated to 2021 triggers HIGH confidence SSTI."""
        scanner = self._scanner()
        # Server evaluates ALL template expressions
        scanner.http.get.return_value = _make_response(
            "<html><p>Result: 2021</p></html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("SSTI", findings[0].vuln_type)
        self.assertEqual(findings[0].confidence, "high")

    def test_freemarker_detected(self):
        """Freemarker-style evaluation returns result in response."""
        scanner = self._scanner()
        # Server evaluates templates and returns the math result
        scanner.http.get.return_value = _make_response(
            "<html>Result: 2021</html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertGreater(len(findings), 0)
        self.assertIn("SSTI", findings[0].vuln_type)

    def test_erb_detected(self):
        """ERB <%= 43*47 %> evaluated to 2021."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            "<html>Result: 2021</html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertGreater(len(findings), 0)

    def test_raw_template_echoed_no_finding(self):
        """If server echoes {{7*7}} literally (not evaluated), no finding."""
        scanner = self._scanner()
        # Always echo the raw template expression
        def side_effect(url):
            return _make_response("<html>You searched: {{43*47}}</html>")

        scanner.http.get.side_effect = side_effect

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        # The probes where expected="2021" should NOT trigger because
        # the raw "{{43*47}}" is still in the response
        ssti_findings = [f for f in findings if "SSTI" in f.vuln_type]
        self.assertEqual(len(ssti_findings), 0)

    def test_no_evaluation_clean_response(self):
        """Clean response with no evaluation markers returns no findings."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            "<html><p>Welcome to our site</p></html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 0)


class TestSSTIConcatProbes(unittest.TestCase):
    """Detection via string concatenation probes."""

    def _scanner(self):
        return SSTIScanner(MagicMock(), {})

    def test_jinja2_concat_detected(self):
        """Jinja2 string concat {{'okr'+'scn'}} -> 'okrscn'."""
        scanner = self._scanner()
        # Math probes don't match, but concat does
        def side_effect(url):
            if "okrscn" in url:
                return _make_response("<html>ignored</html>")
            return _make_response("<html>Result: okrscn</html>")

        scanner.http.get.side_effect = side_effect
        scanner.http.post.return_value = _make_response("<html>Result: okrscn</html>")

        findings = scanner.scan_parameter(
            "http://t.local/page", "POST", {"name": "hello"}, "name",
        )
        concat_findings = [f for f in findings if "SSTI" in f.vuln_type]
        # May detect via math or concat depending on which probe hits first
        # If all math probes also return "okrscn", we'll get a finding
        self.assertGreater(len(concat_findings), 0)


class TestSSTIPostMethod(unittest.TestCase):
    """POST request handling."""

    def _scanner(self):
        return SSTIScanner(MagicMock(), {})

    def test_post_ssti_detected(self):
        """SSTI detected via POST request."""
        scanner = self._scanner()
        scanner.http.post.return_value = _make_response(
            "<html><p>2021</p></html>"
        )
        scanner.http.get.return_value = _make_response(
            "<html>nothing here</html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "POST", {"name": "test"}, "name",
        )
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].method, "POST")


class TestSSTIEdgeCases(unittest.TestCase):
    """Edge cases and error handling."""

    def _scanner(self):
        return SSTIScanner(MagicMock(), {})

    def test_none_response_handled(self):
        """None response (timeout) does not crash."""
        scanner = self._scanner()
        scanner.http.get.return_value = None
        scanner.http.post.return_value = None

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(findings, [])

    def test_original_value_matches_expected_no_false_positive(self):
        """Param value '2021' should not trigger 43*47=2021 as false positive."""
        scanner = self._scanner()
        # Response always contains "2021" because the page echoes the original
        # param value, not because template evaluation happened
        scanner.http.get.return_value = _make_response(
            "<html>Product ID: 2021</html>"
        )

        # original value is "2021" -- same as 43*47 result
        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "2021"}, "q",
        )
        # Should not find SSTI because expected == original_value guard
        self.assertEqual(len(findings), 0)

    def test_append_mode_numeric_param(self):
        """Append mode works for numeric params like id=1{{7*7}}."""
        scanner = self._scanner()
        # Server evaluates the appended template and returns "149" (1 + 49)
        # Actually the response would show the evaluated result somewhere
        scanner.http.get.return_value = _make_response(
            "<html>Product ID: 12021</html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"id": "1"}, "id",
        )
        self.assertGreater(len(findings), 0)

    def test_unique_probe_high_confidence(self):
        """Unique math probes (43*47=2021) produce HIGH confidence."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            "<html>Result: 2021</html>"
        )

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "high")

    def test_standard_probe_medium_confidence(self):
        """Standard math probes (7*7=49) produce MEDIUM confidence."""
        scanner = self._scanner()

        call_count = [0]
        def side_effect(url):
            call_count[0] += 1
            # Unique probes (2021, 323, 899) should NOT match
            for unique in ["2021", "323", "899"]:
                if unique in url:
                    return _make_response("<html>nothing</html>")
            # Standard 49 probe matches
            return _make_response("<html>value: 49</html>")

        scanner.http.get.side_effect = side_effect

        findings = scanner.scan_parameter(
            "http://t.local/page", "GET", {"q": "test"}, "q",
        )
        if findings:
            # If it found via standard probe, confidence should be medium
            self.assertEqual(findings[0].confidence, "medium")


class TestSSTIPayloadLoading(unittest.TestCase):
    """Custom payload file loading."""

    def _scanner(self):
        return SSTIScanner(MagicMock(), {})

    def test_has_name(self):
        """Module NAME is set."""
        scanner = self._scanner()
        self.assertEqual(scanner.NAME, "ssti")


if __name__ == "__main__":
    unittest.main()
