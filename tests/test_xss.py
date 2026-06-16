"""Unit tests for the XSS detection module.

All HTTP calls are mocked — no live network required.
Run with:  python -m pytest tests/ -v
"""

import unittest
from unittest.mock import MagicMock

from scanner.modules.xss import XSSScanner, _DEFAULT_PAYLOADS


def _make_response(text: str, status: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


def _q(url: str) -> str:
    from urllib.parse import urlparse, parse_qs
    return parse_qs(urlparse(url).query).get("q", [""])[0]


class TestXSSHtmlInjection(unittest.TestCase):
    """Phase 3 fallback: HTML injection when script execution is filtered."""

    def _scanner(self):
        return XSSScanner(MagicMock(), {})

    def test_html_injection_when_script_filtered(self):
        """App allows harmless formatting tags but encodes everything else
        (a typical sanitiser) → HTML Injection, not full XSS."""
        import re
        scanner = self._scanner()
        _allowed = re.compile(r"^</?(?:u|b|i|em|strong|h1|p|marquee)>$", re.I)

        def get_side(url):
            v = _q(url)
            tags = re.findall(r"</?[a-zA-Z][^>]*>", v)
            if tags and not all(_allowed.match(t) for t in tags):
                # contains a disallowed tag -> sanitiser encodes the whole value
                v = v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return _make_response(f"<div>You searched: {v}</div>")

        scanner.http.get.side_effect = get_side
        findings = scanner.scan_parameter("http://t.local/shop", "GET", {"q": "x"}, "q")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "HTML Injection")
        self.assertEqual(findings[0].confidence, "medium")

    def test_full_xss_takes_priority_over_html_injection(self):
        """When script reflects raw, the finding is full XSS, not HTML injection."""
        scanner = self._scanner()
        scanner.http.get.side_effect = lambda url: _make_response(f"<div>{_q(url)}</div>")
        findings = scanner.scan_parameter("http://t.local/shop", "GET", {"q": "x"}, "q")
        self.assertEqual(len(findings), 1)
        self.assertIn("Reflected XSS", findings[0].vuln_type)

    def test_no_html_injection_when_everything_encoded(self):
        """A safe app that encodes all output yields no finding."""
        scanner = self._scanner()

        def get_side(url):
            v = _q(url).replace("<", "&lt;").replace(">", "&gt;")
            return _make_response(f"<div>{v}</div>")

        scanner.http.get.side_effect = get_side
        findings = scanner.scan_parameter("http://t.local/shop", "GET", {"q": "x"}, "q")
        self.assertEqual(findings, [])


class TestXSSReflectionProbe(unittest.TestCase):
    """Phase 1: reflection probe."""

    def _scanner(self, client=None):
        return XSSScanner(client or MagicMock(), {})

    def test_probe_reflected_returns_true(self):
        """When the unique probe token appears in the response, reflection is detected."""
        scanner = self._scanner()

        # Echo whatever the request sends back in the response body
        def get_side(url):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            value = qs.get("q", [""])[0]
            return _make_response(f"<html><body>Result: {value}</body></html>")

        scanner.http.get.side_effect = get_side
        reflected, context = scanner._probe_reflection(
            url="http://target.local/page",
            method="GET",
            params={"q": "test"},
            param_name="q",
        )

        self.assertTrue(reflected)

    def test_probe_not_reflected_returns_false(self):
        """When the probe is absent from the response, no reflection is reported."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response(
            "<html><body>Static page, no echo here.</body></html>"
        )

        reflected, context = scanner._probe_reflection(
            url="http://target.local/page",
            method="GET",
            params={"q": "test"},
            param_name="q",
        )

        self.assertFalse(reflected)

    def test_none_response_handled(self):
        """Network failure (None response) does not raise an exception."""
        scanner = self._scanner()
        scanner.http.get.return_value = None

        reflected, context = scanner._probe_reflection(
            url="http://target.local/page",
            method="GET",
            params={"q": "test"},
            param_name="q",
        )

        self.assertFalse(reflected)


class TestXSSContextDetection(unittest.TestCase):
    """Static context-detection logic."""

    def test_html_context_detected(self):
        html = "<html><body>Hello xssprobeabc123 world</body></html>"
        ctx = XSSScanner._detect_context(html, "xssprobeabc123")
        self.assertEqual(ctx, "html")

    def test_attribute_context_detected(self):
        html = '<input type="text" value="xssprobeabc123" />'
        ctx = XSSScanner._detect_context(html, "xssprobeabc123")
        self.assertEqual(ctx, "attribute")

    def test_script_context_detected(self):
        html = "<script>var q = 'xssprobeabc123';</script>"
        ctx = XSSScanner._detect_context(html, "xssprobeabc123")
        self.assertEqual(ctx, "script")


class TestXSSPayloadValidation(unittest.TestCase):
    """Phase 2: unencoded payload detection."""

    def _scanner(self, client=None):
        return XSSScanner(client or MagicMock(), {})

    def test_script_tag_reflected_unencoded(self):
        """<script>alert(1)</script> in the response body is flagged."""
        payload = '<script>alert(1)</script>'
        body = f'<html><body><p>{payload}</p></body></html>'
        confirmed, evidence = XSSScanner._check_unencoded(body, payload)
        self.assertTrue(confirmed)
        self.assertIn("verbatim", evidence)

    def test_onerror_fragment_detected(self):
        """onerror= appearing unencoded triggers detection."""
        payload = '<img src=x onerror=alert(1)>'
        body = f'<div>{payload}</div>'
        confirmed, evidence = XSSScanner._check_unencoded(body, payload)
        self.assertTrue(confirmed)

    def test_html_encoded_not_detected(self):
        """HTML-encoded < and > do NOT trigger a finding."""
        payload = '<script>alert(1)</script>'
        # Server properly encoded the output
        body = "&lt;script&gt;alert(1)&lt;/script&gt;"
        confirmed, evidence = XSSScanner._check_unencoded(body, payload)
        self.assertFalse(confirmed)

    def test_scan_parameter_no_reflection_returns_empty(self):
        """If the probe is not reflected, scan_parameter returns []."""
        scanner = self._scanner()
        # All GET calls return a static page that never echoes the probe
        scanner.http.get.return_value = _make_response(
            "<html><body>Nothing echoed here.</body></html>"
        )

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"q": "hello"},
            param_name="q",
        )

        self.assertEqual(findings, [])

    def test_full_scan_parameter_detects_xss(self):
        """End-to-end: reflected probe + unencoded payload → finding."""
        scanner = self._scanner()

        call_count = [0]

        def side_effect(url):
            call_count[0] += 1
            # First call is the probe — echo back whatever was in the URL
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            value = qs.get("q", [""])[0]
            return _make_response(f"<html><body>{value}</body></html>")

        scanner.http.get.side_effect = side_effect

        findings = scanner.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"q": "test"},
            param_name="q",
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].vuln_type, "Cross-Site Scripting (Reflected XSS)")
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(findings[0].parameter, "q")

    def test_post_method_supported(self):
        """XSS detection works with POST requests."""
        scanner = self._scanner()

        def post_side(url, data=None):
            value = (data or {}).get("comment", "")
            return _make_response(f"<p>{value}</p>")

        scanner.http.post.side_effect = post_side

        findings = scanner.scan_parameter(
            url="http://target.local/submit",
            method="POST",
            params={"comment": "hello"},
            param_name="comment",
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].method, "POST")


class TestXSSEdgeCases(unittest.TestCase):
    """Edge cases and robustness checks."""

    def test_none_response_in_payload_phase(self):
        """Network errors during payload phase are handled without crashing."""
        scanner = XSSScanner(MagicMock(), {})
        # Probe succeeds (echoes the token), payload phase returns None
        probe_done = [False]

        def get_side(url):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            value = qs.get("q", [""])[0]
            if not probe_done[0]:
                probe_done[0] = True
                return _make_response(f"echo:{value}")
            return None  # simulate network failure on subsequent calls

        scanner.http.get.side_effect = get_side
        # Should not raise
        findings = scanner.scan_parameter("http://t.local/?q=x", "GET", {"q": "x"}, "q")
        # May or may not find something, but must not raise
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
