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
        # Call 1: baseline (clean), calls 2+: injected responses with the error
        scanner.http.get.side_effect = [_make_response("")] + [_make_response(body)] * 30

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
        scanner.http.get.side_effect = [_make_response("")] + [_make_response(body)] * 30

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 1)
        self.assertIn("MySQL", findings[0].evidence)

    def test_mssql_error_detected(self):
        """MSSQL 'incorrect syntax near' triggers error-based detection."""
        body = "Incorrect syntax near the keyword 'OR'."
        scanner = self._scanner()
        scanner.http.get.side_effect = [_make_response("")] + [_make_response(body)] * 30

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 1)
        self.assertIn("MSSQL", findings[0].evidence)

    def test_oracle_error_detected(self):
        """ORA-xxxxx error pattern triggers Oracle detection."""
        body = "ORA-01756: quoted string not properly terminated"
        scanner = self._scanner()
        scanner.http.get.side_effect = [_make_response("")] + [_make_response(body)] * 30

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

    def test_error_in_baseline_not_flagged(self):
        """SQL error already in baseline page must NOT be reported (false positive prevention).

        This guards against pages that mention 'mysql' or 'sql syntax' in their
        static content (e.g. a tutorial or documentation site).
        """
        body = "You have an error in your SQL syntax; check the manual"
        scanner = self._scanner()
        # Both baseline AND injected responses contain the same SQL error string
        scanner.http.get.return_value = _make_response(body)

        findings = scanner.scan_parameter("http://t.local/", "GET", {"id": "1"}, "id")
        self.assertEqual(len(findings), 0, "Must not flag errors already present in baseline")

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
        # Call 1: baseline (clean), calls 2+: injected responses with the error
        scanner.http.post.side_effect = [_make_response("")] + [_make_response(body)] * 30

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

        # Two stable baselines (stability check) + AND pairs
        scanner.http.get.side_effect = [baseline, baseline] + [true_resp, false_resp] * 10

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
        # Two stable baselines (stability check) + pairs
        scanner.http.get.side_effect = [baseline, baseline] + [true_resp, false_resp] * 10

        finding = scanner._test_boolean_based(
            url="http://target.local/page",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertIsNotNone(finding)

    def test_dynamic_page_boolean_skipped(self):
        """Dynamic pages with varying response sizes skip boolean detection (false positive prevention)."""
        # Two baselines that differ significantly (dynamic ads, nonces, timestamps)
        baseline1 = _make_response("A" * 500)
        baseline2 = _make_response("A" * 800)  # >10% drift → dynamic page

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None
        scanner.http.get.side_effect = [baseline1, baseline2]

        finding = scanner._test_boolean_based(
            url="http://target.local/page",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )

        self.assertIsNone(finding, "Dynamic pages must not trigger boolean SQLi false positives")

    def test_boolean_candidate_not_reproducible_rejected(self):
        """A pattern that appears once but does not reproduce on re-test is discarded."""
        resp_500 = _make_response("A" * 500)
        resp_498 = _make_response("A" * 498)  # near baseline (TRUE)
        resp_80 = _make_response("A" * 80)    # diverges (FALSE) -> looks like AND hit

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None

        # 1-2: stable baselines; 3-4: first AND pair LOOKS like a hit;
        # 5-6: re-confirmation returns baseline-sized pages (no signal) -> reject;
        # everything after stays at baseline so no other pair hits.
        seq = [resp_500, resp_500, resp_498, resp_80, resp_500, resp_500]

        def get_side(*a, **kw):
            return seq.pop(0) if seq else resp_500

        scanner.http.get.side_effect = get_side

        finding = scanner._test_boolean_based(
            url="http://target.local/page",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertIsNone(
            finding, "Boolean candidate that fails the re-test must not be flagged",
        )

    def test_string_quote_breaking_pair_detected(self):
        """String-context SQLi (category=Gin): quote-breaking AND pair differentiates."""
        baseline = _make_response("PRODUCT " * 100)        # ~800 bytes
        true_resp = _make_response("PRODUCT " * 99)        # near baseline (TRUE keeps rows)
        false_resp = _make_response("PRODUCT " * 20)       # far smaller (FALSE -> no rows)

        scanner = self._scanner()
        scanner._test_error_based = lambda *a, **kw: None
        scanner._test_error_status = lambda *a, **kw: None  # isolate boolean path
        # 2 stable baselines, then the numeric AND pairs return baseline (no signal),
        # then a string quote-breaking pair hits, then reconfirm repeats the hit.
        n_numeric = 6  # _APPEND_AND_PAIRS length
        seq = [baseline, baseline]
        seq += [baseline, baseline] * n_numeric          # numeric pairs: no differential
        seq += [true_resp, false_resp]                   # first string pair: hit
        seq += [true_resp, false_resp]                   # reconfirm: same hit
        scanner.http.get.side_effect = lambda *a, **kw: seq.pop(0) if seq else baseline

        finding = scanner._test_boolean_based(
            url="https://shop.local/catalog",
            method="GET",
            params={"category": "Gin"},
            param_name="category",
        )
        self.assertIsNotNone(finding, "Quote-breaking string boolean pair must be detected")


class TestSQLiStatusTransition(unittest.TestCase):
    """Error-based detection via HTTP 200→500→recover status transition."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 5.0})

    def test_status_transition_detected(self):
        """quote→500, balanced→200, quote→500 again = confirmed."""
        base = _make_response("ok", 200)
        broken = _make_response("error", 500)
        fixed = _make_response("ok", 200)
        scanner = self._scanner()
        # order: baseline, quote(500), recovery '' (200), reconfirm quote(500)
        scanner.http.get.side_effect = [base, broken, fixed, broken]
        finding = scanner._test_error_status(
            "https://shop.local/catalog", "GET", {"category": "Gin"}, "category",
        )
        self.assertIsNotNone(finding)
        self.assertIn("status transition", finding.vuln_type)
        self.assertEqual(finding.confidence, "high")

    def test_always_500_not_flagged(self):
        """A param that 500s on everything (recovery fails) must not be flagged."""
        broken = _make_response("error", 500)
        scanner = self._scanner()
        scanner.http.get.return_value = broken
        # baseline itself is 500 → bail immediately
        finding = scanner._test_error_status(
            "https://shop.local/x", "GET", {"a": "1"}, "a",
        )
        self.assertIsNone(finding)

    def test_quote_no_error_not_flagged(self):
        """If the quote doesn't break anything (stays 200), no finding."""
        base = _make_response("ok", 200)
        scanner = self._scanner()
        scanner.http.get.side_effect = [base, base, base, base, base]
        finding = scanner._test_error_status(
            "https://shop.local/x", "GET", {"a": "1"}, "a",
        )
        self.assertIsNone(finding)

    def test_recovery_fails_not_flagged(self):
        """quote→500 but nothing recovers → not flagged (always-erroring param)."""
        base = _make_response("ok", 200)
        broken = _make_response("error", 500)
        scanner = self._scanner()
        # baseline 200, quote 500, then all recovery attempts stay 500
        scanner.http.get.side_effect = [base] + [broken] * 10
        finding = scanner._test_error_status(
            "https://shop.local/x", "GET", {"a": "1"}, "a",
        )
        self.assertIsNone(finding)


class TestSQLiUnionBased(unittest.TestCase):
    """UNION-based in-band extraction — the 'solid proof' path."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 5.0})

    @staticmethod
    def _q(url):
        from urllib.parse import urlparse, parse_qs
        return parse_qs(urlparse(url).query).get("q", [""])[0]

    def test_union_confirmed_with_extraction(self):
        """A DB that executes UNION (concatenates markers) is confirmed, and real
        data is extracted between the markers."""
        scanner = self._scanner()

        def get_side(url):
            import re
            q = self._q(url)
            body = "<html>shop results</html>"
            # Extraction form: 'T1'||(EXPR)||'T2'  -> return loot between markers.
            me = re.search(r"'(\w+)'\|\|\(.+?\)\|\|'(\w+)'", q)
            if me and "UNION" in q.upper():
                return _make_response(body + f"<i>{me.group(1)}users,coupons,orders{me.group(2)}</i>")
            # Plain computed marker 'T1'||'T2' -> DB joins them (execution proof).
            mp = re.search(r"'(\w+)'\|\|'(\w+)'", q)
            if mp and "UNION" in q.upper():
                return _make_response(body + f"<i>{mp.group(1)}{mp.group(2)}</i>")
            # Injectability gate: a lone quote breaks SQL -> error.
            if q.count("'") % 2 == 1:
                return _make_response("SQL error", 500)
            return _make_response(body)

        scanner.http.get.side_effect = get_side
        finding = scanner._test_union_based(
            "http://t.local/shop", "GET", {"q": "widget"}, "q", baseline_text="<html>shop results</html>",
        )
        self.assertIsNotNone(finding)
        self.assertIn("UNION-based", finding.vuln_type)
        self.assertEqual(finding.confidence, "high")
        self.assertIn("users,coupons,orders", finding.evidence)

    def test_union_no_false_positive_on_pure_reflection(self):
        """A search box that merely reflects the payload (never executes it) must
        NOT be flagged — the computed marker never gets joined."""
        scanner = self._scanner()
        # Reflects q verbatim, never errors, never concatenates.
        scanner.http.get.side_effect = lambda url: _make_response(f"<div>{self._q(url)}</div>")
        finding = scanner._test_union_based(
            "http://t.local/shop", "GET", {"q": "widget"}, "q", baseline_text="<div>widget</div>",
        )
        self.assertIsNone(finding)

    def test_union_no_fp_when_quote_errors_but_no_execution(self):
        """Gate passes (quote breaks the page) but UNION never executes (e.g. WAF
        strips it) → still no finding, because the joined marker never appears."""
        scanner = self._scanner()

        def get_side(url):
            q = self._q(url)
            if q.count("'") % 2 == 1:
                return _make_response("SQL error", 500)   # gate sees a difference
            return _make_response(f"<div>{q}</div>")        # reflects, never joins

        scanner.http.get.side_effect = get_side
        finding = scanner._test_union_based(
            "http://t.local/shop", "GET", {"q": "widget"}, "q", baseline_text="<div>widget</div>",
        )
        self.assertIsNone(finding)

    def test_visible_diff_sample_finds_appearing_content(self):
        """The boolean concrete-evidence helper returns a line present in TRUE but
        absent in FALSE."""
        true_html = "<ul><li>Aurora Desk Lamp</li><li>Terra Mug</li></ul>"
        false_html = "<ul></ul>"
        sample = SQLiScanner._visible_diff_sample(true_html, false_html)
        self.assertIsNotNone(sample)
        self.assertIn("Aurora Desk Lamp", sample)


class TestSQLiTimeBased(unittest.TestCase):
    """Time-based blind SQLi detection."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {"delay_threshold": 2.0})

    def test_time_delay_detected(self):
        """Simulated 3-second response triggers time-based detection."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Normal page")

        # 3 baseline samples (2 perf_counter calls each) + 1 payload call
        # + differential-timing confirmation at 2x sleep (must scale)
        times = iter([0.0, 0.1,   # baseline sample 1
                      0.0, 0.1,   # baseline sample 2
                      0.0, 0.1,   # baseline sample 3
                      0.0, 3.5,   # payload start/end
                      0.0, 7.0])  # 2x re-test scales proportionally -> confirmed

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

    def test_single_spike_not_confirmed(self):
        """A one-off latency spike that does NOT scale at 2x sleep is rejected (FP guard)."""
        import itertools
        scanner = self._scanner()  # delay_threshold = 2.0
        scanner.http.get.return_value = _make_response("Normal page")

        # baseline fast; first payload spikes (3.5s) but the 2x re-test stays
        # fast (0.2s) → does not scale → must NOT be flagged.
        times = itertools.chain(
            [0.0, 0.1, 0.0, 0.1, 0.0, 0.1],  # 3 baselines
            [0.0, 3.5],                       # payload 1 trips threshold
            [0.0, 0.2],                       # 2x re-test fails to scale -> reject
            itertools.cycle([0.0, 0.1]),      # every other payload stays fast
        )
        with patch("scanner.modules.sqli.time.perf_counter", side_effect=times):
            finding = scanner._test_time_based(
                url="http://target.local/page",
                method="GET",
                params={"id": "1"},
                param_name="id",
            )
        self.assertIsNone(finding, "Non-scaling latency spike must not be flagged as SQLi")

    def test_append_mode_payload_shows_original_value(self):
        """Time-based append-mode payload displays the full injected value."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("Normal")

        # 3 baseline samples (2 perf_counter calls each) + 1 payload call
        # + differential-timing confirmation at 2x sleep (must scale)
        times = iter([0.0, 0.05,  # baseline sample 1
                      0.0, 0.05,  # baseline sample 2
                      0.0, 0.05,  # baseline sample 3
                      0.0, 3.0,   # first append payload triggers
                      0.0, 6.0])  # 2x re-test scales proportionally -> confirmed

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


class TestSQLiORMInjection(unittest.TestCase):
    """Django ORM filter injection detection."""

    def _scanner(self):
        return SQLiScanner(MagicMock(), {})

    def test_orm_injection_detected_via_id_gte(self):
        """id__gte=0 returning more data than filtered baseline signals ORM injection."""
        scanner = self._scanner()
        # baseline: filtered results (~1KB)
        # probe with id__gte=0: all records (~10KB)
        baseline_resp = _make_response("A" * 1000)
        expanded_resp = _make_response("A" * 12000)  # >10% expansion on large page

        call_count = [0]
        def _get(url, **kwargs):
            call_count[0] += 1
            return expanded_resp if call_count[0] > 1 else baseline_resp
        scanner.http.get.side_effect = _get

        finding = scanner._test_orm_injection(
            url="http://target.local/list",
            method="GET",
            params={"title__icontains": "aaa"},
            param_name="title__icontains",
            baseline_text="A" * 1000,
        )

        self.assertIsNotNone(finding)
        self.assertIn("ORM Injection", finding.vuln_type)
        self.assertEqual(finding.confidence, "high")

    def test_orm_injection_detected_via_result_count(self):
        """Detection via result-count increase works even with small byte expansion.

        Pages with heavy static CSS/JS have a large baseline that dwarfs small
        result-set additions.  The count-based signal catches this case.
        """
        scanner = self._scanner()
        # Simulate a page with ~13KB of static HTML (nav/footer/CSS) + 0 results
        static_html = "X" * 13000
        baseline_body = static_html + "Signals Found: 0"
        # Probe returns same static HTML + 8 results (+small expansion, but count rises)
        probe_body = static_html + "Signals Found: 8" + "post-content " * 50

        scanner.http.get.side_effect = [_make_response(probe_body)]

        finding = scanner._test_orm_injection(
            url="http://target.local/list",
            method="GET",
            params={"title__icontains": "notfound"},
            param_name="title__icontains",
            baseline_text=baseline_body,
        )

        self.assertIsNotNone(finding, "Must detect ORM injection via result-count signal")
        self.assertIn("ORM Injection", finding.vuln_type)
        self.assertIn("8", finding.evidence)  # count increase visible in evidence

    def test_orm_injection_skipped_for_plain_params(self):
        """Parameters without '__' are skipped — not Django ORM syntax."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("A" * 1000)

        finding = scanner._test_orm_injection(
            url="http://target.local/",
            method="GET",
            params={"id": "1"},
            param_name="id",
            baseline_text="A" * 1000,
        )
        self.assertIsNone(finding)

    def test_orm_injection_no_expansion_no_finding(self):
        """If all probes return similar response size, no finding is raised."""
        scanner = self._scanner()
        scanner.http.get.return_value = _make_response("A" * 1000)

        finding = scanner._test_orm_injection(
            url="http://target.local/list",
            method="GET",
            params={"title__icontains": "aaa"},
            param_name="title__icontains",
            baseline_text="A" * 1000,
        )
        self.assertIsNone(finding)

    def test_orm_injection_reproduction_has_traversal_steps(self):
        """Finding reproduction must include relationship traversal examples."""
        scanner = self._scanner()
        baseline_resp = _make_response("A" * 1000)
        expanded_resp = _make_response("A" * 12000)

        call_count = [0]
        def _get(url, **kwargs):
            call_count[0] += 1
            return expanded_resp if call_count[0] > 1 else baseline_resp
        scanner.http.get.side_effect = _get

        finding = scanner._test_orm_injection(
            url="http://target.local/list",
            method="GET",
            params={"title__icontains": "aaa"},
            param_name="title__icontains",
            baseline_text="A" * 1000,
        )

        self.assertIsNotNone(finding)
        self.assertIn("user__password", finding.reproduction)
        self.assertIn("user__email", finding.reproduction)


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
