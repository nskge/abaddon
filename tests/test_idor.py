"""Tests for the IDOR detection module."""

import unittest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from scanner.modules.idor import IDORScanner, _adjacent_ids, _size_similar


def _make_resp(body: str, status: int = 200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


def _scanner():
    http = MagicMock()
    return IDORScanner(http_client=http, config={})


class TestHelpers(unittest.TestCase):

    def test_adjacent_ids_normal(self):
        self.assertEqual(_adjacent_ids(5), [4, 6, 7])

    def test_adjacent_ids_at_one(self):
        self.assertEqual(_adjacent_ids(1), [2, 3])

    def test_size_similar_within_tolerance(self):
        self.assertTrue(_size_similar(1000, 900))   # 10% diff
        self.assertTrue(_size_similar(1000, 600))   # 40% diff — within 60%

    def test_size_similar_outside_tolerance(self):
        self.assertFalse(_size_similar(1000, 300))  # 70% diff — outside 60%

    def test_size_similar_zero_base(self):
        self.assertFalse(_size_similar(0, 500))


class TestNumericParamIDOR(unittest.TestCase):

    def _scanner(self):
        return _scanner()

    def test_idor_detected_adjacent_id(self):
        s = self._scanner()
        body_a = "user profile: Alice, email: alice@example.com, age: 28, credits: 500, joined: 2020-01-01, status: active, role: viewer"
        body_b = "user profile: Bob, email: bob@example.com, age: 33, credits: 9999, joined: 2019-06-15, status: active, role: admin"
        # baseline × 2 (stability check) + probe id=2, id=3
        s.http.get.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # probe id=2 → HIT
            _make_resp(body_b),  # probe id=3
        ]
        findings = s.scan_parameter(
            url="http://target.local/profile",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.vuln_type, "IDOR")
        self.assertEqual(f.parameter, "id")
        self.assertIn("1 →", f.evidence)

    def test_idor_high_confidence_two_hits(self):
        s = self._scanner()
        body_a = "profile data: user=1, score=100, rank=bronze, xp=0, guild=none, active=true, joined=2023, region=eu-1"
        body_b = "profile data: user=2, score=200, rank=silver, xp=500, guild=alpha, active=true, joined=2022, region=us-1"
        body_c = "profile data: user=3, score=300, rank=gold, xp=1500, guild=beta, active=false, joined=2021, region=as-1"
        s.http.get.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # probe id=2 → HIT
            _make_resp(body_c),  # probe id=3 → HIT
        ]
        findings = s.scan_parameter(
            url="http://target.local/data",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "high")

    def test_no_idor_identical_responses(self):
        """Server returns same body regardless of ID → parameter is ignored."""
        s = self._scanner()
        body = "static page content: welcome to the site"
        s.http.get.return_value = _make_resp(body)
        findings = s.scan_parameter(
            url="http://target.local/page",
            method="GET",
            params={"id": "5"},
            param_name="id",
        )
        self.assertEqual(findings, [])

    def test_no_idor_probes_return_404(self):
        """Adjacent IDs return 404 → no finding."""
        s = self._scanner()
        body_a = "post content for id=1: hello world"
        s.http.get.side_effect = [
            _make_resp(body_a),           # baseline
            _make_resp(body_a),           # stability
            _make_resp("not found", 404), # probe id=2
            _make_resp("not found", 404), # probe id=3
        ]
        findings = s.scan_parameter(
            url="http://target.local/post",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertEqual(findings, [])

    def test_no_idor_dynamic_page(self):
        """Pages with >10% size drift between identical requests → skip."""
        s = self._scanner()
        body_a = "content A " * 100  # 1000 chars
        body_unstable = "content A " * 115  # 1150 chars → 15% drift
        s.http.get.side_effect = [
            _make_resp(body_a),         # baseline
            _make_resp(body_unstable),  # stability check → drift >10% → skip
        ]
        findings = s.scan_parameter(
            url="http://target.local/dynamic",
            method="GET",
            params={"id": "3"},
            param_name="id",
        )
        self.assertEqual(findings, [])

    def test_no_idor_baseline_too_small(self):
        """Tiny responses (error stubs) → skip."""
        s = self._scanner()
        s.http.get.return_value = _make_resp("err", 200)
        findings = s.scan_parameter(
            url="http://target.local/tiny",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertEqual(findings, [])

    def test_no_idor_probe_size_too_different(self):
        """Probe size differs by >60% from baseline → skip (different resource type)."""
        s = self._scanner()
        body_a = "X" * 1000
        body_b = "Y" * 100  # 90% smaller
        s.http.get.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # probe id=2 → too small
            _make_resp(body_b),  # probe id=3 → too small
        ]
        findings = s.scan_parameter(
            url="http://target.local/obj",
            method="GET",
            params={"id": "1"},
            param_name="id",
        )
        self.assertEqual(findings, [])

    def test_non_numeric_param_not_tested(self):
        """Non-numeric param values should not trigger numeric IDOR."""
        s = self._scanner()
        findings = s.scan_parameter(
            url="http://target.local/search",
            method="GET",
            params={"q": "admin"},
            param_name="q",
        )
        # http never called for param (only path check may happen)
        # path has no numeric segments → no calls
        self.assertEqual(findings, [])

    def test_post_method_idor(self):
        """IDOR detection works on POST requests."""
        s = self._scanner()
        body_a = "record 1 data: name=foo, value=100, category=sales, region=north, active=yes, owner=alice, dept=ops-1"
        body_b = "record 2 data: name=bar, value=200, category=marketing, region=south, active=no, owner=bob, dept=hr-22"
        s.http.post.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # probe id=2 → HIT
            _make_resp(body_b),  # probe id=3
        ]
        findings = s.scan_parameter(
            url="http://target.local/api/record",
            method="POST",
            params={"id": "1", "token": "abc"},
            param_name="id",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "IDOR")


class TestUUIDParamIDOR(unittest.TestCase):

    def test_uuid_idor_detected(self):
        s = _scanner()
        body_a = "document: title=My Annual Report, owner=alice, pages=42, classification=public, dept=finance, year=2024"
        body_b = "document: title=Secret Internal Doc, owner=bob, pages=12, classification=confidential, dept=hr, year=2023"
        s.http.get.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # random UUID → HIT
        ]
        findings = s.scan_parameter(
            url="http://target.local/doc",
            method="GET",
            params={"uuid": "11111111-2222-3333-4444-555555555555"},
            param_name="uuid",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "IDOR")
        self.assertIn("Random UUID", findings[0].evidence)

    def test_uuid_idor_not_detected_when_404(self):
        s = _scanner()
        body_a = "doc: id=abc"
        s.http.get.side_effect = [
            _make_resp(body_a),            # baseline
            _make_resp(body_a),            # stability
            _make_resp("not found", 404),  # random uuid 1
            _make_resp("not found", 404),  # random uuid 2
            _make_resp("not found", 404),  # random uuid 3
        ]
        findings = s.scan_parameter(
            url="http://target.local/doc",
            method="GET",
            params={"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            param_name="uuid",
        )
        self.assertEqual(findings, [])


class TestPathSegmentIDOR(unittest.TestCase):

    def test_path_idor_detected(self):
        s = _scanner()
        body_a = "invoice #5: amount=100.00, client=Alice Corp, due=2024-03-01, status=paid, items=3, tax=10, ref=INV005"
        body_b = "invoice #6: amount=250.00, client=Bob LLC, due=2024-04-01, status=pending, items=5, tax=25, ref=INV006"
        # For path /invoice/5/ → baseline×2 + probe /invoice/4/ + probe /invoice/6/ + probe /invoice/7/
        s.http.get.side_effect = [
            _make_resp(body_a),  # baseline
            _make_resp(body_a),  # stability
            _make_resp(body_b),  # probe /invoice/4/ → HIT
            _make_resp(body_b),  # probe /invoice/6/
            _make_resp(body_b),  # probe /invoice/7/
        ]
        findings = s.scan_parameter(
            url="http://target.local/invoice/5/",
            method="GET",
            params={},
            param_name="__no_param__",  # no query params
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "IDOR")
        self.assertIn("path[", findings[0].parameter)

    def test_path_idor_not_triggered_for_non_numeric_segments(self):
        s = _scanner()
        # No numeric segments → no path probes → http never called
        findings = s.scan_parameter(
            url="http://target.local/api/users/profile",
            method="GET",
            params={},
            param_name="__no_param__",
        )
        self.assertEqual(findings, [])
        s.http.get.assert_not_called()

    def test_path_idor_tested_only_once_per_url(self):
        """scan_parameter called twice for same URL must only probe path once."""
        s = _scanner()
        body_a = "item 1: data"
        body_b = "item 2: data"
        s.http.get.side_effect = [
            _make_resp(body_a),  # path baseline
            _make_resp(body_a),  # path stability
            _make_resp(body_b),  # path probe id=2
            _make_resp(body_b),  # path probe id=3
            # second call to scan_parameter should NOT trigger path test again
        ]
        url = "http://target.local/item/1/"
        s.scan_parameter(url=url, method="GET", params={"filter": "all"}, param_name="filter")
        call_count_after_first = s.http.get.call_count
        # Second scan_parameter call (different param) should not redo path test
        s.http.get.side_effect = None
        s.http.get.return_value = _make_resp(body_a)
        s.scan_parameter(url=url, method="GET", params={"sort": "asc"}, param_name="sort")
        # Path test should not have fired again — only param test for "sort" may run
        # (sort is non-numeric, so no param test either)
        self.assertEqual(s.http.get.call_count, call_count_after_first)


if __name__ == "__main__":
    unittest.main()
