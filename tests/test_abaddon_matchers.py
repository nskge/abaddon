"""Tests for ABADDON matchers, OAST, and the correlation engine."""

import unittest

from abaddon.core.correlation import CorrelationEngine, Finding, noisy_or
from abaddon.core.matchers import (
    MatchContext,
    evaluate_matcher,
    shannon_entropy,
)
from abaddon.core.oast import MockOASTProvider
from abaddon.models.schemas import (
    EntropyMatcher,
    OASTMatcher,
    ReflectionMatcher,
    RegexMatcher,
    StatusMatcher,
    Template,
    TimeMatcher,
    WordMatcher,
)


def _ctx(**kw) -> MatchContext:
    base = dict(body="", headers={}, status_code=200, elapsed=0.1)
    base.update(kw)
    return MatchContext(**base)


class TestBasicMatchers(unittest.TestCase):

    def test_word_or(self):
        m = WordMatcher(type="word", words=["root:x", "daemon:"], condition="or")
        r = evaluate_matcher(m, _ctx(body="root:x:0:0:root:/root:/bin/bash"))
        self.assertTrue(r.matched)

    def test_word_and_requires_all(self):
        m = WordMatcher(type="word", words=["a", "zzz"], condition="and")
        r = evaluate_matcher(m, _ctx(body="a only here"))
        self.assertFalse(r.matched)

    def test_word_negative(self):
        m = WordMatcher(type="word", words=["blocked"], negative=True)
        r = evaluate_matcher(m, _ctx(body="all good"))
        self.assertTrue(r.matched)  # word absent → negative matches

    def test_regex(self):
        m = RegexMatcher(type="regex", regex=[r"SQL syntax.*MySQL"])
        r = evaluate_matcher(m, _ctx(body="You have an error in your SQL syntax near MySQL"))
        self.assertTrue(r.matched)

    def test_status(self):
        m = StatusMatcher(type="status", status=[200, 302])
        self.assertTrue(evaluate_matcher(m, _ctx(status_code=302)).matched)
        self.assertFalse(evaluate_matcher(m, _ctx(status_code=404)).matched)

    def test_header_part(self):
        m = WordMatcher(type="word", words=["nginx"], part="header")
        r = evaluate_matcher(m, _ctx(headers={"Server": "nginx/1.0"}))
        self.assertTrue(r.matched)


class TestBlindMatchers(unittest.TestCase):

    def test_time_matcher_detects_delay(self):
        m = TimeMatcher(type="time", threshold=5.0)
        r = evaluate_matcher(m, _ctx(elapsed=6.2, baseline_elapsed=0.2))
        self.assertTrue(r.matched)
        self.assertGreater(r.confidence, 0.0)

    def test_time_matcher_ignores_jitter(self):
        m = TimeMatcher(type="time", threshold=5.0)
        r = evaluate_matcher(m, _ctx(elapsed=0.4, baseline_elapsed=0.2))
        self.assertFalse(r.matched)

    def test_entropy_size_delta(self):
        m = EntropyMatcher(type="entropy", size_delta=0.25)
        base = "X" * 1000
        big = "X" * 2000
        r = evaluate_matcher(m, _ctx(body=big, baseline_body=base))
        self.assertTrue(r.matched)

    def test_entropy_no_change(self):
        m = EntropyMatcher(type="entropy", size_delta=0.25)
        base = "X" * 1000
        r = evaluate_matcher(m, _ctx(body="X" * 1010, baseline_body=base))
        self.assertFalse(r.matched)

    def test_shannon_entropy_monotonic(self):
        self.assertLess(shannon_entropy("aaaaaa"), shannon_entropy("abcdef"))


class TestReflectionMatcher(unittest.TestCase):

    def test_unescaped_html_context(self):
        marker = "abz<x>"
        m = ReflectionMatcher(type="reflection", marker=marker)
        r = evaluate_matcher(m, _ctx(body=f"<div>search: {marker}</div>"))
        self.assertTrue(r.matched)

    def test_escaped_is_safe(self):
        marker = "abz<x>"
        m = ReflectionMatcher(type="reflection", marker=marker)
        body = "<div>search: abz&lt;x&gt;</div>"
        r = evaluate_matcher(m, _ctx(body=body))
        self.assertFalse(r.matched)

    def test_script_context_high_confidence(self):
        marker = "abz123"
        m = ReflectionMatcher(type="reflection", marker=marker)
        body = f"<script>var q = '{marker}';</script>"
        r = evaluate_matcher(m, _ctx(body=body))
        self.assertTrue(r.matched)
        self.assertGreaterEqual(r.confidence, 0.7)

    def test_not_reflected(self):
        m = ReflectionMatcher(type="reflection", marker="abz<x>")
        r = evaluate_matcher(m, _ctx(body="nothing here"))
        self.assertFalse(r.matched)


class TestOAST(unittest.TestCase):

    def test_oast_hit(self):
        provider = MockOASTProvider()
        handle = provider.new_handle()
        provider.trigger(handle.correlation_id, protocol="dns")
        m = OASTMatcher(type="oast", protocols=["dns", "http"])
        r = evaluate_matcher(
            m, _ctx(oast=provider, oast_correlation_id=handle.correlation_id)
        )
        self.assertTrue(r.matched)
        self.assertGreaterEqual(r.confidence, 0.9)

    def test_oast_no_interaction(self):
        provider = MockOASTProvider()
        handle = provider.new_handle()
        m = OASTMatcher(type="oast")
        r = evaluate_matcher(
            m, _ctx(oast=provider, oast_correlation_id=handle.correlation_id)
        )
        self.assertFalse(r.matched)

    def test_oast_protocol_filter(self):
        provider = MockOASTProvider()
        handle = provider.new_handle()
        provider.trigger(handle.correlation_id, protocol="dns")
        m = OASTMatcher(type="oast", protocols=["http"])  # only http counts
        r = evaluate_matcher(
            m, _ctx(oast=provider, oast_correlation_id=handle.correlation_id)
        )
        self.assertFalse(r.matched)

    def test_handle_payload_format(self):
        provider = MockOASTProvider(base_domain="oast.test")
        handle = provider.new_handle()
        self.assertTrue(handle.payload.endswith(".oast.test"))


class TestCorrelation(unittest.TestCase):

    def test_noisy_or_combines(self):
        self.assertAlmostEqual(noisy_or([0.5, 0.5]), 0.75)
        self.assertAlmostEqual(noisy_or([1.0]), 1.0)
        self.assertAlmostEqual(noisy_or([]), 0.0)

    def _template(self, matchers, condition="or", threshold=0.6):
        return Template.model_validate(
            {
                "id": "t",
                "info": {"name": "Test", "severity": "high"},
                "confidence_threshold": threshold,
                "requests": [
                    {
                        "path": ["/"],
                        "matchers-condition": condition,
                        "matchers": matchers,
                    }
                ],
            }
        )

    def test_single_weak_signal_below_threshold(self):
        tpl = self._template(
            [{"type": "word", "words": ["maybe"], "confidence": 0.4}], threshold=0.6
        )
        engine = CorrelationEngine()
        ctx = _ctx(body="maybe vulnerable")
        finding = engine.evaluate_request(tpl, tpl.requests[0], ctx, "http://t/")
        self.assertIsNone(finding)  # 0.4 < 0.6

    def test_multi_signal_promotes(self):
        tpl = self._template(
            [
                {"type": "word", "words": ["error"], "confidence": 0.4},
                {"type": "status", "status": [500], "confidence": 0.4},
            ],
            condition="or",
            threshold=0.6,
        )
        engine = CorrelationEngine()
        ctx = _ctx(body="db error", status_code=500)
        finding = engine.evaluate_request(tpl, tpl.requests[0], ctx, "http://t/")
        # noisy-or(0.4, 0.4) = 0.64 >= 0.6 → confirmed
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(len(finding.matched_signals), 2)

    def test_and_condition_requires_all(self):
        tpl = self._template(
            [
                {"type": "word", "words": ["present"], "confidence": 0.8},
                {"type": "word", "words": ["absent"], "confidence": 0.8},
            ],
            condition="and",
            threshold=0.5,
        )
        engine = CorrelationEngine()
        ctx = _ctx(body="present only")
        finding = engine.evaluate_request(tpl, tpl.requests[0], ctx, "http://t/")
        self.assertIsNone(finding)

    def test_oast_alone_confirms(self):
        provider = MockOASTProvider()
        handle = provider.new_handle()
        provider.trigger(handle.correlation_id, protocol="http")
        tpl = self._template([{"type": "oast", "confidence": 0.95}], threshold=0.6)
        engine = CorrelationEngine()
        ctx = _ctx(oast=provider, oast_correlation_id=handle.correlation_id)
        finding = engine.evaluate_request(tpl, tpl.requests[0], ctx, "http://t/")
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(finding.confidence, 0.9)


if __name__ == "__main__":
    unittest.main()
