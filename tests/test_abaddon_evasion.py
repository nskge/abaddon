"""Tests for ABADDON evasion layer + scope integration with the engine."""

import asyncio
import unittest

import httpx

from abaddon.core.scope import Scope
from abaddon.network.engine import AsyncEngine, Probe
from abaddon.network.evasion import Evasion, PayloadMutator, random_ip


class TestEvasionHeaders(unittest.TestCase):

    def test_ua_rotation_present(self):
        ev = Evasion(rotate_ua=True)
        h = ev.mutate({})
        self.assertIn("User-Agent", h)

    def test_static_ua_overrides(self):
        ev = Evasion(static_ua="CustomScanner/1.0")
        h = ev.mutate({})
        self.assertEqual(h["User-Agent"], "CustomScanner/1.0")

    def test_ip_spoof_headers_injected(self):
        ev = Evasion(ip_spoof=True)
        h = ev.mutate({})
        self.assertIn("X-Forwarded-For", h)
        self.assertIn("True-Client-IP", h)
        # Same IP used across spoof headers in one mutation
        self.assertEqual(h["X-Forwarded-For"], h["X-Real-IP"])

    def test_ip_spoof_disabled_by_default(self):
        ev = Evasion()
        h = ev.mutate({})
        self.assertNotIn("X-Forwarded-For", h)

    def test_existing_headers_preserved(self):
        ev = Evasion(ip_spoof=True)
        h = ev.mutate({"Authorization": "Bearer tok"})
        self.assertEqual(h["Authorization"], "Bearer tok")

    def test_random_ip_format(self):
        ip = random_ip()
        parts = ip.split(".")
        self.assertEqual(len(parts), 4)
        self.assertTrue(all(1 <= int(p) <= 254 for p in parts))


class TestPayloadMutator(unittest.TestCase):

    def test_level_zero_is_identity(self):
        m = PayloadMutator(level=0)
        self.assertEqual(m.variants("' OR 1=1"), ["' OR 1=1"])

    def test_level_one_url_encode_and_comment(self):
        m = PayloadMutator(level=1)
        variants = m.variants("a b")
        self.assertIn("a%20b", variants)
        self.assertIn("a/**/b", variants)

    def test_level_three_includes_unicode(self):
        m = PayloadMutator(level=3)
        variants = m.variants("SELECT")
        self.assertTrue(any(v.startswith("%u") for v in variants))

    def test_variants_deduplicated(self):
        m = PayloadMutator(level=3)
        variants = m.variants("x")
        self.assertEqual(len(variants), len(set(variants)))

    def test_level_clamped(self):
        self.assertEqual(PayloadMutator(level=99).level, 3)
        self.assertEqual(PayloadMutator(level=-5).level, 0)


class TestEngineEvasionIntegration(unittest.TestCase):

    def test_engine_applies_evasion_headers(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["ua"] = request.headers.get("User-Agent")
            captured["xff"] = request.headers.get("X-Forwarded-For")
            return httpx.Response(200, text="ok body content here padded out")

        transport = httpx.MockTransport(handler)
        ev = Evasion(rotate_ua=True, ip_spoof=True)

        async def go():
            async with AsyncEngine(transport=transport, evasion=ev) as engine:
                return await engine.send(Probe(url="http://target.local/"))

        result = asyncio.run(go())
        self.assertTrue(result.ok)
        self.assertIsNotNone(captured["ua"])
        self.assertIsNotNone(captured["xff"])


if __name__ == "__main__":
    unittest.main()
