"""Tests for the ABADDON async engine, throttling, and scope."""

import asyncio
import unittest

import httpx

from abaddon.core.scope import Scope
from abaddon.network.engine import AsyncEngine, Probe
from abaddon.network.throttle import AdaptiveThrottle, TokenBucket


def _run(coro):
    return asyncio.run(coro)


class TestScope(unittest.TestCase):

    def test_disabled_scope_allows_all(self):
        s = Scope()
        self.assertFalse(s.enabled)
        self.assertTrue(s.allows("http://anything.local/x"))

    def test_glob_pattern_match(self):
        s = Scope(patterns=["*.example.com"])
        self.assertTrue(s.allows("https://api.example.com/v1"))
        self.assertTrue(s.allows("https://www.example.com/"))
        self.assertFalse(s.allows("https://evil.com/"))

    def test_cidr_match(self):
        s = Scope(cidrs=["172.16.10.0/24"])
        self.assertTrue(s.allows("http://172.16.10.45/list"))
        self.assertFalse(s.allows("http://10.0.0.1/"))

    def test_no_host_rejected_when_enabled(self):
        s = Scope(patterns=["*.example.com"])
        self.assertFalse(s.allows("not-a-url"))


class TestTokenBucket(unittest.TestCase):

    def test_zero_rate_is_unlimited(self):
        bucket = TokenBucket(rate=0)

        async def go():
            # Should return immediately, many times.
            for _ in range(100):
                await bucket.acquire()

        _run(go())  # completes without hanging

    def test_rate_limits_throughput(self):
        async def go():
            bucket = TokenBucket(rate=50, capacity=1)
            loop = asyncio.get_event_loop()
            start = loop.time()
            for _ in range(5):
                await bucket.acquire()
            return loop.time() - start

        elapsed = _run(go())
        # 5 tokens at 50/s with capacity 1 → at least ~4 refills (~0.08s)
        self.assertGreater(elapsed, 0.04)


class TestAdaptiveThrottle(unittest.TestCase):

    def test_backoff_increases_per_host(self):
        t = AdaptiveThrottle(base_delay=0.0, backoff=2.0, max_delay=5.0)
        self.assertEqual(t.current_delay("a.com"), 0.0)
        t.record_failure("a.com")
        d1 = t.current_delay("a.com")
        self.assertGreater(d1, 0.0)
        t.record_failure("a.com")
        self.assertGreater(t.current_delay("a.com"), d1)
        # Other host unaffected
        self.assertEqual(t.current_delay("b.com"), 0.0)

    def test_backoff_capped(self):
        t = AdaptiveThrottle(backoff=10.0, max_delay=1.0)
        for _ in range(10):
            t.record_failure("a.com")
        self.assertLessEqual(t.current_delay("a.com"), 1.0)

    def test_recovery_decays(self):
        t = AdaptiveThrottle(backoff=2.0, recovery=0.5, floor=0.05)
        t.record_failure("a.com")
        t.record_failure("a.com")
        high = t.current_delay("a.com")
        t.record_success("a.com")
        self.assertLess(t.current_delay("a.com"), high)


class TestAsyncEngine(unittest.TestCase):

    def test_thousand_probes_no_leak(self):
        """1000 probes through a mock transport all complete; client closes."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK BODY " * 20)

        transport = httpx.MockTransport(handler)

        async def go():
            async with AsyncEngine(concurrency=100, transport=transport) as engine:
                probes = [Probe(url=f"http://target.local/item/{i}") for i in range(1000)]
                results = await engine.run(probes)
                client_closed_after = engine
                return results, engine

        results, engine = _run(go())
        self.assertEqual(len(results), 1000)
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(engine.stats.sent, 1000)
        # Client released after context exit
        self.assertIsNone(engine._client)

    def test_scope_blocks_out_of_scope(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="should not reach")

        transport = httpx.MockTransport(handler)
        scope = Scope(patterns=["*.allowed.com"])

        async def go():
            async with AsyncEngine(transport=transport, scope=scope) as engine:
                r1 = await engine.send(Probe(url="http://api.allowed.com/x"))
                r2 = await engine.send(Probe(url="http://evil.com/x"))
                return r1, r2, engine

        r1, r2, engine = _run(go())
        self.assertTrue(r1.ok)
        self.assertEqual(r2.error, "out-of-scope")
        self.assertEqual(engine.stats.out_of_scope, 1)

    def test_backoff_and_retry_on_connect_error(self):
        state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            raise httpx.ConnectError("refused", request=request)

        transport = httpx.MockTransport(handler)

        async def go():
            async with AsyncEngine(transport=transport, retries=2) as engine:
                result = await engine.send(Probe(url="http://down.local/"))
                return result, engine

        result, engine = _run(go())
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "ConnectError")
        # initial + 2 retries = 3 attempts
        self.assertEqual(state["calls"], 3)
        # Host got throttled
        self.assertGreater(engine.throttle.current_delay("down.local"), 0.0)

    def test_retry_on_503_then_success(self):
        state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(503, text="overloaded")
            return httpx.Response(200, text="recovered now ok")

        transport = httpx.MockTransport(handler)

        async def go():
            async with AsyncEngine(transport=transport, retries=2) as engine:
                return await engine.send(Probe(url="http://flaky.local/"))

        result = _run(go())
        self.assertTrue(result.ok)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(state["calls"], 2)

    def test_streaming_handler_mode(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="x" * 200)

        transport = httpx.MockTransport(handler)
        seen = []

        async def go():
            async with AsyncEngine(concurrency=20, transport=transport) as engine:
                async def on_result(r):
                    seen.append(r.status_code)
                probes = [Probe(url=f"http://t.local/{i}") for i in range(50)]
                returned = await engine.run(probes, handler=on_result)
                return returned

        returned = _run(go())
        self.assertEqual(returned, [])  # streaming mode returns nothing
        self.assertEqual(len(seen), 50)


if __name__ == "__main__":
    unittest.main()
