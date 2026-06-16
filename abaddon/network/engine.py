"""AsyncEngine — the heart of ABADDON.

A high-concurrency HTTP engine built on ``httpx.AsyncClient`` (HTTP/2) with:

* an :class:`asyncio.Semaphore` concurrency gate (conservative default),
* a bounded producer/consumer :class:`asyncio.Queue` for back-pressure,
* a global :class:`~abaddon.network.throttle.TokenBucket` rate limiter,
* per-host adaptive back-off via
  :class:`~abaddon.network.throttle.AdaptiveThrottle`,
* mandatory pre-flight scope enforcement,
* optional request mutation (evasion) injected per request.

The engine is *transport agnostic for tests*: pass a custom ``transport``
(e.g. ``httpx.MockTransport``) to drive it without real network I/O.
"""

import asyncio
import time
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpx

from ..core.scope import Scope
from .throttle import AdaptiveThrottle, TokenBucket

# Network errors that justify a per-host back-off + retry.
_RETRYABLE_EXC = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
)
_RETRYABLE_STATUS = {429, 503}


@dataclass
class Probe:
    """A single request to dispatch."""

    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    data: Any = None
    json: Any = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeResult:
    """Outcome of a dispatched :class:`Probe`."""

    probe: Probe
    status_code: Optional[int]
    headers: Dict[str, str]
    text: str
    elapsed: float
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


@dataclass
class EngineStats:
    """Live counters for the CLI dashboard / observability layer."""

    sent: int = 0
    errors: int = 0
    hits: int = 0
    out_of_scope: int = 0
    status_counts: Dict[int, int] = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)

    def record(self, ok: bool, status: Optional[int] = None) -> None:
        self.sent += 1
        if not ok:
            self.errors += 1
        if status is not None:
            self.status_counts[status] = self.status_counts.get(status, 0) + 1

    @property
    def rps(self) -> float:
        elapsed = time.monotonic() - self.started
        return self.sent / elapsed if elapsed > 0 else 0.0


class AsyncEngine:
    """Concurrent HTTP engine with throttling, scope, and evasion hooks."""

    def __init__(
        self,
        concurrency: int = 150,
        rate: float = 0.0,
        timeout: float = 10.0,
        retries: int = 2,
        verify: bool = False,
        http2: bool = True,
        follow_redirects: bool = True,
        scope: Optional[Scope] = None,
        throttle: Optional[AdaptiveThrottle] = None,
        evasion: Any = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.retries = max(0, retries)
        self.verify = verify
        self.http2 = http2
        self.follow_redirects = follow_redirects
        self.scope = scope or Scope()
        self.throttle = throttle or AdaptiveThrottle()
        self.evasion = evasion
        self._transport = transport

        self._bucket = TokenBucket(rate) if rate and rate > 0 else None
        self._sem = asyncio.Semaphore(self.concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self.stats = EngineStats()

    # ------------------------------------------------------------------
    # Async context manager — owns the client lifecycle (no FD leaks)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncEngine":
        limits = httpx.Limits(
            max_connections=self.concurrency,
            max_keepalive_connections=max(10, self.concurrency // 2),
        )
        client_kwargs: Dict[str, Any] = dict(
            http2=self.http2,
            verify=self.verify,
            timeout=self.timeout,
            limits=limits,
            follow_redirects=self.follow_redirects,
        )
        if self._transport is not None:
            client_kwargs["transport"] = self._transport
        self._client = httpx.AsyncClient(**client_kwargs)
        self.stats = EngineStats()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Single dispatch
    # ------------------------------------------------------------------

    async def send(self, probe: Probe) -> ProbeResult:
        if self._client is None:
            raise RuntimeError("AsyncEngine must be used as an async context manager")

        # --- Invariant: scope enforcement BEFORE any I/O ---
        if not self.scope.allows(probe.url):
            self.stats.out_of_scope += 1
            return ProbeResult(probe, None, {}, "", 0.0, error="out-of-scope")

        host = urlparse(probe.url).hostname or ""

        async with self._sem:
            if self._bucket is not None:
                await self._bucket.acquire()
            await self.throttle.wait(host)
            return await self._dispatch_with_retry(probe, host)

    async def _dispatch_with_retry(self, probe: Probe, host: str) -> ProbeResult:
        attempt = 0
        last_elapsed = 0.0
        while True:
            attempt += 1
            headers = dict(probe.headers or {})
            if self.evasion is not None:
                headers = self.evasion.mutate(headers, url=probe.url)

            start = perf_counter()
            try:
                resp = await self._client.request(  # type: ignore[union-attr]
                    probe.method,
                    probe.url,
                    headers=headers or None,
                    params=probe.params,
                    data=probe.data,
                    json=probe.json,
                )
            except _RETRYABLE_EXC as exc:
                last_elapsed = perf_counter() - start
                self.throttle.record_failure(host)
                if attempt <= self.retries:
                    await asyncio.sleep(self.throttle.current_delay(host) or 0.2)
                    continue
                self.stats.record(ok=False)
                return ProbeResult(
                    probe, None, {}, "", last_elapsed, error=type(exc).__name__
                )
            except httpx.HTTPError as exc:
                last_elapsed = perf_counter() - start
                self.stats.record(ok=False)
                return ProbeResult(
                    probe, None, {}, "", last_elapsed, error=type(exc).__name__
                )

            last_elapsed = perf_counter() - start

            if resp.status_code in _RETRYABLE_STATUS and attempt <= self.retries:
                self.throttle.record_failure(host)
                await asyncio.sleep(self.throttle.current_delay(host) or 0.5)
                continue

            self.throttle.record_success(host)
            self.stats.record(ok=True, status=resp.status_code)
            return ProbeResult(
                probe,
                resp.status_code,
                dict(resp.headers),
                resp.text,
                last_elapsed,
            )

    # ------------------------------------------------------------------
    # Bulk producer/consumer run
    # ------------------------------------------------------------------

    async def run(
        self,
        probes: Iterable[Probe],
        handler: Optional[Callable[[ProbeResult], Awaitable[None]]] = None,
        queue_size: int = 1000,
    ) -> List[ProbeResult]:
        """Dispatch all *probes* through a bounded queue of workers.

        If *handler* is given it is awaited for each result (streaming mode) and
        an empty list is returned; otherwise every result is collected and
        returned.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        results: List[ProbeResult] = []
        collect = handler is None

        async def producer() -> None:
            for probe in probes:
                await queue.put(probe)
            for _ in range(self.concurrency):
                await queue.put(None)

        async def worker() -> None:
            while True:
                probe = await queue.get()
                try:
                    if probe is None:
                        return
                    result = await self.send(probe)
                    if collect:
                        results.append(result)
                    else:
                        await handler(result)  # type: ignore[misc]
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        prod = asyncio.create_task(producer())
        try:
            await asyncio.gather(prod, *workers)
        except asyncio.CancelledError:
            for task in workers:
                task.cancel()
            prod.cancel()
            raise
        return results
