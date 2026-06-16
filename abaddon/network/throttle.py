"""Adaptive throttling — protect the target from accidental DoS.

Two cooperating mechanisms:

* :class:`TokenBucket` — a classic global rate limiter (requests/second).
* :class:`AdaptiveThrottle` — a *per-host* exponential back-off. When a specific
  host starts timing out or returning 429/503 we increase the delay **for that
  host only**, so a single slow target never poisons the whole scan. On success
  the host's delay decays back toward zero.
"""

import asyncio
import time
from typing import Dict


class TokenBucket:
    """Async token-bucket rate limiter. ``rate <= 0`` means unlimited."""

    def __init__(self, rate: float, capacity: float = 0.0) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity) if capacity > 0 else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        if self.rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
            await asyncio.sleep(wait)


class AdaptiveThrottle:
    """Per-host exponential back-off with gradual recovery."""

    def __init__(
        self,
        base_delay: float = 0.0,
        max_delay: float = 10.0,
        backoff: float = 2.0,
        recovery: float = 0.7,
        floor: float = 0.05,
    ) -> None:
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff = backoff
        self.recovery = recovery
        self.floor = floor
        self._delays: Dict[str, float] = {}

    def current_delay(self, host: str) -> float:
        return self._delays.get(host, self.base_delay)

    async def wait(self, host: str) -> None:
        delay = self.current_delay(host)
        if delay > 0:
            await asyncio.sleep(delay)

    def record_failure(self, host: str) -> None:
        """Increase this host's delay (timeout / connect error / 429 / 503)."""
        current = self._delays.get(host, self.base_delay)
        seed = current if current > 0 else 0.1
        self._delays[host] = min(self.max_delay, seed * self.backoff)

    def record_success(self, host: str) -> None:
        """Decay this host's delay back toward zero on a clean response."""
        current = self._delays.get(host)
        if not current:
            return
        decayed = current * self.recovery
        self._delays[host] = decayed if decayed > self.floor else 0.0

    @property
    def throttled_hosts(self) -> int:
        return sum(1 for d in self._delays.values() if d > 0)
