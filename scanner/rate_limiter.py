"""Adaptive rate limiter -- auto-throttles on HTTP 429/503 responses.

The limiter is thread-safe.  All scanner modules share one instance so
back-off triggered by any thread immediately slows the whole session.
"""

import threading
import time


class AdaptiveRateLimiter:
    """Tracks server health signals and injects delays between requests.

    Normal operation:
        - No delay until *burst* requests have been sent.
        - After the burst window, applies *min_delay* between requests.

    On HTTP 429 / 503:
        - Delay doubles (up to *max_delay*).
        - A short hard sleep is injected immediately so all threads back off.

    Recovery:
        - Each successful response shrinks the delay 10% toward *min_delay*.
    """

    def __init__(
        self,
        min_delay: float = 0.0,
        max_delay: float = 15.0,
        burst: int = 8,
    ) -> None:
        self._min = min_delay
        self._max = max_delay
        self._burst = burst

        self._current: float = min_delay
        self._count: int = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def wait(self) -> None:
        """Block if necessary before sending the next request."""
        with self._lock:
            self._count += 1
            if self._count <= self._burst:
                return
            delay = self._current

        if delay > 0:
            time.sleep(delay)

    def record(self, status_code: int) -> None:
        """Update internal delay based on response status."""
        with self._lock:
            if status_code in (429, 503):
                # Exponential back-off
                self._current = min(
                    self._current * 2 if self._current > 0 else 0.5,
                    self._max,
                )
            elif status_code < 400:
                # Gradual recovery
                if self._current > self._min:
                    self._current = max(self._min, self._current * 0.9)

    @property
    def current_delay(self) -> float:
        with self._lock:
            return self._current

    @property
    def requests_sent(self) -> int:
        with self._lock:
            return self._count
