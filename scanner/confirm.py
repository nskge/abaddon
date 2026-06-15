"""Confirmation primitives for false-positive reduction.

Inspired by Nuclei's ``matchers-condition: and`` philosophy: a single positive
signal is a *candidate*, not a finding.  Before a module emits a Finding it
should corroborate the signal with an independent, harder-to-fake observation.

This module is deliberately transport-agnostic.  Callers pass in small
closures (``measure`` / ``probe``) so the same confirmation logic works for any
HTTP method, injection mode (append/replace), or payload template.

Two primitives are provided:

* :func:`confirm_time_based` -- differential timing.  Re-issues a blind
  time-based payload with a *larger* sleep and requires the measured delay to
  scale proportionally.  Random network jitter produces one anomalous sample,
  never two correlated, proportional ones, so this kills the dominant source of
  time-based false positives.

* :func:`confirm_repeated` -- signal stability.  Re-issues a boolean/content
  probe N times and requires the signal to reproduce every time.  Dynamic pages
  (ads, nonces, timestamps) won't reproduce the same delta twice.
"""

from typing import Callable, Optional, Tuple

import logging

logger = logging.getLogger("vulnscanner")


def confirm_time_based(
    measure: Callable[[float], Optional[float]],
    base_delay: float,
    first_elapsed: float,
    baseline_avg: float,
    *,
    factor: float = 2.0,
    tolerance: float = 0.6,
    slope_ratio: float = 0.5,
) -> Tuple[bool, Optional[float]]:
    """Confirm a candidate time-based hit by re-testing with a larger sleep.

    A genuinely injectable ``SLEEP(n)`` scales with ``n``: doubling the
    requested delay must add roughly ``base_delay`` extra seconds to the
    response time.  A one-off slow response (cache miss, GC pause, transient
    congestion) will not reproduce a *proportional* second delay.

    Args:
        measure:       Callable that injects a sleep of ``delay`` seconds and
                       returns the observed response time in seconds, or
                       ``None`` if the request failed.
        base_delay:    The sleep duration (seconds) used by the first payload.
        first_elapsed: Response time observed for the first payload.
        baseline_avg:  Mean baseline response time (no payload).
        factor:        Multiplier for the confirmation sleep (default 2x).
        tolerance:     Fraction of the larger sleep that must be observed above
                       baseline for the confirmation to count (default 0.6).
        slope_ratio:   The confirmation must be slower than the first sample by
                       at least ``base_delay * slope_ratio`` seconds, proving the
                       delay tracks the injected sleep (default 0.5).

    Returns:
        ``(confirmed, second_elapsed)``.  ``second_elapsed`` is ``None`` when
        the confirmation request failed.
    """
    second_delay = base_delay * factor
    second_elapsed = measure(second_delay)
    if second_elapsed is None:
        logger.debug("[confirm/time] confirmation request failed — not confirming")
        return False, None

    # The larger sleep must clearly exceed baseline (accounts for ~factor*delay).
    scaled_threshold = baseline_avg + second_delay * tolerance
    # The extra (factor-1)*base_delay of sleep must actually show up as more time.
    slope_ok = (second_elapsed - first_elapsed) >= base_delay * slope_ratio

    confirmed = second_elapsed >= scaled_threshold and slope_ok
    logger.debug(
        "[confirm/time] base=%.1fs first=%.2fs second(%.1fs)=%.2fs "
        "threshold=%.2fs slope_ok=%s -> %s",
        base_delay, first_elapsed, second_delay, second_elapsed,
        scaled_threshold, slope_ok, "CONFIRMED" if confirmed else "rejected",
    )
    return confirmed, second_elapsed


def confirm_repeated(
    probe: Callable[[], bool],
    *,
    attempts: int = 1,
) -> bool:
    """Confirm a boolean signal by reproducing it ``attempts`` more times.

    Returns ``True`` only if every additional probe also returns ``True``.
    Used to discard candidates that don't survive a re-test (the hallmark of a
    dynamic-page false positive).
    """
    for i in range(attempts):
        if not probe():
            logger.debug("[confirm/repeat] signal not reproduced on retry %d — rejecting", i + 1)
            return False
    return True
