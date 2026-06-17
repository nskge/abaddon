"""Race-condition (TOCTOU / limit-overrun) detection module.

Many security controls assume requests are processed one at a time: "redeem
this coupon once", "withdraw up to your balance", "one vote per user". When the
check and the action aren't atomic, firing many identical requests in the same
instant can slip several past the check before any of them commits — the
single-packet / last-byte-sync attack popularised by PortSwigger.

Detection strategy (opt-in, intrusive):
  1. Warm up with one sequential request to learn the "normal" response.
  2. Fire a tight concurrent burst of identical requests (all dispatched before
     any completes, mimicking the single-packet technique with threads).
  3. If the burst yields a DIFFERENT distribution of outcomes than the
     sequential baseline — e.g. several "success" responses where the control
     should allow one, or a mix of success/conflict statuses — that's the
     fingerprint of a non-atomic check.

This module is OPT-IN (own scan-type or --aggressive) because it sends repeated
state-changing requests. Findings are reported for manual confirmation, never as
proven exploits, since only the application owner knows the intended limit.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseModule, Finding
from ..parser import rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# How many identical requests to fire in the burst.
_BURST = 20
# Endpoints/params that look state-changing are the only ones worth racing.
_STATEFUL_HINTS = (
    "coupon", "voucher", "promo", "discount", "gift", "redeem", "claim",
    "balance", "withdraw", "transfer", "amount", "qty", "quantity",
    "vote", "like", "follow", "invite", "referral", "register", "signup",
    "apply", "purchase", "order", "checkout", "cart", "token", "otp", "code",
)


def looks_stateful(url: str, method: str, params: Dict[str, str]) -> bool:
    """Heuristic: only race endpoints that plausibly mutate limited state.

    Pure function — keeps the burst off read-only pages (no point, and it'd be
    noisy). POST is the strong signal; GET needs an action-like param name."""
    blob = (url + " " + " ".join(params.keys())).lower()
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return any(h in blob for h in _STATEFUL_HINTS)


def analyze_burst(
    baseline: Tuple[int, int],
    burst: List[Tuple[int, int]],
) -> Optional[str]:
    """Decide whether *burst* shows a race signal vs the *baseline* (status,len).

    Returns a human-readable signal description, or None. Pure + testable.

    Signal = the concurrent burst produced an outcome the single sequential
    request did not: either multiple distinct status codes, or a cluster of
    "success-like" responses that matches baseline where we'd expect the limit
    to reject all but one.
    """
    if not burst:
        return None
    base_status, base_len = baseline
    statuses = Counter(s for s, _ in burst)

    # Mixed statuses in the burst (e.g. 200s AND 409/429) → non-atomic handling.
    if len(statuses) > 1:
        # Only interesting if at least one matches the baseline success.
        if base_status in statuses:
            mix = ", ".join(f"{c}×{s}" for s, c in statuses.most_common())
            return f"burst returned mixed outcomes ({mix}) vs a single {base_status} baseline"

    # All-success burst: every concurrent request succeeded like the baseline.
    # For a once-only action this is the overrun fingerprint (worth manual check).
    base_success = base_status < 400
    n_base_like = sum(1 for s, _ in burst if s == base_status)
    if base_success and n_base_like >= max(3, int(len(burst) * 0.6)):
        # Response-length variance hints the server processed them differently.
        lengths = {l for _, l in burst}
        var_note = " with varying response sizes" if len(lengths) > 1 else ""
        return (
            f"{n_base_like}/{len(burst)} concurrent requests all succeeded "
            f"({base_status}){var_note} — if this endpoint enforces a one-time "
            f"limit, it is not atomic"
        )
    return None


class RaceConditionScanner(BaseModule):
    """Detects non-atomic limit checks via a concurrent request burst."""

    NAME = "race"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self._raced: set = set()

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        if not looks_stateful(url, method, params):
            return []
        # Once per (url, method) — racing the same endpoint per-param is wasteful.
        key = (url, method)
        if key in self._raced:
            return []
        self._raced.add(key)

        baseline = self._send(url, method, params)
        if baseline is None:
            return []
        base_tuple = (baseline.status_code, len(baseline.text))

        burst = self._fire_burst(url, method, params)
        signal = analyze_burst(base_tuple, burst)
        if not signal:
            return []

        statuses = Counter(s for s, _ in burst)
        dist = ", ".join(f"{c}×HTTP{s}" for s, c in statuses.most_common())
        return [Finding(
            vuln_type="Race Condition (potential limit-overrun)",
            url=url,
            method=method,
            parameter=param_name,
            payload=f"{_BURST} concurrent identical requests",
            evidence=f"{signal}. Burst distribution: {dist}.",
            confidence="low",
            details=(
                "A concurrent burst of identical requests produced an outcome a "
                "single request did not, which is the fingerprint of a non-atomic "
                "check-then-act (TOCTOU). If this endpoint enforces a one-time or "
                "balance-limited action, an attacker may exceed it (double-spend a "
                "coupon, overdraw a balance, bypass a rate limit). Confirm manually "
                "— only the app owner knows the intended limit. Remediation: enforce "
                "limits atomically (DB unique constraint, SELECT … FOR UPDATE, "
                "optimistic locking, idempotency keys)."
            ),
            reproduction=(
                f"# Reproduce with Turbo Intruder (single-packet attack) in Burp:\n"
                f"#   send {_BURST} copies of the request on one connection, gate-synced.\n"
                f"# Or with curl in parallel:\n"
                f"$ for i in $(seq 1 {_BURST}); do curl -s -o /dev/null -w '%{{http_code}}\\n' "
                f"'{rebuild_url_with_params(url, params) if method == 'GET' else url}' & done; wait | sort | uniq -c\n"
                f"# Compare success count to the intended limit (e.g. 1 coupon use)."
            ),
        )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method.upper() == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _fire_burst(self, url, method, params) -> List[Tuple[int, int]]:
        """Dispatch _BURST identical requests as simultaneously as threads allow.

        We pre-build the request and release all threads at once to compress the
        send window (a thread-based approximation of the single-packet attack)."""
        results: List[Tuple[int, int]] = []

        def _one(_):
            r = self._send(url, method, params)
            return (r.status_code, len(r.text)) if r is not None else None

        with ThreadPoolExecutor(max_workers=_BURST) as pool:
            for res in pool.map(_one, range(_BURST)):
                if res is not None:
                    results.append(res)
        return results
