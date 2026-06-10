"""IDOR (Insecure Direct Object Reference) detection module.

Detects endpoints where changing an object identifier — numeric ID or UUID —
in query/POST parameters or URL path segments exposes resources belonging to
other users/objects without authorisation checks.

Detection strategies
--------------------
1. Parameter-based (numeric): query/POST params with integer values.
2. Parameter-based (UUID): params whose value is a UUID v4.
3. Path-based: numeric segments in the URL path (e.g. /api/users/123/).

For each candidate identifier the scanner:
  a. Records a stable baseline for the original ID (dual-request stability check).
  b. Probes with ID ± 1 and ID + 2.
  c. For UUIDs: probes with 3 random UUIDs.
  d. Reports a finding when a probe returns HTTP 200 with substantive content
     that is structurally similar in size but differs in content from baseline.

Confidence
----------
high   – Two or more adjacent IDs each return a distinct 200 response.
medium – One adjacent/random ID returns a different valid 200 response.

False-positive guards
---------------------
- Dual-baseline stability: if two requests to the same ID return differently-
  sized responses the page is dynamic (ads/nonces/timestamps) → skip.
- Identical-response guard: probes returning the exact same body as baseline
  are ignored (server treats the parameter as irrelevant).
- Tiny-body guard: responses under 100 bytes are rejected.
- Size-similarity gate: probe response must be within ±60 % of baseline size
  (same type of resource, not a redirect page or error stub).
"""

import hashlib
import re
import uuid as _uuid_mod
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urlencode

import logging

from .base import BaseModule, Finding
from ..parser import rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_NUMERIC_RE = re.compile(r'^\d{1,15}$')
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

_TINY_BODY = 100          # bytes
_SIZE_TOLERANCE = 0.60    # probe size must be within ±60 % of baseline
_DYNAMIC_DRIFT = 0.10     # >10 % drift between two identical requests → dynamic page


def _md5(text: str) -> str:
    return hashlib.md5(text.encode(errors="replace")).hexdigest()


class IDORScanner(BaseModule):
    """Detect Insecure Direct Object Reference vulnerabilities."""

    NAME = "idor"

    def __init__(self, http_client: Any, config: Dict) -> None:
        super().__init__(http_client, config)
        # Track (method, url) pairs already tested for path-based IDOR
        # to avoid redundant work when scan_parameter is called multiple times
        # for the same URL (once per query param).
        self._path_tested: set = set()

    # ------------------------------------------------------------------
    # HTTP helper (matches pattern used by sqli, ssti, cmdi, crlf)
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method.upper() == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _send_url(self, full_url: str, method: str, params: Dict[str, str]):
        """Send a request where the full URL is already built (path-based probes)."""
        if method.upper() == "GET":
            return self.http.get(full_url)
        return self.http.post(full_url, data=params)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        value = params.get(param_name, "")

        # --- 1. Parameter-based: numeric ID ---
        if _NUMERIC_RE.match(value):
            f = self._test_numeric_param(url, method, params, param_name, int(value))
            if f:
                findings.append(f)

        # --- 2. Parameter-based: UUID ---
        elif _UUID_RE.match(value):
            f = self._test_uuid_param(url, method, params, param_name, value)
            if f:
                findings.append(f)

        # --- 3. Path-based (tested once per URL) ---
        url_key = f"{method.upper()}:{url}"
        if url_key not in self._path_tested:
            self._path_tested.add(url_key)
            findings.extend(self._test_path_segments(url, method, params))

        return findings

    # ------------------------------------------------------------------
    # Strategy 1: numeric parameter
    # ------------------------------------------------------------------

    def _test_numeric_param(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        original_id: int,
    ) -> Optional[Finding]:
        baseline = self._send(url, method, params)
        if not self._valid_baseline(baseline):
            return None

        baseline_size = len(baseline.text)
        baseline_hash = _md5(baseline.text)

        if not self._page_is_stable(url, method, params, baseline_size):
            logger.debug("[IDOR] %s=%d: dynamic page, skipping", param_name, original_id)
            return None

        probe_ids = _adjacent_ids(original_id)
        hits = self._probe_numeric(
            url, method, params, param_name, probe_ids, baseline_size, baseline_hash
        )
        if not hits:
            return None

        confidence = "high" if len(hits) >= 2 else "medium"
        hit_id, hit_size = hits[0]
        probe_params = {**params, param_name: str(hit_id)}

        return Finding(
            vuln_type="IDOR",
            url=url,
            method=method,
            parameter=param_name,
            payload=str(hit_id),
            evidence=(
                f"ID {original_id} → {hit_id}: different 200 responses "
                f"({baseline_size} B vs {hit_size} B) — "
                f"{len(hits)} adjacent ID(s) returned accessible resources"
            ),
            confidence=confidence,
            details=(
                f"Parameter {param_name!r} controls direct object access. "
                f"Adjacent IDs return distinct resources without apparent "
                f"authorisation check.\n"
                f"Accessible IDs found: {[h[0] for h in hits]}"
            ),
            reproduction=(
                f"# Baseline (original object):\n"
                f"$ curl '{url}?{urlencode({**params, param_name: str(original_id)})}'\n\n"
                f"# Probe (adjacent object — potentially unauthorized):\n"
                f"$ curl '{url}?{urlencode(probe_params)}'\n\n"
                f"# Enumerate objects in range:\n"
                f"$ for id in $(seq 1 20); do\n"
                f"    echo -n \"ID $id: \"\n"
                f"    curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}\\n' "
                f"'{url}?{param_name}='\"$id\"\n"
                f"  done"
            ),
        )

    def _probe_numeric(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        probe_ids: List[int],
        baseline_size: int,
        baseline_hash: str,
    ) -> List[Tuple[int, int]]:
        hits = []
        for pid in probe_ids:
            resp = self._send(url, method, {**params, param_name: str(pid)})
            if resp is None or resp.status_code != 200:
                continue
            rsize = len(resp.text)
            if rsize < _TINY_BODY:
                continue
            if _md5(resp.text) == baseline_hash:
                continue  # identical → server ignores the param
            if not _size_similar(baseline_size, rsize):
                continue
            hits.append((pid, rsize))
        return hits

    # ------------------------------------------------------------------
    # Strategy 2: UUID parameter
    # ------------------------------------------------------------------

    def _test_uuid_param(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        original_uuid: str,
    ) -> Optional[Finding]:
        baseline = self._send(url, method, params)
        if not self._valid_baseline(baseline):
            return None

        baseline_size = len(baseline.text)
        baseline_hash = _md5(baseline.text)

        if not self._page_is_stable(url, method, params, baseline_size):
            return None

        for _ in range(3):
            random_uuid = str(_uuid_mod.uuid4())
            resp = self._send(url, method, {**params, param_name: random_uuid})
            if resp is None or resp.status_code != 200:
                continue
            rsize = len(resp.text)
            if rsize < _TINY_BODY:
                continue
            if _md5(resp.text) == baseline_hash:
                continue
            if not _size_similar(baseline_size, rsize):
                continue

            return Finding(
                vuln_type="IDOR",
                url=url,
                method=method,
                parameter=param_name,
                payload=random_uuid,
                evidence=(
                    f"Random UUID returned a different 200 response "
                    f"({baseline_size} B vs {rsize} B) — "
                    f"UUID {original_uuid!r} may not enforce ownership"
                ),
                confidence="medium",
                details=(
                    f"UUID parameter {param_name!r} returned a valid response "
                    f"for a random UUID. This may indicate that any UUID resolves "
                    f"to a resource without authorisation validation."
                ),
                reproduction=(
                    f"# Original:\n"
                    f"$ curl '{url}?{urlencode(params)}'\n\n"
                    f"# Random UUID (also returned 200):\n"
                    f"$ curl '{url}?{param_name}={random_uuid}'"
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Strategy 3: path-segment IDOR
    # ------------------------------------------------------------------

    def _test_path_segments(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        findings: List[Finding] = []

        for seg_idx, segment in enumerate(segments):
            if not _NUMERIC_RE.match(segment):
                continue
            original_id = int(segment)

            def _build_url(new_id: int, _segs=segments, _idx=seg_idx, _parsed=parsed) -> str:
                new_segs = _segs[:]
                new_segs[_idx] = str(new_id)
                return urlunparse(_parsed._replace(path="/".join(new_segs)))

            baseline_url = _build_url(original_id)
            baseline = self._send_url(baseline_url, method, params)
            if not self._valid_baseline(baseline):
                continue

            baseline_size = len(baseline.text)
            baseline_hash = _md5(baseline.text)

            # Stability check using baseline_url
            r2 = self._send_url(baseline_url, method, params)
            if r2 is None or baseline_size == 0:
                continue
            if abs(len(r2.text) - baseline_size) / baseline_size > _DYNAMIC_DRIFT:
                continue

            probe_ids = _adjacent_ids(original_id)
            hits: List[Tuple[int, int, str]] = []
            for pid in probe_ids:
                probe_url = _build_url(pid)
                resp = self._send_url(probe_url, method, params)
                if resp is None or resp.status_code != 200:
                    continue
                rsize = len(resp.text)
                if rsize < _TINY_BODY:
                    continue
                if _md5(resp.text) == baseline_hash:
                    continue
                if not _size_similar(baseline_size, rsize):
                    continue
                hits.append((pid, rsize, probe_url))

            if not hits:
                continue

            confidence = "high" if len(hits) >= 2 else "medium"
            hit_id, hit_size, hit_url = hits[0]
            enumerate_base = _build_url(0).replace("/0", "")

            findings.append(Finding(
                vuln_type="IDOR",
                url=url,
                method=method,
                parameter=f"path[{seg_idx}] (/{segment}/)",
                payload=str(hit_id),
                evidence=(
                    f"Path /{segment}/ → /{hit_id}/: different 200 responses "
                    f"({baseline_size} B vs {hit_size} B)"
                ),
                confidence=confidence,
                details=(
                    f"URL path segment at index {seg_idx} (value {segment!r}) "
                    f"controls direct object access. Modifying it returns distinct "
                    f"resources without apparent authorisation check.\n"
                    f"Accessible IDs found: {[h[0] for h in hits]}"
                ),
                reproduction=(
                    f"# Baseline:\n"
                    f"$ curl '{baseline_url}'\n\n"
                    f"# Probe (potentially unauthorized):\n"
                    f"$ curl '{hit_url}'\n\n"
                    f"# Enumerate path IDs:\n"
                    f"$ for id in $(seq 1 20); do\n"
                    f"    echo -n \"/$id/: \"\n"
                    f"    curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}\\n' "
                    f"'{enumerate_base}/$id'\n"
                    f"  done"
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _valid_baseline(self, resp) -> bool:
        return (
            resp is not None
            and resp.status_code == 200
            and len(resp.text) >= _TINY_BODY
        )

    def _page_is_stable(
        self, url: str, method: str, params: Dict, baseline_size: int
    ) -> bool:
        r2 = self._send(url, method, params)
        if r2 is None or baseline_size == 0:
            return False
        drift = abs(len(r2.text) - baseline_size) / baseline_size
        return drift <= _DYNAMIC_DRIFT


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _adjacent_ids(original: int) -> List[int]:
    ids = []
    if original > 1:
        ids.append(original - 1)
    ids.append(original + 1)
    ids.append(original + 2)
    return ids


def _size_similar(size_a: int, size_b: int) -> bool:
    if size_a == 0:
        return False
    return abs(size_a - size_b) / size_a <= _SIZE_TOLERANCE
