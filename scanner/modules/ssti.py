"""Server-Side Template Injection (SSTI) detection module.

Detection strategy:
  1. Random math probe -- inject arithmetic with random large factors (e.g. {{7331*6271}})
     and verify the EXACT product appears in the response but NOT in the baseline.
  2. String concatenation probes -- detect engines that don't eval math.
  3. Append + replace modes -- covers both quoted-string and bare-value contexts.

False-positive prevention:
  - The expected result (product) is compared against the baseline response.
    If the product already exists in the baseline, the result is discarded.
  - Random factors are chosen per-scan to avoid collisions with static page content.
  - Raw template syntax must NOT appear in the response (that means literal echo, not eval).

References:
  - PortSwigger SSTI research: https://portswigger.net/research/server-side-template-injection
  - PayloadsAllTheThings SSTI cheatsheet
"""

import re
import random
from typing import Dict, List, Optional, Tuple

import logging

from .base import BaseModule, Finding
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")


# ---------------------------------------------------------------------------
# Random probe generation
# ---------------------------------------------------------------------------

def _make_random_probes() -> List[Tuple[str, str, str]]:
    """Generate SSTI math probes with random large factors per scan.

    Using random numbers makes the expected product highly unlikely to already
    appear in the target page, virtually eliminating false positives from
    coincidental numeric strings (UUIDs, phone numbers, static IDs).
    """
    # Two independent random factors — their product is the expected result
    a = random.randint(1009, 9973)   # primes range → large, unlikely to appear naturally
    b = random.randint(1009, 9973)
    prod = str(a * b)

    return [
        (f"{{{{{a}*{b}}}}}", prod, "Jinja2/Twig"),
        (f"${{{a}*{b}}}", prod, "Freemarker/Mako"),
        (f"<%= {a}*{b} %>", prod, "ERB"),
        (f"#set($x={a}*{b})${{x}}", prod, "Velocity"),
        (f"{{{{{a}*{b}}}}}aa", prod, "Jinja2/Pebble (AA marker)"),
        (f"#{{{a}*{b}}}", prod, "Slim/Jade"),
    ]


# String concatenation probes (detect engines that don't eval math)
_CONCAT_PROBES: List[Tuple[str, str, str]] = [
    ("{{'okr'+'scn'}}", "okrscn", "Jinja2"),
    ("${'okr'+'scn'}", "okrscn", "Freemarker"),
    ("<%= 'okr'+'scn' %>", "okrscn", "ERB"),
]


class SSTIScanner(BaseModule):
    """Detects Server-Side Template Injection via math evaluation probes.

    Always compares against the baseline response to avoid false positives
    from static page content containing the expected numeric result.
    """

    NAME = "ssti"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
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
        """Test *param_name* for SSTI.

        Gets baseline first to compare against, eliminating false positives
        from numeric strings (UUIDs, phone numbers, etc.) already on the page.
        """
        findings: List[Finding] = []

        # --- Get baseline BEFORE injecting anything ---
        baseline_resp = self._send(url, method, params)
        baseline_html = baseline_resp.text if baseline_resp is not None else ""

        # Phase 1: random math probes (virtually zero false positives)
        unique_probes = _make_random_probes()
        finding = self._test_probes(
            url, method, params, param_name, unique_probes,
            baseline_html=baseline_html, confidence="high",
        )
        if finding:
            findings.append(finding)
            return findings

        # Phase 2: string concatenation probes
        finding = self._test_probes(
            url, method, params, param_name, _CONCAT_PROBES,
            baseline_html=baseline_html, confidence="medium",
        )
        if finding:
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _test_probes(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        probes: List[Tuple[str, str, str]],
        baseline_html: str,
        confidence: str,
    ) -> Optional[Finding]:
        """Inject each probe and check whether the evaluated result appears."""
        original_value = params.get(param_name, "")

        for payload_tpl, expected, engine in probes:
            # --- append mode (e.g. id=1{{7331*6271}}) ---
            appended = original_value + payload_tpl
            resp = self._send(url, method, inject_into_params(params, param_name, appended))
            if resp is not None:
                confirmed, evidence = self._check_evaluation(
                    resp.text, expected, payload_tpl, original_value, baseline_html,
                )
                if confirmed:
                    logger.debug(
                        "[SSTI] %s=%r -> %s (append, %s)",
                        param_name, appended, expected, engine,
                    )
                    return self._make_finding(
                        url, method, param_name, appended,
                        expected, engine, evidence, confidence,
                    )

            # --- replace mode (e.g. id={{7331*6271}}) ---
            resp = self._send(url, method, inject_into_params(params, param_name, payload_tpl))
            if resp is not None:
                confirmed, evidence = self._check_evaluation(
                    resp.text, expected, payload_tpl, original_value, baseline_html,
                )
                if confirmed:
                    logger.debug(
                        "[SSTI] %s=%r -> %s (replace, %s)",
                        param_name, payload_tpl, expected, engine,
                    )
                    return self._make_finding(
                        url, method, param_name, payload_tpl,
                        expected, engine, evidence, confidence,
                    )

        return None

    @staticmethod
    def _check_evaluation(
        html: str,
        expected: str,
        payload: str,
        original_value: str,
        baseline_html: str,
    ) -> Tuple[bool, str]:
        """Return (True, evidence) only when evaluation is confirmed and NOT a baseline artifact.

        Rules:
          1. The evaluated result (e.g. "9851321") must be in the injected response.
          2. The same result must NOT already be in the baseline response.
             (Prevents false positives from UUIDs, phone numbers, static IDs.)
          3. The raw template expression (e.g. "{{7331*6271}}") must NOT be in the
             response -- if it is, the engine echoed literal text rather than evaluating.
          4. The expected result must not equal the original parameter value.
        """
        if expected == original_value:
            return False, ""

        if expected not in html:
            return False, ""

        # KEY: expected result was already in the page before we injected anything
        if expected in baseline_html:
            logger.debug(
                "[SSTI] skip: expected=%r already in baseline (not an evaluation)",
                expected,
            )
            return False, ""

        # Raw template still visible? Then it was not evaluated.
        if payload in html:
            return False, ""

        # Extract context around the match
        idx = html.index(expected)
        start = max(0, idx - 50)
        end = min(len(html), idx + len(expected) + 50)
        snippet = html[start:end].replace("\n", " ")

        return True, f"Template evaluated: {payload} -> {expected} in response: ...{snippet!r}..."

    def _make_finding(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        expected: str,
        engine: str,
        evidence: str,
        confidence: str,
    ) -> Finding:
        params = {param_name: payload}
        curl = build_curl_command(url, method, params, param_name, payload)
        return Finding(
            vuln_type="Server-Side Template Injection (SSTI)",
            url=url,
            method=method,
            parameter=param_name,
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            details=(
                f"The server evaluates template expressions in parameter {param_name!r}. "
                f"Payload {payload!r} was evaluated to {expected!r} (engine hint: {engine}). "
                f"SSTI can lead to Remote Code Execution (RCE). "
                f"Remediation: never pass user input into template render calls; "
                f"use sandboxed template environments."
            ),
            reproduction=(
                f"# 1. Send the math expression and check if the server evaluates it:\n"
                f"{curl}\n"
                f"# 2. Search for '{expected}' in the response body.\n"
                f"#    If present AND the raw template '{payload}' is NOT present,\n"
                f"#    the server evaluated the expression (SSTI confirmed).\n"
                f"# 3. Engine hint: {engine}. Try escalation payloads:\n"
                f"#    Jinja2 RCE: {{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}\n"
                f"#    Twig RCE:   {{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('id')}}}}"
            ),
        )
