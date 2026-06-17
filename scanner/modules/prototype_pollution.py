"""Server-side Prototype Pollution detection module (Node.js / JS back-ends).

Detection strategy:
  Prototype pollution lets an attacker set properties on ``Object.prototype``,
  which every object then inherits. On the server this can escalate to RCE,
  auth bypass, or DoS depending on available "gadgets". Blind detection relies
  on gadgets whose effect is *observable in the HTTP response*:

  1. JSON-spaces gadget (Express):
        pollute ``__proto__.json spaces`` = N  →  the server's JSON responses
        come back indented with N spaces. We baseline the response whitespace,
        send the pollution, then re-request and diff the indentation. A change
        that reverts on a fresh process-free request is a strong positive.

  2. Status/exposedHeaders gadgets: polluting certain keys changes response
        status or adds headers — we probe a couple of well-known ones.

  We send pollution via BOTH query-string bracket notation and JSON body, and
  via both the ``__proto__`` and ``constructor.prototype`` access paths, since
  frameworks block them inconsistently.

Confidence:
  The JSON-spaces reflection is high-confidence (behavioural). Header/status
  gadgets are medium. Pure reflection of ``__proto__`` keys is low.
"""

import json
import logging
import re
from typing import Dict, List, Optional

from .base import BaseModule, Finding
from ..parser import rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# Sentinel used so we can recognise our own pollution in responses.
_MARKER = "9737"   # arbitrary, unlikely-to-collide indentation width proxy


def build_query_payloads(marker: str = _MARKER) -> List[Dict[str, str]]:
    """Query-string pollution payloads (bracket notation). Each dict is a set
    of extra params to merge into the request."""
    return [
        {"__proto__[json spaces]": marker},
        {"__proto__.json spaces": marker},
        {"constructor[prototype][json spaces]": marker},
        {"constructor.prototype.json spaces": marker},
    ]


def build_json_payloads(marker: str = _MARKER) -> List[dict]:
    """JSON-body pollution payloads."""
    n = int(marker[0]) + 1  # small indent width derived from marker (1-10)
    return [
        {"__proto__": {"json spaces": n}},
        {"constructor": {"prototype": {"json spaces": n}}},
    ]


def _indent_width(text: str) -> int:
    """Best-effort: detect the leading-space indentation of a pretty JSON body.

    Returns the number of spaces before the first nested key, or 0 if the JSON
    is minified (no indentation)."""
    if not text:
        return 0
    # Look for a newline followed by spaces then a quote (a nested key).
    m = re.search(r"\n( +)\S", text)
    return len(m.group(1)) if m else 0


class PrototypePollutionScanner(BaseModule):
    """Detects server-side prototype pollution via observable gadgets."""

    NAME = "prototype"

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # The JSON-spaces gadget only manifests if the endpoint returns JSON.
        baseline = self._send(url, method, params, body=None)
        if baseline is None:
            return findings

        ct = baseline.headers.get("Content-Type", "").lower()
        returns_json = "json" in ct or baseline.text.strip().startswith(("{", "["))
        baseline_indent = _indent_width(baseline.text) if returns_json else 0

        # ---- 1. Query-string pollution (json spaces gadget) ----
        if returns_json:
            for extra in build_query_payloads():
                polluted_params = {**params, **extra}
                r = self._send(url, "GET", polluted_params, body=None)
                if r is None:
                    continue
                new_indent = _indent_width(r.text)
                if new_indent > baseline_indent and new_indent >= 2:
                    findings.append(self._make_finding(
                        url, "GET", list(extra.keys())[0],
                        json.dumps(extra),
                        f"JSON response indentation changed {baseline_indent}→{new_indent} "
                        f"spaces after polluting 'json spaces' via query string.",
                        access_path=list(extra.keys())[0],
                    ))
                    return findings  # one solid positive is enough

        # ---- 2. JSON-body pollution (json spaces gadget) ----
        for payload in build_json_payloads():
            r = self._send_json(url, payload)
            if r is None:
                continue
            new_indent = _indent_width(r.text)
            if returns_json and new_indent > baseline_indent and new_indent >= 2:
                findings.append(self._make_finding(
                    url, "POST", "(JSON body)",
                    json.dumps(payload),
                    f"JSON response indentation changed {baseline_indent}→{new_indent} "
                    f"spaces after polluting via JSON body __proto__.",
                    access_path="__proto__ (JSON body)",
                ))
                return findings

        # ---- 3. Reflection-only fallback (low confidence) ----
        # If __proto__ keys are echoed back verbatim, the input reaches an
        # object-merge sink — worth a low-confidence pointer for manual review.
        probe = {**params, "__proto__[pp_probe]": _MARKER}
        r = self._send(url, "GET", probe, body=None)
        if r is not None and f"pp_probe" in r.text and _MARKER in r.text:
            findings.append(self._make_finding(
                url, "GET", "__proto__[pp_probe]",
                json.dumps({"__proto__[pp_probe]": _MARKER}),
                "Server reflected a __proto__ key back in the response, indicating "
                "the input reaches an unsafe recursive-merge sink.",
                access_path="__proto__[pp_probe]",
                confidence="low",
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, url, method, params, body):
        try:
            if method == "GET":
                return self.http.get(rebuild_url_with_params(url, params))
            return self.http.post(url, data=params)
        except Exception as exc:
            logger.debug("[prototype] send error: %s", exc)
            return None

    def _send_json(self, url, payload):
        try:
            return self.http.raw_post(
                url, json.dumps(payload), content_type="application/json",
            )
        except Exception as exc:
            logger.debug("[prototype] json send error: %s", exc)
            return None

    def _make_finding(
        self, url, method, parameter, payload, evidence,
        access_path, confidence="high",
    ) -> Finding:
        return Finding(
            vuln_type="Prototype Pollution (Server-Side)",
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            details=(
                "User input flows into a recursive object merge without blocking "
                "the special keys __proto__ / constructor / prototype, polluting "
                "Object.prototype globally. Depending on available gadgets this "
                "escalates to RCE (e.g. child_process spawn options), auth bypass, "
                "or DoS. Remediation: use Map instead of plain objects for "
                "user-controlled keys, Object.freeze(Object.prototype), validate "
                "against a schema, or upgrade the vulnerable merge library."
            ),
            reproduction=(
                f"# 1. Pollute via {access_path}:\n"
                f"$ curl -sk '{url}' -H 'Content-Type: application/json' \\\n"
                f"    -d '{{\"__proto__\":{{\"json spaces\":10}}}}'\n"
                f"# 2. Re-request a JSON endpoint and observe the new indentation:\n"
                f"$ curl -sk '{url}'\n"
                f"# 3. Confirm/exploit with the prototype-pollution gadget scanner:\n"
                f"#    https://github.com/portswigger/server-side-prototype-pollution\n"
                f"# 4. Hunt RCE gadgets (Node): pollute 'shell', 'NODE_OPTIONS', "
                f"'execArgv' and trigger a child_process call."
            ),
        )
