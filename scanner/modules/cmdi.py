"""OS Command Injection detection module.

Detection strategy:
  1. Time-based  -- inject sleep/ping/timeout commands and measure response delay.
  2. Output-based -- inject commands whose output (e.g. /etc/passwd markers, echo
     tokens) is identifiable in the HTTP response body.

Both append-mode (suffix after original value) and replace-mode are tested to
cover both quoted-string and bare-value contexts in backend code.
"""

import re
import time
from typing import Dict, List, Optional, Tuple

import logging

from .base import BaseModule, Finding
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

# Unique token used for echo-based detection
_ECHO_TOKEN = "okrscann7x3q"

# (payload, description) -- output-based
_OUTPUT_PAYLOADS: List[Tuple[str, str]] = [
    # Unix
    (f"; echo {_ECHO_TOKEN}", "semicolon + echo (Unix)"),
    (f"| echo {_ECHO_TOKEN}", "pipe + echo (Unix)"),
    (f"|| echo {_ECHO_TOKEN}", "or-pipe + echo (Unix)"),
    (f"& echo {_ECHO_TOKEN}", "background + echo (Unix)"),
    (f"&& echo {_ECHO_TOKEN}", "and + echo (Unix)"),
    (f"`echo {_ECHO_TOKEN}`", "backtick + echo (Unix)"),
    (f"$(echo {_ECHO_TOKEN})", "subshell + echo (Unix)"),
    ("; cat /etc/passwd", "semicolon + cat passwd"),
    ("| cat /etc/passwd", "pipe + cat passwd"),
    # Windows
    (f"& echo {_ECHO_TOKEN}", "background + echo (Windows)"),
    (f"| echo {_ECHO_TOKEN}", "pipe + echo (Windows)"),
    (f"&& echo {_ECHO_TOKEN}", "and + echo (Windows)"),
]

# (template with {delay}, OS hint) -- time-based
_TIME_PAYLOADS: List[Tuple[str, str]] = [
    ("; sleep {delay}", "Unix"),
    ("| sleep {delay}", "Unix"),
    ("|| sleep {delay}", "Unix"),
    ("& sleep {delay} &", "Unix"),
    ("&& sleep {delay}", "Unix"),
    ("`sleep {delay}`", "Unix"),
    ("$(sleep {delay})", "Unix"),
    ("| ping -c {delay} 127.0.0.1", "Unix/ping"),
    ("& timeout /T {delay} /NOBREAK >nul", "Windows"),
    ("| timeout /T {delay} /NOBREAK >nul", "Windows"),
    ("& ping -n {delay} 127.0.0.1 >nul", "Windows/ping"),
]

_PASSWD_SIGS = [
    r"root:x?:0:0:",
    r"\w+:\w*:\d+:\d+:",
]


class CommandInjectionScanner(BaseModule):
    """Detects OS command injection via output-based and time-based payloads."""

    NAME = "cmdi"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self.delay = float(config.get("delay_threshold", 5.0))
        self.custom_payloads: Optional[str] = config.get("custom_payloads")

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Run output-based then time-based command injection checks."""
        finding = (
            self._test_output_based(url, method, params, param_name)
            or self._test_time_based(url, method, params, param_name)
        )
        return [finding] if finding else []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, url: str, method: str, params: Dict[str, str]):
        if method == "GET":
            return self.http.get(rebuild_url_with_params(url, params))
        return self.http.post(url, data=params)

    def _append(self, params: Dict, name: str, suffix: str) -> Dict:
        return {**params, name: params.get(name, "") + suffix}

    # ------------------------------------------------------------------
    # Output-based detection
    # ------------------------------------------------------------------

    def _test_output_based(
        self, url, method, params, param_name,
    ) -> Optional[Finding]:
        for payload, desc in _OUTPUT_PAYLOADS:
            # Append mode
            resp = self._send(url, method, self._append(params, param_name, payload))
            if resp is None:
                continue

            body = resp.text

            # Check for echo token
            if _ECHO_TOKEN in body:
                full_payload = f"{params.get(param_name, '')}{payload}"
                curl = build_curl_command(url, method, params, param_name, full_payload)
                logger.debug("[CMDi/Output] %s: echo token found (%s)", param_name, desc)
                return Finding(
                    vuln_type="OS Command Injection (Output-based)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=full_payload,
                    evidence=f"Echo token '{_ECHO_TOKEN}' reflected in response ({desc})",
                    confidence="high",
                    details=(
                        f"Command injection via {desc}. Injected command output appears "
                        "in the HTTP response. Remediation: never pass user input to "
                        "shell commands; use language-native APIs instead of system()."
                    ),
                    reproduction=(
                        f"# 1. Inject the command and look for the token in the response:\n"
                        f"{curl}\n"
                        f"# 2. Search for '{_ECHO_TOKEN}' in the output.\n"
                        f"#    If present, the server executed your echo command.\n"
                        f"# 3. Escalate with 'id' or 'whoami' to prove RCE:\n"
                        f"{build_curl_command(url, method, params, param_name, params.get(param_name, '') + '; id')}\n"
                        f"# 4. Look for output like 'uid=33(www-data)' to confirm OS access."
                    ),
                )

            # Check for /etc/passwd signatures
            if "passwd" in payload.lower():
                for sig in _PASSWD_SIGS:
                    if re.search(sig, body):
                        logger.debug("[CMDi/Output] %s: passwd content found (%s)", param_name, desc)
                        full_pl = f"{params.get(param_name, '')}{payload}"
                        curl = build_curl_command(url, method, params, param_name, full_pl)
                        return Finding(
                            vuln_type="OS Command Injection (Output-based)",
                            url=url,
                            method=method,
                            parameter=param_name,
                            payload=full_pl,
                            evidence=f"/etc/passwd content detected in response ({desc})",
                            confidence="high",
                            details=(
                                "Command injection reading /etc/passwd. "
                                "Remediation: avoid system() / exec(); validate all inputs."
                            ),
                            reproduction=(
                                f"# 1. Send the payload to read /etc/passwd:\n"
                                f"{curl}\n"
                                f"# 2. Look for 'root:x:0:0:' in the response body.\n"
                                f"#    If present, the server executed 'cat /etc/passwd'.\n"
                                f"# 3. Confirm with 'id' command:\n"
                                f"{build_curl_command(url, method, params, param_name, params.get(param_name, '') + '; id')}"
                            ),
                        )
        return None

    # ------------------------------------------------------------------
    # Time-based detection
    # ------------------------------------------------------------------

    def _test_time_based(
        self, url, method, params, param_name,
    ) -> Optional[Finding]:
        t0 = time.perf_counter()
        baseline = self._send(url, method, params)
        baseline_time = time.perf_counter() - t0
        if baseline is None:
            return None

        delay_sec = int(self.delay)

        for template, os_hint in _TIME_PAYLOADS:
            suffix = template.format(delay=delay_sec)
            t0 = time.perf_counter()
            resp = self._send(url, method, self._append(params, param_name, suffix))
            elapsed = time.perf_counter() - t0

            if resp is None:
                continue

            if elapsed >= self.delay and elapsed >= (baseline_time + self.delay * 0.8):
                display = f"{params.get(param_name, '')}{suffix}"
                logger.debug(
                    "[CMDi/Time] %s=%r elapsed=%.2fs baseline=%.2fs (%s)",
                    param_name, display, elapsed, baseline_time, os_hint,
                )
                curl = build_curl_command(url, method, params, param_name, display)
                return Finding(
                    vuln_type="OS Command Injection (Time-based)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=display,
                    evidence=(
                        f"Response delayed {elapsed:.2f}s with {delay_sec}s sleep "
                        f"(baseline: {baseline_time:.2f}s, OS: {os_hint})"
                    ),
                    confidence="medium",
                    details=(
                        f"Time-based command injection ({os_hint}). "
                        "Remediation: never pass user input to shell commands."
                    ),
                    reproduction=(
                        f"# 1. Measure baseline response time:\n"
                        f"$ time {build_curl_command(url, method, params, param_name, params.get(param_name, '')).lstrip('$ ')}\n"
                        f"# 2. Send the sleep payload and measure:\n"
                        f"$ time {curl.lstrip('$ ')}\n"
                        f"# 3. If the second request takes ~{delay_sec}s longer,\n"
                        f"#    it confirms time-based command injection ({os_hint})."
                    ),
                )
        return None
