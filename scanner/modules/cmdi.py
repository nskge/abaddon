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
from ..confirm import confirm_time_based
from ..parser import build_curl_command, inject_into_params, rebuild_url_with_params

logger = logging.getLogger("vulnscanner")

import random
import string

def _make_echo_token() -> str:
    """Generate a unique per-scan token that is astronomically unlikely to appear
    naturally in the target page or be a coincidence in search-term reflection."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"okrscann_{suffix}"

def _make_output_payloads(token: str) -> List[Tuple[str, str]]:
    """Build echo-based payloads with the given per-scan token."""
    return [
        # Unix
        (f"; echo {token}", "semicolon + echo (Unix)"),
        (f"| echo {token}", "pipe + echo (Unix)"),
        (f"|| echo {token}", "or-pipe + echo (Unix)"),
        (f"`echo {token}`", "backtick + echo (Unix)"),
        (f"$(echo {token})", "subshell + echo (Unix)"),
        (f"&& echo {token}", "and + echo (Unix)"),
        ("; cat /etc/passwd", "semicolon + cat passwd"),
        ("| cat /etc/passwd", "pipe + cat passwd"),
        # Windows
        (f"& echo {token}", "background + echo (Windows/Unix)"),
        (f"&& echo {token}", "and + echo (Windows)"),
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
        # Generate a unique per-scan token to minimise collision with page content
        echo_token = _make_echo_token()
        output_payloads = _make_output_payloads(echo_token)

        # --- Baseline check: send JUST the token (no command prefix) ---
        # If the token appears in the baseline response, this param reflects
        # everything (e.g. a search field) -- echo detection would be meaningless.
        baseline_resp = self._send(url, method, self._append(params, param_name, echo_token))
        reflects_input = baseline_resp is not None and echo_token in baseline_resp.text

        for payload, desc in output_payloads:
            # Append mode
            resp = self._send(url, method, self._append(params, param_name, payload))
            if resp is None:
                continue

            body = resp.text

            # Check for echo token
            if echo_token in body:
                # Skip if the param reflects arbitrary input (search terms, form echo-back)
                if reflects_input:
                    logger.debug(
                        "[CMDi/Output] %s: token found but param reflects all input -- skip (%s)",
                        param_name, desc,
                    )
                    continue

                # Additional check: distinguish real execution from search-term reflection.
                # If the full payload string (including "echo ") appears literally, it's
                # reflection of the search term, not command output.
                # Real execution: only the token appears; "echo token" does NOT.
                full_echo_string = f"echo {echo_token}"
                if full_echo_string.lower() in body.lower():
                    logger.debug(
                        "[CMDi/Output] %s: full echo string reflected verbatim -- NOT execution (%s)",
                        param_name, desc,
                    )
                    continue

                full_payload = f"{params.get(param_name, '')}{payload}"
                curl = build_curl_command(url, method, params, param_name, full_payload)
                logger.debug("[CMDi/Output] %s: echo token found (%s)", param_name, desc)
                return Finding(
                    vuln_type="OS Command Injection (Output-based)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=full_payload,
                    evidence=f"Echo token '{echo_token}' found in response without command prefix ({desc})",
                    confidence="high",
                    details=(
                        f"Command injection via {desc}. Injected command output appears "
                        "in the HTTP response. Remediation: never pass user input to "
                        "shell commands; use language-native APIs instead of system()."
                    ),
                    reproduction=(
                        f"# 1. Inject the command and look for the token in the response:\n"
                        f"{curl}\n"
                        f"# 2. Search for '{echo_token}' in the output.\n"
                        f"#    If present WITHOUT 'echo' before it, the server executed the command.\n"
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
        """Multi-sample time-based CMDi detection.

        A single baseline measurement is unreliable on CDNs and high-latency
        connections — one slow cache miss can fake a delay.  We take 3 baseline
        samples, compute mean and standard deviation, and only flag when the
        payload response exceeds mean + 3*std AND the server is stable enough
        to trust (std < 2.0 s).  High std → CDN/unstable → skip entirely.
        """
        # Collect 3 baseline samples to establish mean and variance
        _baseline_times: List[float] = []
        for _ in range(3):
            t0 = time.perf_counter()
            resp = self._send(url, method, params)
            elapsed = time.perf_counter() - t0
            if resp is not None:
                _baseline_times.append(elapsed)

        if not _baseline_times:
            return None

        avg_baseline = sum(_baseline_times) / len(_baseline_times)
        if len(_baseline_times) > 1:
            variance = sum((t - avg_baseline) ** 2 for t in _baseline_times) / (len(_baseline_times) - 1)
            std_baseline = variance ** 0.5
        else:
            std_baseline = avg_baseline * 0.5

        # If baseline standard deviation > 2s, the server is too unstable
        # (CDN jitter, high-latency network) — time-based detection is unreliable
        if std_baseline > 2.0:
            logger.debug(
                "[CMDi/Time] %s: baseline std=%.2fs > 2s — server too unstable, skipping time-based",
                param_name, std_baseline,
            )
            return None

        # Dynamic threshold: baseline mean + 3 standard deviations
        # Also require at least the configured delay seconds above the mean
        threshold = max(
            avg_baseline + self.delay,
            avg_baseline + 3 * std_baseline + self.delay * 0.5,
        )

        delay_sec = int(self.delay)

        for template, os_hint in _TIME_PAYLOADS:
            suffix = template.format(delay=delay_sec)
            t0 = time.perf_counter()
            resp = self._send(url, method, self._append(params, param_name, suffix))
            elapsed = time.perf_counter() - t0

            if resp is None:
                continue

            if elapsed >= threshold:
                display = f"{params.get(param_name, '')}{suffix}"

                # --- Differential-timing confirmation (false-positive guard) ---
                # Re-test with 2x the sleep; a genuine injected sleep scales with
                # the requested delay, a random network spike does not.
                def _measure(d_seconds: float):
                    sfx2 = template.format(delay=int(d_seconds))
                    t = time.perf_counter()
                    r = self._send(url, method, self._append(params, param_name, sfx2))
                    if r is None:
                        return None
                    return time.perf_counter() - t

                confirmed, second_elapsed = confirm_time_based(
                    _measure, float(delay_sec), elapsed, avg_baseline,
                )
                if not confirmed:
                    logger.debug(
                        "[CMDi/Time] %s=%r candidate NOT confirmed by 2x re-test "
                        "(first=%.2fs second=%s) — skipping (FP guard)",
                        param_name, display, elapsed,
                        f"{second_elapsed:.2f}s" if second_elapsed is not None else "n/a",
                    )
                    continue

                logger.debug(
                    "[CMDi/Time] %s=%r elapsed=%.2fs threshold=%.2fs confirmed@2x=%.2fs "
                    "(avg=%.2fs std=%.2fs %s)",
                    param_name, display, elapsed, threshold, second_elapsed,
                    avg_baseline, std_baseline, os_hint,
                )
                curl = build_curl_command(url, method, params, param_name, display)
                return Finding(
                    vuln_type="OS Command Injection (Time-based)",
                    url=url,
                    method=method,
                    parameter=param_name,
                    payload=display,
                    evidence=(
                        f"Response delayed {elapsed:.2f}s with {delay_sec}s sleep payload, "
                        f"confirmed at {2 * delay_sec}s sleep ({second_elapsed:.2f}s) "
                        f"(baseline avg={avg_baseline:.2f}s ±{std_baseline:.2f}s, OS: {os_hint})"
                    ),
                    confidence="high",
                    details=(
                        f"Time-based command injection ({os_hint}). "
                        f"Payload caused {elapsed:.2f}s delay vs "
                        f"{avg_baseline:.2f}s±{std_baseline:.2f}s baseline (3 samples), "
                        f"and a 2x-sleep re-test scaled to {second_elapsed:.2f}s "
                        f"(differential-timing confirmed). "
                        "Remediation: never pass user input to shell commands."
                    ),
                    reproduction=(
                        f"# 1. Measure baseline response time (run 3x to confirm stability):\n"
                        f"$ time {build_curl_command(url, method, params, param_name, params.get(param_name, '')).lstrip('$ ')}\n"
                        f"# 2. Send the sleep payload and measure:\n"
                        f"$ time {curl.lstrip('$ ')}\n"
                        f"# 3. If the second request takes ~{delay_sec}s longer than baseline,\n"
                        f"#    it confirms time-based command injection ({os_hint}).\n"
                        f"# Expected: baseline ~{avg_baseline:.1f}s vs payload ~{elapsed:.1f}s"
                    ),
                )
        return None
