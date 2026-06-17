"""HTTP Request Smuggling detection module (CL.TE / TE.CL).

Detection strategy — timing-based differential (PortSwigger methodology):
  A front-end and back-end server that disagree on which header delimits the
  request body (Content-Length vs Transfer-Encoding) can be desynchronised.
  We send a crafted request that, *if* the desync exists, forces the back-end
  to block waiting for bytes that never arrive — producing a measurable delay.

  We never send an actual smuggled request that would poison another user's
  connection. We only measure the self-inflicted timeout, so the test is
  non-destructive: at worst our own socket hangs until it times out.

Why raw sockets:
  The ``requests`` library refuses to send a request with both a
  Content-Length and a Transfer-Encoding header (it normalises them away), so
  smuggling can't be tested through it. We build the raw HTTP/1.1 bytes by hand
  and speak directly to the socket.

Confidence:
  Smuggling is famously jitter-prone. We require the malicious probe to be
  slower than BOTH a fresh baseline AND a fixed threshold, across repeated
  samples, before reporting — and we still flag it for manual confirmation.
"""

import logging
import socket
import ssl
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseModule, Finding

logger = logging.getLogger("vulnscanner")

# Seconds the malicious probe must exceed the baseline by to be suspicious.
_DELAY_THRESHOLD = 5.0
# How long we let a probe socket hang before giving up (must exceed threshold).
_SOCKET_TIMEOUT = 12.0
# Repeat the confirming probe this many times to defeat one-off network jitter.
_CONFIRM_SAMPLES = 2


# ---------------------------------------------------------------------------
# Raw request builders (pure functions — unit-testable without a socket)
# ---------------------------------------------------------------------------

def _build_baseline(host: str, path: str) -> bytes:
    """A well-formed chunked request the back-end can complete immediately."""
    body = "0\r\n\r\n"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )
    return req.encode("latin-1")


def _build_clte_probe(host: str, path: str) -> bytes:
    """CL.TE probe: front-end honours Content-Length (4), back-end honours
    Transfer-Encoding. The back-end reads chunk ``1\\r\\nA`` then blocks waiting
    for the next chunk that the front-end withheld → delay if vulnerable."""
    body = "1\r\nA\r\nX"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )
    return req.encode("latin-1")


def _build_tecl_probe(host: str, path: str) -> bytes:
    """TE.CL probe: front-end honours Transfer-Encoding, back-end honours
    Content-Length. The front-end terminates at the ``0`` chunk while the
    back-end keeps waiting for its declared Content-Length bytes → delay if
    vulnerable."""
    body = "0\r\n\r\n"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )
    return req.encode("latin-1")


# Obfuscated Transfer-Encoding variants for bypassing naive front-end parsers.
# (used in reproduction guidance, not auto-fired)
_TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding\n: chunked",
    " Transfer-Encoding: chunked",
    "X: X\nTransfer-Encoding: chunked",
]


# ---------------------------------------------------------------------------
# Socket I/O
# ---------------------------------------------------------------------------

def _send_raw(
    host: str,
    port: int,
    use_ssl: bool,
    raw: bytes,
    timeout: float,
) -> Tuple[float, bool]:
    """Send *raw* bytes and time how long until the response starts (or hangs).

    Returns ``(elapsed_seconds, completed)`` where *completed* is True if the
    server sent a response and closed, False if we hit the socket timeout
    (the tell-tale sign of a back-end blocked waiting for more body bytes).
    """
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(raw)
        # Read until close or timeout; we only care about timing, not content.
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
        return time.monotonic() - t0, True
    except (socket.timeout, ssl.SSLError):
        return time.monotonic() - t0, False
    except OSError as exc:
        logger.debug("[smuggling] socket error: %s", exc)
        return time.monotonic() - t0, False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class SmugglingScanner(BaseModule):
    """Detects HTTP request smuggling (CL.TE and TE.CL desync) via timing.

    This is a host-level check, not a per-parameter one: it runs once per
    target host and ignores the injected parameter entirely.
    """

    NAME = "smuggling"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self._scanned_hosts: set = set()

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return []
        # Run once per host — smuggling is a property of the infra, not the param.
        if host in self._scanned_hosts:
            return []
        self._scanned_hosts.add(host)

        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"

        findings: List[Finding] = []

        clte = self._probe(host, port, use_ssl, path, "CL.TE", _build_clte_probe)
        if clte:
            findings.append(clte)
        tecl = self._probe(host, port, use_ssl, path, "TE.CL", _build_tecl_probe)
        if tecl:
            findings.append(tecl)

        return findings

    def _probe(
        self, host: str, port: int, use_ssl: bool, path: str,
        kind: str, builder,
    ) -> Optional[Finding]:
        """Run a timing differential for one smuggling variant."""
        # Fresh baseline each probe so transient latency affects both equally.
        base_elapsed, base_done = _send_raw(
            host, port, use_ssl, _build_baseline(host, path), _SOCKET_TIMEOUT,
        )
        if not base_done:
            # Server is just slow/unreachable — can't establish a clean baseline.
            logger.debug("[smuggling] %s: no clean baseline (%.1fs), skipping", kind, base_elapsed)
            return None

        # The malicious probe must hang past threshold every sample to count.
        slow_samples = 0
        worst = 0.0
        for _ in range(_CONFIRM_SAMPLES):
            elapsed, done = _send_raw(
                host, port, use_ssl, builder(host, path), _SOCKET_TIMEOUT,
            )
            worst = max(worst, elapsed)
            if (not done or elapsed >= base_elapsed + _DELAY_THRESHOLD) and elapsed >= _DELAY_THRESHOLD:
                slow_samples += 1

        if slow_samples < _CONFIRM_SAMPLES:
            return None

        logger.info(
            "[smuggling] %s timing desync: baseline=%.1fs probe=%.1fs",
            kind, base_elapsed, worst,
        )

        scheme = "https" if use_ssl else "http"
        front, back = ("Content-Length", "Transfer-Encoding") if kind == "CL.TE" \
            else ("Transfer-Encoding", "Content-Length")

        return Finding(
            vuln_type=f"HTTP Request Smuggling ({kind})",
            url=f"{scheme}://{host}:{port}{path}",
            method="POST",
            parameter="(request framing)",
            payload=f"{kind} timing probe (CL+TE desync)",
            evidence=(
                f"{kind} probe hung {worst:.1f}s vs {base_elapsed:.1f}s baseline "
                f"across {_CONFIRM_SAMPLES} samples — front-end honours {front}, "
                f"back-end honours {back}."
            ),
            confidence="medium",
            details=(
                f"The front-end and back-end disagree on request-body framing "
                f"({kind}). An attacker can prepend a partial request that the "
                f"back-end prepends to the NEXT user's request — enabling cache "
                f"poisoning, credential theft, request hijacking, and WAF bypass. "
                f"Timing-based detection is jitter-prone: CONFIRM MANUALLY before "
                f"reporting, and never run smuggling tests on shared infra without "
                f"authorisation."
            ),
            reproduction=(
                f"# Confirm with the Smuggler tool or Burp Repeater (single connection):\n"
                f"$ git clone https://github.com/defparam/smuggler && cd smuggler\n"
                f"$ python3 smuggler.py -u {scheme}://{host}{path}\n\n"
                f"# Or Burp: send this raw request, observe the {_DELAY_THRESHOLD:.0f}s+ delay:\n"
                f"#   POST {path} HTTP/1.1\n"
                f"#   Host: {host}\n"
                f"#   {front}: <crafted>\n"
                f"#   {back}: <crafted>\n\n"
                f"# Try obfuscated Transfer-Encoding headers if a WAF normalises the simple form:\n"
                + "\n".join(f"#   {te}" for te in _TE_OBFUSCATIONS[:4])
            ),
        )
