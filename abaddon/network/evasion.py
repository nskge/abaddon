"""Evasion layer — exercise WAF / rate-limit controls during *authorized* tests.

Two responsibilities:

* :class:`Evasion` — per-request header mutation: User-Agent rotation and
  IP-spoofing headers (``X-Forwarded-For`` & friends) to test whether per-IP
  ACLs / rate limits are bypassable.
* :class:`PayloadMutator` — encoding-chain transforms (URL, double-URL, unicode,
  case, SQL comment injection) across three escalating levels, mirroring the
  existing OkrScann ``--waf-evasion`` ladder.

This is standard control-validation tooling for engagements you are authorized
to run — it does not defeat detection for malicious use.
"""

import random
from typing import Dict, List, Optional
from urllib.parse import quote

# A small embedded pool of realistic desktop/mobile User-Agents.
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# Headers that downstream proxies/WAFs may trust for client-IP decisions.
_IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "True-Client-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "CF-Connecting-IP",
]


def random_ip() -> str:
    """A random non-reserved-looking IPv4 for spoof headers."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class Evasion:
    """Per-request header mutation."""

    def __init__(
        self,
        rotate_ua: bool = True,
        ip_spoof: bool = False,
        static_ua: Optional[str] = None,
    ) -> None:
        self.rotate_ua = rotate_ua
        self.ip_spoof = ip_spoof
        self.static_ua = static_ua

    def mutate(self, headers: Dict[str, str], url: Optional[str] = None) -> Dict[str, str]:
        out = dict(headers or {})
        if self.static_ua:
            out["User-Agent"] = self.static_ua
        elif self.rotate_ua:
            out["User-Agent"] = random.choice(USER_AGENTS)
        if self.ip_spoof:
            ip = random_ip()
            for header in _IP_SPOOF_HEADERS:
                out.setdefault(header, ip)
        return out


class PayloadMutator:
    """Generate WAF-evasion variants of a payload across escalating levels."""

    def __init__(self, level: int = 0) -> None:
        self.level = max(0, min(3, level))

    def variants(self, payload: str) -> List[str]:
        """Return unique payload variants for the configured level (incl. original)."""
        out: List[str] = [payload]
        if self.level >= 1:
            out.append(quote(payload, safe=""))           # URL encode
            out.append(payload.replace(" ", "/**/"))      # SQL comment for spaces
        if self.level >= 2:
            out.append(quote(quote(payload, safe=""), safe=""))  # double URL encode
            out.append(self._mixed_case(payload))                # case mutation
        if self.level >= 3:
            out.append(self._unicode_escape(payload))     # unicode escapes
            out.append(payload.replace(" ", "+"))         # plus-for-space
        # Deduplicate while preserving order.
        seen = set()
        unique = []
        for v in out:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

    @staticmethod
    def _mixed_case(payload: str) -> str:
        return "".join(
            ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(payload)
        )

    @staticmethod
    def _unicode_escape(payload: str) -> str:
        return "".join(f"%u{ord(ch):04x}" if ch.isalpha() else ch for ch in payload)
