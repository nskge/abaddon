"""Scope enforcement — a non-negotiable safety invariant.

A target is only probed when it matches the configured allowlist of host glob
patterns and/or CIDR ranges. When no scope is configured the scanner runs in
single-target / unrestricted mode (the operator is responsible for the URL they
passed); when scope *is* configured it is enforced before the first packet.
"""

import fnmatch
import ipaddress
from typing import List, Optional
from urllib.parse import urlparse


class Scope:
    """Allowlist of host patterns and CIDR ranges."""

    def __init__(
        self,
        patterns: Optional[List[str]] = None,
        cidrs: Optional[List[str]] = None,
    ) -> None:
        self.patterns: List[str] = [p.strip().lower() for p in (patterns or []) if p.strip()]
        self.cidrs: List[ipaddress._BaseNetwork] = []
        for c in cidrs or []:
            c = c.strip()
            if not c:
                continue
            try:
                self.cidrs.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        self.enabled: bool = bool(self.patterns or self.cidrs)

    def allows(self, url: str) -> bool:
        """Return True if *url*'s host is in scope (or scope is disabled)."""
        if not self.enabled:
            return True
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        for pattern in self.patterns:
            if fnmatch.fnmatch(host, pattern):
                return True
        if self.cidrs:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            for net in self.cidrs:
                if ip in net:
                    return True
        return False

    def __repr__(self) -> str:
        return f"Scope(patterns={self.patterns!r}, cidrs={[str(c) for c in self.cidrs]!r})"
