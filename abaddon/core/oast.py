"""Out-of-band Application Security Testing (OAST) provider abstraction.

Blind vulnerabilities (blind SQLi, SSRF, blind RCE, OOB XXE, log4shell-class)
produce no observable change in the HTTP response — the only reliable proof is
an *out-of-band interaction*: the target reaches back to a server we control.

This module defines the provider interface plus two implementations:

* :class:`MockOASTProvider` — deterministic, in-memory, for tests.
* :class:`WebhookOASTProvider` — polls a self-hosted interaction server that
  exposes ``GET {poll_url}?token=...`` returning a JSON list of interactions.
  (Compatible with a minimal interactsh-style listener.)

A real engagement plugs in its own interaction server; the matcher only depends
on this interface.
"""

import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Interaction:
    """A single out-of-band callback received by the interaction server."""

    protocol: str  # "dns" | "http"
    correlation_id: str
    remote_addr: str = ""
    raw: str = ""


@dataclass
class OASTHandle:
    """A registered token plus the payload value to inject into requests."""

    correlation_id: str
    payload: str  # e.g. "abcd1234.oast.example.com"


class OASTProvider(ABC):
    """Interface every OAST backend must satisfy."""

    @abstractmethod
    def new_handle(self) -> OASTHandle:
        """Allocate a fresh correlation id + injectable payload."""

    @abstractmethod
    def poll(self, correlation_id: str) -> List[Interaction]:
        """Return interactions observed for *correlation_id* so far."""

    @property
    def available(self) -> bool:
        return True


class MockOASTProvider(OASTProvider):
    """In-memory OAST provider for tests and offline runs."""

    def __init__(self, base_domain: str = "oast.mock") -> None:
        self.base_domain = base_domain
        self._interactions: Dict[str, List[Interaction]] = {}

    def new_handle(self) -> OASTHandle:
        token = secrets.token_hex(8)
        return OASTHandle(correlation_id=token, payload=f"{token}.{self.base_domain}")

    def trigger(
        self, correlation_id: str, protocol: str = "dns", remote_addr: str = "127.0.0.1"
    ) -> None:
        """Test helper: simulate the target calling back."""
        self._interactions.setdefault(correlation_id, []).append(
            Interaction(protocol=protocol, correlation_id=correlation_id, remote_addr=remote_addr)
        )

    def poll(self, correlation_id: str) -> List[Interaction]:
        return list(self._interactions.get(correlation_id, []))


class WebhookOASTProvider(OASTProvider):
    """Polls a self-hosted interaction server over HTTP.

    The server is expected to:
      * accept callbacks at ``*.{base_domain}`` (DNS) and ``{base_url}/{token}`` (HTTP)
      * expose ``GET {poll_url}?token={correlation_id}`` returning JSON::

            {"interactions": [{"protocol": "dns", "remote_addr": "1.2.3.4"}, ...]}
    """

    def __init__(
        self,
        base_domain: str,
        poll_url: str,
        http_client=None,
        timeout: float = 5.0,
    ) -> None:
        self.base_domain = base_domain
        self.poll_url = poll_url
        self.timeout = timeout
        self._client = http_client  # injected; a requests-like .get(url, ...) object

    def new_handle(self) -> OASTHandle:
        token = secrets.token_hex(8)
        return OASTHandle(correlation_id=token, payload=f"{token}.{self.base_domain}")

    @property
    def available(self) -> bool:
        return self._client is not None

    def poll(self, correlation_id: str) -> List[Interaction]:
        if self._client is None:
            return []
        try:
            resp = self._client.get(
                self.poll_url, params={"token": correlation_id}, timeout=self.timeout
            )
            data = resp.json()
        except Exception:
            return []
        out: List[Interaction] = []
        for item in data.get("interactions", []):
            out.append(
                Interaction(
                    protocol=item.get("protocol", "dns"),
                    correlation_id=correlation_id,
                    remote_addr=item.get("remote_addr", ""),
                    raw=item.get("raw", ""),
                )
            )
        return out
