"""Out-of-band application security testing (OAST) primitives.

Blind and second-order vulnerabilities never show up in the immediate response:
a stored XSS fires later, in a *different* viewer's browser (e.g. an admin
moderating a review); a blind SSRF/RCE reaches out from the server. The only way
to confirm them is an out-of-band signal — the payload makes the victim call
back to a collector we control, and we observe the hit.

This module provides a local callback listener (the general, correct oracle for
a real victim browser) plus, in :mod:`scanner.active_checks`, a fallback that
polls a target-provided capture/collector log for environments where the victim
is simulated and exfiltrates to an in-app endpoint rather than fetching our URL.
"""

import http.server
import socketserver
import threading
import time
from typing import Dict, List, Optional

import logging

logger = logging.getLogger("vulnscanner")


class _CollectorHandler(http.server.BaseHTTPRequestHandler):
    """Records every request path/headers so payloads can be correlated by token."""

    def do_GET(self):  # noqa: N802 (stdlib naming)
        self.server.hits.append({  # type: ignore[attr-defined]
            "path": self.path,
            "time": time.time(),
            "ua": self.headers.get("User-Agent", ""),
            "ref": self.headers.get("Referer", ""),
        })
        # Respond as a tiny GIF so <img>/<script src> payloads "succeed".
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        try:
            self.wfile.write(b"GIF89a")
        except Exception:
            pass

    do_POST = do_GET

    def log_message(self, *args):  # silence the default stderr logging
        return


class OASTListener:
    """A tiny local HTTP server that records callbacks, keyed by a token.

    Bind host defaults to 127.0.0.1 (works when the victim/bot runs on the same
    machine, as in local labs). For a remote victim, pass the externally
    reachable address via *host*.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._host = host
        socketserver.TCPServer.allow_reuse_address = True
        self._srv = socketserver.TCPServer((host, 0), _CollectorHandler)
        self._srv.hits = []  # type: ignore[attr-defined]
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._srv.server_address[1]

    def base_url(self) -> str:
        return f"http://{self._host}:{self.port}"

    def url_for(self, token: str) -> str:
        """Callback URL embedding *token* so a hit can be attributed."""
        return f"{self.base_url()}/x/{token}"

    def start(self) -> "OASTListener":
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        logger.debug("OAST listener up on %s", self.base_url())
        return self

    def stop(self) -> None:
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass

    def hits(self) -> List[Dict]:
        return list(self._srv.hits)  # type: ignore[attr-defined]

    def was_hit(self, token: str) -> bool:
        """True if any recorded callback path contains *token*."""
        return any(token in h["path"] for h in self._srv.hits)  # type: ignore[attr-defined]

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
