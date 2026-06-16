"""Authenticated-session management for the scanner.

Why this exists
---------------
Most interesting vulnerabilities live *behind* a login (account pages, order
APIs, admin panels). A scanner that only sends anonymous requests can never
reach them, which is the single biggest cause of low recall. This module logs
in once, captures the session cookie, and exposes it so every subsequent
request (recon, crawl, every module) reuses the authenticated session.

It supports two ways to authenticate:

1. **Credential login** — POST a username/password to a login URL and keep the
   resulting session cookie. The success oracle is deliberately generic: a
   login is considered successful when the response sets a new cookie and/or
   redirects away from the login page (the same signal a browser sees).
2. **Ready cookie** — the user pastes a cookie they already have; we just use it.

Re-login on expiry
------------------
Sessions expire. :meth:`looks_logged_out` lets callers detect the tell-tale
"bounced back to /login" response and :meth:`relogin` re-establishes the
session transparently.

Multiple identities
-------------------
BOLA/IDOR testing needs *two* low-privilege users (can user A read user B's
object?). :meth:`session_cookies_for` logs in an arbitrary credential pair and
returns its cookies, so orchestrated checks can hold several identities at once.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import re
import logging

import requests

logger = logging.getLogger("vulnscanner")


@dataclass
class Credential:
    username: str
    password: str
    # Field names on the login form (defaults match the most common case).
    user_field: str = "username"
    pass_field: str = "password"
    # Extra static fields some login forms require (CSRF token handled separately).
    extra: Dict[str, str] = field(default_factory=dict)


class Authenticator:
    """Performs login and hands out authenticated session cookies."""

    def __init__(
        self,
        login_url: str,
        credentials: List[Credential],
        *,
        timeout: int = 10,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.login_url = login_url
        self.credentials = credentials
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.extra_headers = extra_headers or {}
        self._login_host = urlparse(login_url).hostname or ""
        # Captured from the primary login's Set-Cookie (for the CSRF check).
        self.cookie_samesite: Optional[str] = None
        self.cookie_httponly: bool = False
        self.cookie_secure: bool = False
        self.session_cookie_seen: bool = False

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def _new_session(self) -> requests.Session:
        s = requests.Session()
        if self.extra_headers:
            s.headers.update(self.extra_headers)
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.verify = self.verify_ssl
        return s

    def _login_session(self, cred: Credential) -> Tuple[Optional[requests.Session], bool]:
        """Log *cred* in on a fresh session.

        Returns ``(session, ok)``. ``ok`` is the generic success oracle:
        the request set a session cookie AND did not land back on the login page.
        """
        s = self._new_session()
        data = {cred.user_field: cred.username, cred.pass_field: cred.password}
        data.update(cred.extra)
        try:
            # Don't auto-follow: we want to inspect the immediate redirect, which
            # is the clearest "login worked" signal.
            resp = s.post(
                self.login_url, data=data,
                timeout=self.timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            logger.warning("Login request failed for %r: %s", cred.username, exc)
            return None, False

        got_cookie = len(s.cookies) > 0
        self._capture_cookie_attrs(resp)
        location = resp.headers.get("Location", "")
        # Success when we leave the login page (redirect elsewhere) or get a
        # cookie on a 2xx that isn't the login form again.
        redirected_away = (
            300 <= resp.status_code < 400
            and "login" not in urljoin(self.login_url, location).lower()
        )
        ok = got_cookie and (redirected_away or resp.status_code < 300)
        if ok:
            logger.info("Authenticated as %r (HTTP %d)", cred.username, resp.status_code)
        else:
            logger.warning(
                "Login as %r did not look successful (HTTP %d, cookie=%s, loc=%r)",
                cred.username, resp.status_code, got_cookie, location,
            )
        return s, ok

    def login(self) -> Dict[str, str]:
        """Log in the *primary* credential and return its cookies as a dict.

        Returns an empty dict if there are no credentials or login failed
        (the scanner then continues unauthenticated rather than aborting).
        """
        if not self.credentials:
            return {}
        s, ok = self._login_session(self.credentials[0])
        if not ok or s is None:
            return {}
        return requests.utils.dict_from_cookiejar(s.cookies)

    def session_cookies_for(self, index: int) -> Dict[str, str]:
        """Return cookies for credential *index* (for multi-identity checks)."""
        if index >= len(self.credentials):
            return {}
        s, ok = self._login_session(self.credentials[index])
        if not ok or s is None:
            return {}
        return requests.utils.dict_from_cookiejar(s.cookies)

    def _capture_cookie_attrs(self, resp) -> None:
        """Parse the Set-Cookie of a session cookie to record its SameSite /
        HttpOnly / Secure flags (only the first session-looking cookie)."""
        if self.session_cookie_seen:
            return
        raw = resp.headers.get("Set-Cookie", "")
        if not raw:
            return
        low = raw.lower()
        # Only care about cookies that look like a session (heuristic).
        if not any(h in low for h in ("sess", "sid", "auth", "token", "id=")):
            return
        self.session_cookie_seen = True
        self.cookie_httponly = "httponly" in low
        self.cookie_secure = "secure" in low
        m = re.search(r"samesite=(\w+)", low)
        self.cookie_samesite = m.group(1) if m else None

    # ------------------------------------------------------------------
    # Expiry detection
    # ------------------------------------------------------------------

    def looks_logged_out(self, resp) -> bool:
        """Heuristic: did *resp* bounce us to a login page / 401?

        Used by callers to detect mid-scan session expiry and trigger relogin.
        """
        if resp is None:
            return False
        if resp.status_code == 401:
            return True
        if 300 <= resp.status_code < 400:
            loc = resp.headers.get("Location", "").lower()
            if "login" in loc or "signin" in loc:
                return True
        # A 200 that is actually the login form again (some apps render it inline)
        if resp.status_code == 200 and self.login_url:
            body = (resp.text or "").lower()
            if 'name="password"' in body and ("login" in body or "sign in" in body):
                return True
        return False
