"""Session-based HTTP client with proxy, cookie, retry, and rate-limit support."""

from typing import Dict, Optional
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("vulnscanner")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class HTTPClient:
    """Thin wrapper around :class:`requests.Session` with scanner-friendly defaults.

    All requests silently return ``None`` on timeout or connection error so that
    scanner modules can treat a ``None`` response as "skip this payload".

    An optional :class:`~scanner.rate_limiter.AdaptiveRateLimiter` can be
    injected; when present, ``wait()`` is called before every request and
    ``record()`` is called with the response status code.
    """

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        timeout: int = 10,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        rate_limiter=None,
    ) -> None:
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self._rate_limiter = rate_limiter

        self._session = requests.Session()

        # Baseline headers
        self._session.headers.update(
            {
                "User-Agent": DEFAULT_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )
        if headers:
            self._session.headers.update(headers)
        if cookies:
            self._session.cookies.update(cookies)
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

        self._session.verify = verify_ssl

        # Retry on transient failures (not on 4xx/5xx — those are intentional)
        _retry = Retry(total=2, backoff_factor=0.3, status_forcelist=())
        _adapter = HTTPAdapter(max_retries=_retry)
        self._session.mount("http://", _adapter)
        self._session.mount("https://", _adapter)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        """Send a GET request; return the response or None on failure."""
        return self._request("GET", url, params=params, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        """Send a POST request; return the response or None on failure."""
        return self._request("POST", url, data=data, **kwargs)

    def raw_post(
        self,
        url: str,
        body: str,
        content_type: str = "application/xml",
    ) -> Optional[requests.Response]:
        """Send a POST with a raw string body and a custom Content-Type.

        Useful for XXE probing and SOAP/REST XML injection.
        """
        return self._request(
            "POST", url,
            data=body.encode("utf-8", errors="replace"),
            headers={"Content-Type": content_type},
        )

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self._rate_limiter is not None:
            self._rate_limiter.wait()
        try:
            response = self._session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                **kwargs,
            )
            if self._rate_limiter is not None:
                self._rate_limiter.record(response.status_code)
            return response
        except requests.exceptions.Timeout:
            logger.debug("Timeout: %s %s", method, url)
            return None
        except requests.exceptions.ConnectionError as exc:
            logger.debug("Connection error: %s %s — %s", method, url, exc)
            return None
        except requests.exceptions.RequestException as exc:
            logger.debug("Request error: %s %s — %s", method, url, exc)
            return None
