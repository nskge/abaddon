"""Same-host application crawler.

Why this exists
---------------
The base scanner only tests the seed URL's parameters plus forms found on that
one page. Real apps spread their attack surface across many routes, and the
juiciest endpoints (admin pages, JSON APIs) are reachable only after login and
often only linked from authenticated navigation. This crawler walks the app
from a seed, *using whatever session cookies the HTTP client already carries*,
and returns the full surface as injectable targets plus the raw responses
(including JS/CSS assets) so passive checks like secret-scanning can inspect
everything that was fetched.

Three things make it more than a link-follower:

1. It also fetches ``<script src>`` / ``<link href>`` assets. The hardcoded
   secret in this CTF lives in ``/static/app.js`` — only a crawler that pulls
   assets will ever see it.
2. It keeps **hidden** form fields (the stock HTML parser drops them), which is
   what lets the CSRF check tell "form has an anti-CSRF token" from "it doesn't".
3. It harvests ``/api/...`` path strings out of JavaScript bundles. The order
   and account APIs are not linked from any HTML page; the SPA only knows them
   because they're baked into ``app.js`` (``apiBase: "/api"``). We do the same.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
import re
import logging

from .parser import extract_params_from_url, get_base_url

logger = logging.getLogger("vulnscanner")

# Anti-CSRF token field-name hints (case-insensitive substring match).
_CSRF_FIELD_HINTS = ("csrf", "xsrf", "_token", "authenticity", "nonce")

# Links that destroy the session — following them logs the crawler out and
# silently downgrades the rest of the (authenticated) scan to anonymous.
_SESSION_KILLERS = ("logout", "signout", "sign-out", "sign_out", "/exit", "deauth")

# Asset / non-HTML extensions we fetch (for secrets) but never crawl further.
_ASSET_EXT = (".js", ".json", ".css", ".map", ".txt", ".xml")

# Extensions we never fetch at all (binary / noise).
_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".mp3",
)

# Regex to lift API path strings out of JS/HTML (e.g. "/api/orders/2", '/api').
_API_PATH_RE = re.compile(r"""["'`](/api/[A-Za-z0-9_./-]*)["'`]""")
_API_BASE_RE = re.compile(r"""apiBase\s*[:=]\s*["'`]([^"'`]+)["'`]""")


@dataclass
class Page:
    url: str
    method: str
    status: int
    content_type: str
    body: str
    headers: Dict[str, str]


@dataclass
class FormInfo:
    action: str                       # absolute URL
    method: str
    fields: Dict[str, str]            # name -> default value (ALL fields)
    field_types: Dict[str, str]       # name -> input type
    has_csrf_token: bool
    source_url: str                   # page the form was found on


@dataclass
class CrawlResult:
    pages: List[Page] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    targets: List[Dict] = field(default_factory=list)  # {url, method, params, param_name}
    api_paths: List[str] = field(default_factory=list)


class _LinkFormParser(HTMLParser):
    """Collect <a href>, <form> (with ALL inputs incl. hidden), and asset srcs."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.assets: List[str] = []
        self.forms: List[Dict] = []
        self._cur: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href"):
            # stylesheets / preloads — useful for secret scanning of CSS too
            self.assets.append(a["href"])
        elif tag == "form":
            self._cur = {
                "action": a.get("action", ""),
                "method": a.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            itype = a.get("type", "text").lower()
            # Keep EVERYTHING with a name (incl. hidden) except pure buttons.
            if itype not in ("submit", "button", "image", "reset", "file") and a.get("name"):
                self._cur["inputs"].append({
                    "name": a["name"],
                    "value": a.get("value", "test"),
                    "type": itype,
                })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _norm(url: str) -> str:
    """Normalise a URL for the visited-set (drop fragment, keep query)."""
    return urldefrag(url)[0]


def _ext(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    dot = last.rfind(".")
    return last[dot:].lower() if dot != -1 else ""


def crawl(
    seed_url: str,
    http,
    *,
    max_pages: int = 60,
    max_depth: int = 3,
    same_host_only: bool = True,
) -> CrawlResult:
    """Breadth-first crawl from *seed_url* using *http* (carries the session).

    Returns a :class:`CrawlResult` with every fetched page, every form (hidden
    fields included), deduped injectable targets, and API path strings mined
    from JS. Bounded by *max_pages* / *max_depth* so it terminates on big sites.
    """
    seed_host = urlparse(seed_url).hostname or ""
    result = CrawlResult()

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(_norm(seed_url), 0)]
    target_keys: Set[Tuple[str, str, str]] = set()
    api_paths: Set[str] = set()
    fetched_assets: Set[str] = set()

    def _in_scope(u: str) -> bool:
        if not same_host_only:
            return True
        h = urlparse(u).hostname or ""
        return h == seed_host or h.endswith("." + seed_host)

    def _add_target(url: str, method: str, params: Dict[str, str]) -> None:
        base = get_base_url(url)
        for name in params:
            key = (base, method, name)
            if key not in target_keys:
                target_keys.add(key)
                result.targets.append({
                    "url": base, "method": method,
                    "params": dict(params), "param_name": name,
                })

    def _mine_api(body: str) -> None:
        for m in _API_PATH_RE.findall(body):
            api_paths.add(m)
        for m in _API_BASE_RE.findall(body):
            api_paths.add(m)

    while queue and len(result.pages) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if not _in_scope(url) or _ext(urlparse(url).path) in _SKIP_EXT:
            continue

        resp = http.get(url)
        if resp is None:
            continue

        ctype = resp.headers.get("Content-Type", "")
        body = resp.text or ""
        result.pages.append(Page(
            url=url, method="GET", status=resp.status_code,
            content_type=ctype, body=body,
            headers={k: v for k, v in resp.headers.items()},
        ))

        # GET query-string params become injectable targets.
        q = extract_params_from_url(url)
        if q:
            _add_target(url, "GET", q)

        # Only parse HTML for links/forms; assets are fetched but not walked.
        if "html" not in ctype.lower():
            _mine_api(body)
            continue
        _mine_api(body)

        p = _LinkFormParser()
        try:
            p.feed(body)
        except Exception as exc:
            logger.debug("Crawler parse error on %s: %s", url, exc)
            continue

        # Forms → targets (every field) + FormInfo (for CSRF/stored-XSS checks).
        for form in p.forms:
            action = form["action"] or url
            action = action if action.startswith(("http://", "https://")) else urljoin(url, action)
            if not _in_scope(action):
                continue
            fields = {i["name"]: i["value"] for i in form["inputs"]}
            ftypes = {i["name"]: i["type"] for i in form["inputs"]}
            has_token = any(
                any(h in name.lower() for h in _CSRF_FIELD_HINTS)
                or ftypes.get(name) == "hidden" and any(h in name.lower() for h in _CSRF_FIELD_HINTS)
                for name in fields
            )
            result.forms.append(FormInfo(
                action=action, method=form["method"], fields=fields,
                field_types=ftypes, has_csrf_token=has_token, source_url=url,
            ))
            if fields:
                _add_target(action, form["method"], fields)

        # Enqueue same-host links.
        if depth < max_depth:
            for href in p.links:
                nxt = _norm(urljoin(url, href))
                if any(k in nxt.lower() for k in _SESSION_KILLERS):
                    continue  # never follow logout/sign-out — it kills our session
                if nxt.startswith(("http://", "https://")) and _in_scope(nxt) and nxt not in visited:
                    queue.append((nxt, depth + 1))

        # Fetch (but don't crawl) assets so secret-scanning can read them.
        for src in p.assets:
            asset = _norm(urljoin(url, src))
            if not asset.startswith(("http://", "https://")) or not _in_scope(asset):
                continue
            if asset in fetched_assets or _ext(urlparse(asset).path) not in _ASSET_EXT:
                continue
            fetched_assets.add(asset)
            ar = http.get(asset)
            if ar is None:
                continue
            abody = ar.text or ""
            result.pages.append(Page(
                url=asset, method="GET", status=ar.status_code,
                content_type=ar.headers.get("Content-Type", ""), body=abody,
                headers={k: v for k, v in ar.headers.items()},
            ))
            _mine_api(abody)

    result.api_paths = sorted(api_paths)
    logger.info(
        "Crawl: %d page(s), %d form(s), %d target(s), %d API path(s)",
        len(result.pages), len(result.forms), len(result.targets), len(result.api_paths),
    )
    return result
