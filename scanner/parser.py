"""URL and HTML parameter extraction utilities."""

from html.parser import HTMLParser
from typing import Dict, List
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)


# ---------------------------------------------------------------------------
# HTML form extractor
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    """SAX-style parser that collects <form> elements from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: List[Dict] = []
        self._current: Dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            itype = attrs.get("type", "text").lower()
            if itype not in ("submit", "button", "image", "reset", "file", "hidden"):
                self._current["inputs"].append(
                    {
                        "name": attrs.get("name", ""),
                        "value": attrs.get("value", "test"),
                        "type": itype,
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            if self._current["inputs"]:
                self.forms.append(self._current)
            self._current = None


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def extract_params_from_url(url: str) -> Dict[str, str]:
    """Return the query-string parameters of *url* as a flat dict."""
    qs = urlparse(url).query
    return {k: v[0] for k, v in parse_qs(qs, keep_blank_values=True).items()}


def get_base_url(url: str) -> str:
    """Strip query string and fragment from *url*."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def rebuild_url_with_params(base_url: str, params: Dict[str, str]) -> str:
    """Rebuild *base_url* replacing its query string with *params*."""
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=urlencode(params)))


def extract_forms(html: str, base_url: str) -> List[Dict]:
    """Extract all forms from *html*, resolving action URLs against *base_url*."""
    fp = _FormParser()
    fp.feed(html)
    result = []
    for form in fp.forms:
        action = form["action"] or base_url
        if not action.startswith(("http://", "https://")):
            action = urljoin(base_url, action)
        result.append({**form, "action": action})
    return result


def parse_post_data(data_string: str) -> Dict[str, str]:
    """Parse a ``key=val&key2=val2`` string into a dict."""
    if not data_string:
        return {}
    result: Dict[str, str] = {}
    for pair in data_string.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
        elif pair.strip():
            result[pair.strip()] = ""
    return result


def inject_into_params(
    params: Dict[str, str], target: str, payload: str
) -> Dict[str, str]:
    """Return a copy of *params* with *target* replaced by *payload*."""
    return {**params, target: payload}
