"""Tests for the advanced detection modules:
smuggling, prototype pollution, DOM XSS, and JWT advanced attacks."""

import json
import pytest
from unittest.mock import MagicMock

from scanner.modules.base import Finding
from scanner.modules.smuggling import (
    _build_baseline, _build_clte_probe, _build_tecl_probe, SmugglingScanner,
)
from scanner.modules.prototype_pollution import (
    build_query_payloads, build_json_payloads, _indent_width,
    PrototypePollutionScanner,
)
from scanner.modules.dom_xss import analyze_sources_sinks, DOMXSSScanner
from scanner.modules.jwt_analyzer import _forge_kid, _b64url_decode, _ASYMMETRIC_ALGS


# ---------------------------------------------------------------------------
# HTTP Request Smuggling — raw request builders
# ---------------------------------------------------------------------------

def test_smuggling_baseline_is_valid_chunked():
    raw = _build_baseline("target.com", "/")
    assert b"Transfer-Encoding: chunked" in raw
    assert b"Host: target.com" in raw
    assert raw.endswith(b"0\r\n\r\n")


def test_smuggling_clte_has_both_headers():
    raw = _build_clte_probe("target.com", "/api")
    assert b"Content-Length: 4" in raw
    assert b"Transfer-Encoding: chunked" in raw
    # CL.TE probe leaves a dangling chunk
    assert raw.endswith(b"1\r\nA\r\nX")


def test_smuggling_tecl_has_both_headers():
    raw = _build_tecl_probe("target.com", "/")
    assert b"Content-Length: 6" in raw
    assert b"Transfer-Encoding: chunked" in raw


def test_smuggling_paths_preserved():
    raw = _build_clte_probe("h", "/login?x=1")
    assert b"POST /login?x=1 HTTP/1.1" in raw


def test_smuggling_runs_once_per_host(monkeypatch):
    scanner = SmugglingScanner(MagicMock(), {})
    # Stub the probe to never report and track call count.
    calls = []
    monkeypatch.setattr(scanner, "_probe", lambda *a, **k: calls.append(a) or None)
    scanner.scan_parameter("http://h.com/a", "GET", {}, "x")
    scanner.scan_parameter("http://h.com/b", "GET", {}, "y")  # same host
    # Two variants (CL.TE, TE.CL) on first call only → 2 probe calls total
    assert len(calls) == 2


def test_smuggling_no_host_returns_empty():
    scanner = SmugglingScanner(MagicMock(), {})
    assert scanner.scan_parameter("not a url", "GET", {}, "x") == []


# ---------------------------------------------------------------------------
# Prototype Pollution
# ---------------------------------------------------------------------------

def test_pp_query_payloads_have_proto_keys():
    payloads = build_query_payloads()
    keys = [list(p.keys())[0] for p in payloads]
    assert any("__proto__" in k for k in keys)
    assert any("constructor" in k for k in keys)


def test_pp_json_payloads_structure():
    payloads = build_json_payloads()
    assert any("__proto__" in p for p in payloads)
    assert any("constructor" in p for p in payloads)


def test_pp_indent_width_minified():
    assert _indent_width('{"a":1,"b":2}') == 0


def test_pp_indent_width_pretty():
    pretty = '{\n    "a": 1,\n    "b": 2\n}'
    assert _indent_width(pretty) == 4


def test_pp_indent_width_empty():
    assert _indent_width("") == 0


def test_pp_detects_json_spaces_gadget():
    """Baseline minified JSON; polluted response indented → finding."""
    scanner = PrototypePollutionScanner(MagicMock(), {})

    baseline = MagicMock()
    baseline.headers = {"Content-Type": "application/json"}
    baseline.text = '{"ok":true}'

    polluted = MagicMock()
    polluted.headers = {"Content-Type": "application/json"}
    polluted.text = '{\n     "ok": true\n}'  # 5-space indent

    # First call = baseline, subsequent = polluted
    responses = [baseline] + [polluted] * 10
    scanner.http.get = MagicMock(side_effect=responses)

    findings = scanner.scan_parameter("http://t/api", "GET", {}, "x")
    assert any("Prototype Pollution" in f.vuln_type for f in findings)
    assert findings[0].confidence == "high"


def test_pp_no_finding_on_html():
    scanner = PrototypePollutionScanner(MagicMock(), {})
    html = MagicMock()
    html.headers = {"Content-Type": "text/html"}
    html.text = "<html><body>hi</body></html>"
    scanner.http.get = MagicMock(return_value=html)
    scanner.http.raw_post = MagicMock(return_value=html)
    findings = scanner.scan_parameter("http://t/", "GET", {}, "x")
    # No JSON → no json-spaces gadget; reflection probe doesn't match either
    assert findings == []


# ---------------------------------------------------------------------------
# DOM XSS — static source→sink analysis
# ---------------------------------------------------------------------------

def test_domxss_detects_hash_to_innerhtml():
    js = "var x = location.hash.substring(1); el.innerHTML = x;"
    pairs = analyze_sources_sinks(js)
    assert any("hash" in src and "innerHTML" in sink for src, sink in pairs)


def test_domxss_detects_eval_sink():
    js = "eval(location.search);"
    pairs = analyze_sources_sinks(js)
    assert any("eval" in sink for _, sink in pairs)


def test_domxss_no_source_no_pairs():
    js = "el.innerHTML = 'static string';"
    assert analyze_sources_sinks(js) == []


def test_domxss_no_sink_no_pairs():
    js = "var x = location.hash; console.log(x);"
    assert analyze_sources_sinks(js) == []


def test_domxss_postmessage_source():
    js = "addEventListener('message', e => { document.write(e.data); });"
    pairs = analyze_sources_sinks(js)
    assert len(pairs) >= 1


def test_domxss_runs_once_per_url():
    scanner = DOMXSSScanner(MagicMock(), {})
    resp = MagicMock()
    resp.text = "el.innerHTML = location.hash;"
    resp.headers = {}
    scanner.http.get = MagicMock(return_value=resp)
    f1 = scanner.scan_parameter("http://t/page", "GET", {}, "a")
    f2 = scanner.scan_parameter("http://t/page", "GET", {}, "b")  # same url
    assert len(f1) >= 1
    assert f2 == []  # deduped


def test_domxss_static_finding_is_low_confidence():
    scanner = DOMXSSScanner(MagicMock(), {})
    resp = MagicMock()
    resp.text = "el.innerHTML = location.hash;"
    resp.headers = {}
    scanner.http.get = MagicMock(return_value=resp)
    findings = scanner.scan_parameter("http://t/x", "GET", {}, "a")
    assert findings[0].confidence == "low"


# ---------------------------------------------------------------------------
# JWT advanced — kid forging + algorithm confusion detection
# ---------------------------------------------------------------------------

# A real HS256 token: {"alg":"HS256","typ":"JWT"} / {"user":"guest"}
_HS_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJ1c2VyIjoiZ3Vlc3QifQ"
    ".c2lnbmF0dXJl"
)
# RS256 header token (signature irrelevant for detection)
_RS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJ1c2VyIjoiZ3Vlc3QifQ"
    ".c2ln"
)


def test_jwt_forge_kid_produces_valid_structure():
    forged = _forge_kid(_HS_TOKEN, "../../../../dev/null", secret="")
    assert forged is not None
    parts = forged.split(".")
    assert len(parts) == 3
    header = json.loads(_b64url_decode(parts[0]))
    assert header["kid"] == "../../../../dev/null"
    assert header["alg"] == "HS256"


def test_jwt_forge_kid_empty_secret_signs():
    """Empty-secret signature must be deterministic and present."""
    f1 = _forge_kid(_HS_TOKEN, "/dev/null", secret="")
    f2 = _forge_kid(_HS_TOKEN, "/dev/null", secret="")
    assert f1 == f2
    assert f1.split(".")[2]  # non-empty signature


def test_jwt_forge_kid_rejects_malformed():
    assert _forge_kid("not.a.valid.jwt.token", "x") is None
    assert _forge_kid("onlyonepart", "x") is None


def test_jwt_asymmetric_algs_constant():
    assert "RS256" in _ASYMMETRIC_ALGS
    assert "ES256" in _ASYMMETRIC_ALGS
    assert "HS256" not in _ASYMMETRIC_ALGS
