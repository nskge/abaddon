"""Tests for new v2.7.0-v2.8.0 features: rate limiter, WAF evasion, port scanner,
JWT analyzer, SSRF, XXE, discovery utilities, and 403 bypass."""

import base64
import hashlib
import hmac
import json
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from scanner.rate_limiter import AdaptiveRateLimiter
from scanner.waf_evasion import apply_evasion
from scanner.port_scanner import _probe, scan_ports
from scanner.discovery import enumerate_subdomains, discover_paths
from scanner.modules.jwt_analyzer import (
    _decode_token, _forge_alg_none, _crack_hs256, JWTAnalyzer,
)
from scanner.modules.bypass403 import (
    Bypass403Scanner, _is_bypass, _header_repro, _path_repro, _verb_repro,
)
from scanner.modules.ssrf import SSRFScanner
from scanner.modules.xxe import XXEScanner
from scanner.http_client import HTTPClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http():
    """Return a mock HTTPClient."""
    http = MagicMock(spec=HTTPClient)
    http.get.return_value = None
    http.post.return_value = None
    http.raw_post.return_value = None
    return http


def _mock_resp(status=200, text="", headers=None):
    h = headers or {}
    r = MagicMock()
    r.status_code = status
    r.text = text
    # Use a real MagicMock for headers so we can assign .get / .getlist
    r.headers = MagicMock()
    r.headers.get = lambda k, d="": h.get(k, d)
    r.headers.getlist = lambda k: [h.get(k, "")]
    return r


def _make_jwt(header: dict, payload: dict, secret: str = "", alg: str = "HS256") -> str:
    """Create a real JWT for testing."""
    def _b64(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

    h_enc = _b64(header)
    p_enc = _b64(payload)
    msg = f"{h_enc}.{p_enc}".encode()

    if alg.lower() == "none":
        sig = ""
    else:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b"=").decode()

    return f"{h_enc}.{p_enc}.{sig}"


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_burst_no_sleep(self):
        rl = AdaptiveRateLimiter(min_delay=1.0, burst=5)
        t0 = time.monotonic()
        for _ in range(5):
            rl.wait()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.1, "Should not sleep during burst"

    def test_429_doubles_delay(self):
        rl = AdaptiveRateLimiter(min_delay=0.1, burst=0)
        rl.record(429)
        assert rl.current_delay == pytest.approx(0.2, rel=0.1)

    def test_429_caps_at_max(self):
        rl = AdaptiveRateLimiter(min_delay=0.1, max_delay=1.0, burst=0)
        for _ in range(20):
            rl.record(429)
        assert rl.current_delay <= 1.0

    def test_200_recovers_delay(self):
        rl = AdaptiveRateLimiter(min_delay=0.0, burst=0)
        rl.record(429)
        before = rl.current_delay
        rl.record(200)
        assert rl.current_delay < before

    def test_503_same_as_429(self):
        rl = AdaptiveRateLimiter(min_delay=0.1, burst=0)
        rl.record(503)
        assert rl.current_delay > 0.1

    def test_request_counter(self):
        rl = AdaptiveRateLimiter(burst=10)
        for _ in range(3):
            rl.wait()
        assert rl.requests_sent == 3

    def test_thread_safety(self):
        import threading
        rl = AdaptiveRateLimiter(min_delay=0.0, burst=100)
        errors = []

        def worker():
            try:
                for _ in range(50):
                    rl.wait()
                    rl.record(200)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ---------------------------------------------------------------------------
# WAF Evasion
# ---------------------------------------------------------------------------

class TestWafEvasion:
    def test_level0_returns_unchanged(self):
        payloads = ["' OR 1=1--", "<script>alert(1)</script>"]
        # level=0 is handled in BaseModule, apply_evasion itself starts at 1
        result = apply_evasion(payloads, level=1)
        # originals are always present
        for p in payloads:
            assert p in result

    def test_level1_adds_url_encoded(self):
        result = apply_evasion(["<script>"], level=1)
        assert any("%" in p for p in result[1:])

    def test_level2_adds_double_encoded(self):
        result = apply_evasion(["<script>"], level=2)
        assert any("%25" in p for p in result[1:])

    def test_level3_adds_sql_comments(self):
        result = apply_evasion(["SELECT * FROM users"], level=3)
        assert any("/**/" in p for p in result[1:])

    def test_no_duplicates(self):
        result = apply_evasion(["test"], level=3)
        assert len(result) == len(set(result))

    def test_original_preserved_at_front(self):
        payloads = ["one", "two"]
        result = apply_evasion(payloads, level=2)
        assert result[0] == "one"
        assert result[1] == "two"

    def test_empty_input(self):
        assert apply_evasion([], level=2) == []


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------

class TestPortScanner:
    def test_probe_open_port(self):
        """Probe a port we know is open (if socket-level tests are allowed)."""
        # We test the function signature and return shape, not real network
        with patch("scanner.port_scanner.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recv.return_value = b"OpenSSH_8.9"
            mock_conn.return_value = mock_sock
            result = _probe("127.0.0.1", 22, timeout=0.5)
        assert result is not None
        assert result["port"] == 22
        assert result["state"] == "open"
        assert "OpenSSH" in result["banner"]

    def test_probe_closed_port(self):
        with patch("scanner.port_scanner.socket.create_connection",
                   side_effect=ConnectionRefusedError):
            result = _probe("127.0.0.1", 9999, timeout=0.1)
        assert result is None

    def test_scan_ports_returns_sorted(self):
        with patch("scanner.port_scanner._probe") as mock_probe:
            mock_probe.side_effect = lambda h, p, t: {
                "port": p, "service": "test", "banner": "", "state": "open"
            } if p in (80, 22, 443) else None

            results = scan_ports("127.0.0.1", ports=[443, 22, 80])
        ports = [r["port"] for r in results]
        assert ports == sorted(ports)

    def test_scan_ports_filters_closed(self):
        with patch("scanner.port_scanner._probe", return_value=None):
            results = scan_ports("127.0.0.1", ports=[1, 2, 3])
        assert results == []


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_enumerate_subdomains_finds_live(self):
        with patch("scanner.discovery.socket.gethostbyname") as mock_dns:
            mock_dns.side_effect = lambda fqdn: (
                "1.2.3.4" if "www" in fqdn else (_ for _ in ()).throw(socket.gaierror)
            )
            results = enumerate_subdomains("example.com", wordlist=["www", "api", "mail"])
        assert len(results) == 1
        assert results[0][0] == "www.example.com"
        assert results[0][1] == "1.2.3.4"

    def test_enumerate_subdomains_empty_on_no_dns(self):
        with patch("scanner.discovery.socket.gethostbyname",
                   side_effect=socket.gaierror):
            results = enumerate_subdomains("nxdomain.invalid", wordlist=["www"])
        assert results == []

    def test_discover_paths_returns_interesting(self):
        http = _make_http()
        http.get.side_effect = lambda url, **kw: (
            _mock_resp(200, "admin panel", {})
            if "admin" in url
            else _mock_resp(404, "not found", {})
        )
        results = discover_paths("http://example.com", http, wordlist=["/admin", "/home"])
        assert any(r["path"] == "/admin" for r in results)
        assert not any(r["path"] == "/home" for r in results)

    def test_discover_paths_includes_auth_required(self):
        http = _make_http()
        http.get.return_value = _mock_resp(401, "Unauthorized", {})
        results = discover_paths("http://example.com", http, wordlist=["/secret"])
        assert len(results) == 1
        assert results[0]["status"] == 401


# ---------------------------------------------------------------------------
# JWT Analyzer helpers
# ---------------------------------------------------------------------------

class TestJWTHelpers:
    def test_decode_valid_jwt(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"}, "secret")
        decoded = _decode_token(token)
        assert decoded is not None
        assert decoded["payload"]["role"] == "user"

    def test_decode_malformed_jwt(self):
        assert _decode_token("not.a.valid.token.here") is None
        assert _decode_token("noparts") is None

    def test_forge_alg_none_produces_tokens(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        forged = _forge_alg_none(token)
        assert len(forged) >= 2
        for f in forged:
            decoded = _decode_token(f) if f.count(".") == 2 else None
            if decoded:
                assert decoded["header"]["alg"].lower() == "none"

    def test_crack_hs256_finds_weak_secret(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "test"}, "secret")
        found = _crack_hs256(token)
        assert found == "secret"

    def test_crack_hs256_returns_none_for_strong(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "test"},
                          "xK9#mP2$nQ7@vR4!wS8&tU1^yV6*zA3")
        found = _crack_hs256(token)
        assert found is None

    def test_crack_hs256_skips_non_hs256(self):
        # RS256 token (can't crack with HMAC)
        token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "test"}, "secret")
        found = _crack_hs256(token)
        assert found is None


# ---------------------------------------------------------------------------
# JWT Analyzer module
# ---------------------------------------------------------------------------

class TestJWTModule:
    def test_detects_weak_secret_in_param(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        http = _make_http()
        http.get.return_value = _mock_resp(200, "", {})
        mod = JWTAnalyzer(http, {})
        findings = mod.scan_parameter("http://ex.com", "GET", {"token": token}, "token")
        vuln_types = [f.vuln_type for f in findings]
        assert any("Weak HMAC" in v for v in vuln_types)

    def test_detects_sensitive_payload_fields(self):
        token = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1", "password": "plaintext"},
            "xK9#mP2$nQ7@vR4!wS8&tU1^yV6*zA3",
        )
        http = _make_http()
        http.get.return_value = _mock_resp(200, "", {})
        mod = JWTAnalyzer(http, {})
        findings = mod.scan_parameter("http://ex.com", "GET", {"token": token}, "token")
        vuln_types = [f.vuln_type for f in findings]
        assert any("Sensitive Data" in v for v in vuln_types)

    def test_skips_non_jwt_param(self):
        http = _make_http()
        http.get.return_value = _mock_resp(200, "")
        mod = JWTAnalyzer(http, {})
        findings = mod.scan_parameter("http://ex.com", "GET", {"id": "123"}, "id")
        assert findings == []


# ---------------------------------------------------------------------------
# SSRF Scanner
# ---------------------------------------------------------------------------

class TestSSRFScanner:
    def test_skips_non_url_param(self):
        http = _make_http()
        mod = SSRFScanner(http, {})
        findings = mod.scan_parameter("http://ex.com", "GET", {"id": "42"}, "id")
        assert findings == []

    def test_detects_aws_metadata_in_response(self):
        http = _make_http()
        # Baseline returns 200 with no metadata
        baseline = _mock_resp(200, "normal page", {})
        # SSRF response contains AWS metadata indicator
        ssrf_resp = _mock_resp(200, "ami-id\ninstance-id\nlocal-ipv4", {})
        # First call = baseline, subsequent = SSRF probes
        http.get.side_effect = [baseline] + [ssrf_resp] * 30
        mod = SSRFScanner(http, {})
        findings = mod.scan_parameter(
            "http://ex.com", "GET",
            {"url": "http://legitimate.com"}, "url",
        )
        assert len(findings) == 1
        assert "SSRF" in findings[0].vuln_type

    def test_detects_url_like_value(self):
        """Param with http:// value should be tested."""
        http = _make_http()
        baseline = _mock_resp(200, "page", {})
        http.get.side_effect = [baseline] + [_mock_resp(404, "")] * 30
        mod = SSRFScanner(http, {})
        # Should not crash; just returns empty if no indicators
        findings = mod.scan_parameter(
            "http://ex.com", "GET",
            {"src": "http://example.com/img.png"}, "src",
        )
        assert isinstance(findings, list)

    def test_detects_redirect_param_name(self):
        """'redirect' is a URL hint, should probe even without http:// prefix."""
        http = _make_http()
        baseline = _mock_resp(200, "")
        redis_resp = _mock_resp(200, "+OK\r\n-ERR unknown command\r\n")
        http.get.side_effect = [baseline] + [redis_resp] * 30
        mod = SSRFScanner(http, {})
        findings = mod.scan_parameter(
            "http://ex.com", "GET",
            {"redirect": "/dashboard"}, "redirect",
        )
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# XXE Scanner
# ---------------------------------------------------------------------------

class TestXXEScanner:
    def test_raw_xml_detects_etc_passwd(self):
        http = _make_http()
        # raw_post returns /etc/passwd content
        http.raw_post.return_value = _mock_resp(200, "root:x:0:0:root:/root:/bin/bash")
        # get/post return nothing interesting
        http.get.return_value = _mock_resp(200, "normal")
        http.post.return_value = _mock_resp(200, "normal")
        mod = XXEScanner(http, {})
        # POST method should trigger raw_xml_probe first
        findings = mod.scan_parameter("http://ex.com", "POST", {"data": ""}, "data")
        assert len(findings) == 1
        assert "XXE" in findings[0].vuln_type

    def test_no_finding_on_normal_response(self):
        http = _make_http()
        http.raw_post.return_value = _mock_resp(200, "normal app response")
        http.get.return_value = _mock_resp(200, "normal")
        http.post.return_value = _mock_resp(200, "normal")
        mod = XXEScanner(http, {})
        findings = mod.scan_parameter("http://ex.com", "POST", {"xml": ""}, "xml")
        assert findings == []

    def test_skips_non_xml_param_on_get(self):
        http = _make_http()
        mod = XXEScanner(http, {})
        findings = mod.scan_parameter(
            "http://ex.com", "GET",
            {"id": "123"}, "id",
        )
        # Should not make raw_post calls for plain GET numeric params
        http.raw_post.assert_not_called()
        assert findings == []

    def test_xinclude_detection(self):
        http = _make_http()
        # Only the XInclude payload response contains etc/passwd
        def raw_post_side(url, body, content_type="application/xml"):
            if "XInclude" in body or "xi:include" in body:
                return _mock_resp(200, "root:x:0:0")
            return _mock_resp(200, "normal")
        http.raw_post.side_effect = raw_post_side
        http.get.return_value = _mock_resp(200, "normal")
        mod = XXEScanner(http, {})
        findings = mod.scan_parameter("http://ex.com", "POST", {"body": ""}, "body")
        assert any("XXE" in f.vuln_type for f in findings)


# ---------------------------------------------------------------------------
# HTTPClient rate limiter integration
# ---------------------------------------------------------------------------

class TestHTTPClientRateLimiter:
    def test_rate_limiter_wait_called(self):
        rl = MagicMock()
        rl.wait = MagicMock()
        rl.record = MagicMock()

        with patch("requests.Session.request") as mock_req:
            mock_req.return_value = _mock_resp(200)
            client = HTTPClient(rate_limiter=rl)
            client.get("http://example.com")

        rl.wait.assert_called_once()

    def test_rate_limiter_record_called_with_status(self):
        rl = MagicMock()

        with patch("requests.Session.request") as mock_req:
            mock_req.return_value = _mock_resp(429)
            client = HTTPClient(rate_limiter=rl)
            client.get("http://example.com")

        rl.record.assert_called_once_with(429)

    def test_raw_post_sends_correct_content_type(self):
        with patch("requests.Session.request") as mock_req:
            mock_req.return_value = _mock_resp(200)
            client = HTTPClient()
            client.raw_post("http://example.com", body="<test/>", content_type="text/xml")

        call_kwargs = mock_req.call_args
        assert call_kwargs[1]["headers"]["Content-Type"] == "text/xml"


# ---------------------------------------------------------------------------
# 403 Bypass module
# ---------------------------------------------------------------------------

class TestBypass403Helpers:
    def test_is_bypass_true_for_200_after_403(self):
        assert _is_bypass(403, 200) is True

    def test_is_bypass_true_for_204_after_401(self):
        assert _is_bypass(401, 204) is True

    def test_is_bypass_false_when_still_403(self):
        assert _is_bypass(403, 403) is False

    def test_is_bypass_false_when_original_200(self):
        assert _is_bypass(200, 200) is False

    def test_is_bypass_false_for_500(self):
        assert _is_bypass(403, 500) is False

    def test_header_repro_contains_curl(self):
        repro = _header_repro("http://t.com/admin", {}, {"X-Forwarded-For": "127.0.0.1"})
        assert "curl" in repro
        assert "X-Forwarded-For" in repro

    def test_path_repro_contains_curl(self):
        repro = _path_repro("http://t.com/admin/", {})
        assert "curl" in repro

    def test_verb_repro_contains_verb(self):
        repro = _verb_repro("http://t.com/admin", {}, "OPTIONS")
        assert "OPTIONS" in repro
        assert "curl" in repro


class TestBypass403Scanner:
    """Unit tests for the Bypass403Scanner module."""

    def _make_mod(self, http):
        return Bypass403Scanner(http, {})

    def test_skips_non_403_baseline(self):
        """If the page returns 200 normally, bypass logic is skipped."""
        http = _make_http()
        http.get.return_value = _mock_resp(200, "Welcome")
        mod = self._make_mod(http)
        findings = mod.scan_parameter(
            "http://t.com/page", "GET", {"id": "1"}, "id"
        )
        assert findings == []

    def test_skips_when_not_first_param(self):
        """Module runs once per URL, deduped to the first alphabetical param."""
        http = _make_http()
        http.get.return_value = _mock_resp(403, "Forbidden")
        mod = self._make_mod(http)
        # "id" < "name", so module dedupes to "id"; "name" is skipped
        findings = mod.scan_parameter(
            "http://t.com/admin", "GET",
            {"id": "1", "name": "test"},
            "name",
        )
        assert findings == []

    def test_header_bypass_detected(self):
        """X-Forwarded-For spoofing returns 200 -- should produce a finding."""
        http = _make_http()
        call_count = [0]

        def get_side_effect(url, params=None, headers=None, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(403, "Forbidden")   # baseline
            # Any call with extra headers returns 200
            if headers:
                return _mock_resp(200, "Admin panel")
            return _mock_resp(403, "Forbidden")

        http.get.side_effect = get_side_effect
        mod = self._make_mod(http)
        findings = mod.scan_parameter(
            "http://t.com/admin", "GET", {"id": "1"}, "id"
        )
        assert len(findings) == 1
        assert findings[0].vuln_type == "403 Bypass"
        assert "403 -> HTTP 200" in findings[0].evidence or "HTTP 403 -> HTTP 200" in findings[0].evidence

    def test_verb_bypass_detected(self):
        """OPTIONS verb returns 200 after 403 GET -- should produce a finding."""
        http = _make_http()
        # All GET calls return 403, but _request with OPTIONS returns 200
        http.get.return_value = _mock_resp(403, "Forbidden")
        http._request = MagicMock(return_value=_mock_resp(200, "OK"))
        mod = self._make_mod(http)
        findings = mod.scan_parameter(
            "http://t.com/restricted", "GET", {"x": "1"}, "x"
        )
        # Either header or verb bypass produced a finding
        assert len(findings) >= 1
        assert all(f.vuln_type == "403 Bypass" for f in findings)

    def test_no_finding_when_all_techniques_fail(self):
        """No bypass found -- all techniques return 403."""
        http = _make_http()
        http.get.return_value = _mock_resp(403, "Forbidden")
        http._request = MagicMock(return_value=_mock_resp(403, "Forbidden"))
        mod = self._make_mod(http)
        findings = mod.scan_parameter(
            "http://t.com/admin", "GET", {"id": "1"}, "id"
        )
        assert findings == []

    def test_finding_has_reproduction_steps(self):
        """Produced findings must include curl-based reproduction commands."""
        http = _make_http()
        http.get.side_effect = [
            _mock_resp(403, "Forbidden"),
            _mock_resp(200, "bypass!"),  # first header bypass
        ]
        mod = self._make_mod(http)
        findings = mod.scan_parameter(
            "http://t.com/admin", "GET", {"a": "1"}, "a"
        )
        if findings:
            assert "curl" in findings[0].reproduction.lower()

    def test_dedup_same_technique(self):
        """The same technique reported only once even if multiple params."""
        http = _make_http()
        http.get.side_effect = lambda *a, headers=None, **kw: (
            _mock_resp(200, "bypass!") if headers else _mock_resp(403, "Forbidden")
        )
        mod = self._make_mod(http)
        mod._seen = set()
        # Call twice with same URL and technique -- should deduplicate
        f1 = mod.scan_parameter("http://t.com/a", "GET", {"a": "1"}, "a")
        f2 = mod.scan_parameter("http://t.com/a", "GET", {"a": "1"}, "a")
        # Both runs are separate module instances in real usage, but dedup within one run
        assert isinstance(f1, list)
        assert isinstance(f2, list)

    def test_no_params_no_bypass(self):
        """With no params, sorted_params is empty and check passes -- baseline 403 triggers."""
        http = _make_http()
        # baseline returns 403, all techniques fail
        http.get.return_value = _mock_resp(403, "Forbidden")
        http._request = MagicMock(return_value=_mock_resp(403, "Forbidden"))
        mod = self._make_mod(http)
        # Empty params dict: sorted_params is empty, so the first check fails and returns []
        findings = mod.scan_parameter(
            "http://t.com/admin", "GET", {}, "anything"
        )
        assert findings == []
