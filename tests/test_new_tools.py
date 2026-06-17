"""Tests for nuclei, nikto, and wpscan integrations."""

import json
import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from scanner.tools.nuclei import NucleiRunner, _parse_output as _nuclei_parse, _build_command as _nuclei_cmd
from scanner.tools.nikto import NiktoRunner, _parse_json_output, _parse_text_output, _build_command as _nikto_cmd
from scanner.tools.wpscan import WPScanRunner, _parse_output as _wpscan_parse, _looks_like_wordpress, _build_command as _wpscan_cmd


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

_NUCLEI_JSONL = json.dumps({
    "template-id": "CVE-2020-11022",
    "info": {
        "name": "jQuery XSS (CVE-2020-11022)",
        "severity": "medium",
        "description": "XSS in jQuery htmlPrefilter",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"],
    },
    "matched-at": "https://target.com/page",
    "curl-command": "curl -s 'https://target.com/page'",
    "extracted-results": ["Jquery/1.7.1"],
}) + "\n"


def test_nuclei_parse_single():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(_NUCLEI_JSONL)
        path = f.name
    try:
        findings = _nuclei_parse(path, "https://target.com/page")
        assert len(findings) == 1
        f = findings[0]
        assert "CVE-2020-11022" in f.vuln_type or "jQuery" in f.vuln_type
        assert f.confidence == "medium"
        assert "[nuclei]" in f.vuln_type
    finally:
        os.unlink(path)


def test_nuclei_parse_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
    try:
        findings = _nuclei_parse(path, "https://target.com/")
        assert findings == []
    finally:
        os.unlink(path)


def test_nuclei_parse_missing_file():
    findings = _nuclei_parse("/nonexistent/path.jsonl", "https://target.com/")
    assert findings == []


def test_nuclei_build_command_basic():
    cmd = _nuclei_cmd(
        url="https://t.lo/",
        templates_dir=None,
        tags="cve,rce",
        severity="high,critical",
        proxy=None,
        headers={},
        cookies="",
        timeout=10,
        output_file="/tmp/out.jsonl",
    )
    assert "nuclei" in cmd
    assert "-u" in cmd
    assert "-j" in cmd
    assert "-severity" in cmd


def test_nuclei_build_command_with_proxy():
    cmd = _nuclei_cmd(
        url="https://t.lo/",
        templates_dir=None,
        tags="cve",
        severity="high",
        proxy="http://127.0.0.1:8080",
        headers={"X-Custom": "val"},
        cookies="sid=abc",
        timeout=10,
        output_file="/tmp/out.jsonl",
    )
    assert "-proxy" in cmd
    assert "-H" in cmd


def test_nuclei_runner_not_available():
    runner = NucleiRunner(config={})
    with patch("scanner.tools.is_available", return_value=False):
        findings = runner.run("https://target.com/")
    assert findings == []


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------

_NIKTO_JSON = {
    "vulnerabilities": [
        {
            "msg": "The anti-clickjacking X-Frame-Options header is not present.",
            "uri": "/",
            "OSVDB": "",
        },
        {
            "msg": "OSVDB-3268: /admin/: Directory indexing found.",
            "uri": "/admin/",
            "OSVDB": "3268",
        },
    ]
}

_NIKTO_TEXT = """\
+ Server: Apache/2.4.49
+ /cgi-bin/test.cgi: This might be interesting - has been seen in web logs from an unknown scanner.
+ OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests.
+ 8 host(s) tested
"""


def test_nikto_parse_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(_NIKTO_JSON, f)
        path = f.name
    try:
        findings = _parse_json_output(path, "http://target.com")
        assert len(findings) == 2
        urls = [f.url for f in findings]
        assert any("/admin/" in u for u in urls)
    finally:
        os.unlink(path)


def test_nikto_parse_text():
    findings = _parse_text_output(_NIKTO_TEXT, "http://target.com")
    assert len(findings) >= 1
    assert all("[nikto]" in f.vuln_type for f in findings)


def test_nikto_parse_json_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{}")
        path = f.name
    try:
        findings = _parse_json_output(path, "http://target.com")
        assert findings == []
    finally:
        os.unlink(path)


def test_nikto_build_command():
    cmd = _nikto_cmd(
        url="http://target.com",
        proxy=None, cookies="", headers={}, timeout=60,
        output_file="/tmp/nikto.json",
    )
    assert "nikto" in cmd
    assert "-host" in cmd
    assert "-Format" in cmd


def test_nikto_runner_not_available():
    runner = NiktoRunner(config={})
    with patch("scanner.tools.is_available", return_value=False):
        findings = runner.run("http://target.com")
    assert findings == []


# ---------------------------------------------------------------------------
# wpscan
# ---------------------------------------------------------------------------

_WPSCAN_JSON = {
    "version": {
        "number": "5.9.3",
        "vulnerabilities": [
            {
                "title": "WP Core <= 5.9.3 - SQL Injection via WP_Date_Query",
                "references": {
                    "cve": ["2022-21661"],
                    "url": ["https://wpscan.com/vulnerability/abc"],
                },
            }
        ],
    },
    "plugins": {
        "contact-form-7": {
            "version": {"number": "5.5.6"},
            "vulnerabilities": [
                {
                    "title": "CF7 < 5.6 - Reflected XSS",
                    "references": {"cve": ["2022-1234"], "url": []},
                }
            ],
        }
    },
    "users": {"admin": {}, "editor": {}},
}


def test_wpscan_parse_core_vuln():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(_WPSCAN_JSON, f)
        path = f.name
    try:
        findings = _wpscan_parse(path, "http://wp.test/")
        types = [f.vuln_type for f in findings]
        assert any("Core" in t or "core" in t.lower() for t in types)
    finally:
        os.unlink(path)


def test_wpscan_parse_plugin_vuln():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(_WPSCAN_JSON, f)
        path = f.name
    try:
        findings = _wpscan_parse(path, "http://wp.test/")
        types = [f.vuln_type for f in findings]
        assert any("Plugin" in t for t in types)
    finally:
        os.unlink(path)


def test_wpscan_parse_user_enum():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(_WPSCAN_JSON, f)
        path = f.name
    try:
        findings = _wpscan_parse(path, "http://wp.test/")
        types = [f.vuln_type for f in findings]
        assert any("User Enumeration" in t for t in types)
    finally:
        os.unlink(path)


def test_wpscan_looks_like_wordpress_url():
    assert _looks_like_wordpress({}, "https://site.com/wp-login.php")
    assert _looks_like_wordpress({}, "https://site.com/wp-content/themes/x")
    assert not _looks_like_wordpress({}, "https://site.com/login")


def test_wpscan_looks_like_wordpress_techs():
    assert _looks_like_wordpress({"_detected_techs": ["WordPress", "PHP"]}, "https://site.com/")


def test_wpscan_runner_not_available():
    runner = WPScanRunner(config={})
    with patch("scanner.tools.is_available", return_value=False):
        findings = runner.run("http://wp.test/")
    assert findings == []


def test_wpscan_build_command():
    cmd = _wpscan_cmd(
        url="http://wp.test/", api_token=None, enumerate="vp,u",
        proxy=None, cookies="", timeout=30, output_file="/tmp/wp.json",
    )
    assert "wpscan" in cmd
    assert "--url" in cmd
    assert "--format" in cmd


# ---------------------------------------------------------------------------
# Static detection bypass for form targets (regression for XSS-not-found bug)
# ---------------------------------------------------------------------------

def test_form_target_not_blocked_by_static_detection():
    """Form targets must run injection modules even when _static_target is True."""
    from scanner.core import Scanner
    config = {
        "url": "http://example.com/",
        "method": "GET",
        "data": "",
        "scan_type": "xss",
        "headers": {},
        "cookies": {},
        "proxy": None,
        "timeout": 5,
        "follow_redirects": False,
        "threads": 1,
        "verbose": False,
        "quiet": True,
        "no_color": True,
        "waf_evasion": 0,
        "crawl": False,
        "js_crawl": False,
        "custom_payloads": None,
        "delay_threshold": 5.0,
        "auth_username": None,
        "auth_password": None,
        "auth_login_url": "/login",
        "auth_username2": None,
        "auth_password2": None,
        "orchestrated": False,
        "port_scan": False,
        "discover_paths": False,
        "discover_subs": False,
        "rate_limit": False,
        "rate_limit_delay": 0.0,
        "bb_note": None,
        "bb_program": None,
        "use_sqlmap": False,
        "use_dalfox": False,
        "use_nuclei": False,
        "use_nikto": False,
        "use_wpscan": False,
        "ext_tools": False,
    }
    scanner = Scanner(config)
    scanner._static_target = True  # simulate static detection triggered

    # A form target should NOT have injection skipped
    form_target = {
        "url": "http://example.com/search",
        "method": "POST",
        "params": {"q": ""},
        "param_name": "q",
        "is_form": True,
    }

    from scanner.modules.xss import XSSScanner
    _INJECTION_MODULES = {
        "sqli", "xss", "lfi", "cmdi", "ssti", "crlf",
        "redirect", "jwt", "ssrf", "xxe", "bypass403",
    }
    static = scanner._static_target and not form_target.get("is_form")
    active = [
        cls for cls in scanner.module_classes
        if not (static and cls.NAME in _INJECTION_MODULES)
    ]
    # XSS should be active for form targets
    assert any(cls.NAME == "xss" for cls in active), "XSSScanner must run on form targets"
