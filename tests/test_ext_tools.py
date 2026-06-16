"""Tests for external tool integration (sqlmap / dalfox)."""

import pytest
from unittest.mock import MagicMock, patch

from scanner.tools import is_available, check_version
from scanner.tools.sqlmap import SqlmapRunner, _pick_tampers, _parse_output, _build_command
from scanner.tools.dalfox import DalfoxRunner, _parse_output as _dalfox_parse


# ---------------------------------------------------------------------------
# scanner.tools helpers
# ---------------------------------------------------------------------------

def test_is_available_python():
    assert is_available("python") or is_available("python3")


def test_is_available_missing():
    assert not is_available("__nonexistent_binary_xyz__")


def test_check_version_missing():
    assert check_version("__nonexistent_binary_xyz__") is None


# ---------------------------------------------------------------------------
# sqlmap tamper selection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("waf,expected", [
    ("Cloudflare",       "charunicodeencode"),
    ("cloudflare challenge", "charunicodeencode"),
    ("ModSecurity",      "chardoubleencode"),
    ("Imperva/Incapsula","charunicodeencode"),
    ("DDoS-Guard",       "between"),
    ("Unknown WAF XYZ",  "between"),   # falls back to generic
    ("",                 "between"),
])
def test_pick_tampers(waf, expected):
    tampers = _pick_tampers(waf)
    assert expected in tampers
    assert "between" in tampers      # always present


def test_pick_tampers_cloudflare_has_five():
    assert len(_pick_tampers("Cloudflare")) >= 4


# ---------------------------------------------------------------------------
# sqlmap output parser
# ---------------------------------------------------------------------------

_SQLMAP_OUTPUT = """\
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5678=5678

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71,version()),NULL--

---
[INFO] the back-end DBMS is MySQL
web application technology: PHP 7.4
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
"""


def test_parse_output_finds_three_techniques():
    findings = _parse_output(_SQLMAP_OUTPUT, "http://target/?id=1")
    assert len(findings) == 3


def test_parse_output_types():
    findings = _parse_output(_SQLMAP_OUTPUT, "http://target/?id=1")
    types = [f.vuln_type for f in findings]
    assert any("boolean-based" in t for t in types)
    assert any("time-based" in t for t in types)
    assert any("UNION" in t for t in types)


def test_parse_output_param_name():
    findings = _parse_output(_SQLMAP_OUTPUT, "http://target/?id=1")
    assert all(f.parameter == "id" for f in findings)


def test_parse_output_confidence_high():
    findings = _parse_output(_SQLMAP_OUTPUT, "http://target/?id=1")
    assert all(f.confidence == "high" for f in findings)


def test_parse_output_dbms_in_evidence():
    findings = _parse_output(_SQLMAP_OUTPUT, "http://target/?id=1")
    assert all("MySQL" in f.evidence for f in findings)


def test_parse_output_empty():
    findings = _parse_output("no findings here", "http://target/?id=1")
    assert findings == []


def test_parse_output_not_injectable():
    out = "[INFO] GET parameter 'id' does not seem to be injectable"
    findings = _parse_output(out, "http://target/?id=1")
    assert findings == []


# ---------------------------------------------------------------------------
# sqlmap command builder
# ---------------------------------------------------------------------------

def test_build_command_basic():
    cmd = _build_command(
        url="http://t.lo/?id=1", param="id", method="GET", data="",
        waf_name="", waf_evasion=0, dbms=None,
        cookies="", proxy=None, output_dir="/tmp/x",
        extra_headers={}, timeout=30, delay=0,
    )
    assert "sqlmap" in cmd
    assert "-u" in cmd
    assert "--batch" in cmd
    assert "--random-agent" in cmd


def test_build_command_cloudflare_adds_tampers():
    cmd = _build_command(
        url="http://t.lo/?id=1", param="id", method="GET", data="",
        waf_name="Cloudflare", waf_evasion=1, dbms=None,
        cookies="", proxy=None, output_dir="/tmp/x",
        extra_headers={}, timeout=30, delay=0,
    )
    tamper_idx = cmd.index("--tamper") + 1
    tampers = cmd[tamper_idx]
    assert "charunicodeencode" in tampers


def test_build_command_cloudflare_adds_delay():
    cmd = _build_command(
        url="http://t.lo/?id=1", param="id", method="GET", data="",
        waf_name="Cloudflare", waf_evasion=1, dbms=None,
        cookies="", proxy=None, output_dir="/tmp/x",
        extra_headers={}, timeout=30, delay=0,  # delay=0 → auto-add for CF
    )
    assert "--delay" in cmd


def test_build_command_post_adds_data():
    cmd = _build_command(
        url="http://t.lo/login", param=None, method="POST",
        data="user=admin&pass=test",
        waf_name="", waf_evasion=0, dbms="mysql",
        cookies="", proxy=None, output_dir="/tmp/x",
        extra_headers={}, timeout=30, delay=0,
    )
    assert "--data" in cmd
    assert "--dbms" in cmd


def test_build_command_proxy():
    cmd = _build_command(
        url="http://t.lo/?id=1", param=None, method="GET", data="",
        waf_name="", waf_evasion=0, dbms=None,
        cookies="", proxy="http://127.0.0.1:8080",
        output_dir="/tmp/x", extra_headers={}, timeout=30, delay=0,
    )
    assert "--proxy" in cmd


# ---------------------------------------------------------------------------
# SqlmapRunner — sqlmap not installed
# ---------------------------------------------------------------------------

def test_sqlmap_runner_not_available():
    runner = SqlmapRunner(config={"scan_type": "sqli"})
    with patch("scanner.tools.is_available", return_value=False):
        findings = runner.run("http://target/?id=1")
    assert findings == []


# ---------------------------------------------------------------------------
# dalfox output parser
# ---------------------------------------------------------------------------

_DALFOX_LINE = (
    '{"type":"G","poc":"http://target/?q=<script>alert(1)</script>",'
    '"param":"q","data":"<script>alert(1)</script>",'
    '"evidence":"Triggered alert in browser context"}\n'
)


def test_dalfox_parse_single_finding():
    findings = _dalfox_parse(_DALFOX_LINE, "http://target/?q=test")
    assert len(findings) == 1
    f = findings[0]
    assert f.parameter == "q"
    assert "scripting" in f.vuln_type.lower() or "xss" in f.vuln_type.lower()
    assert f.confidence == "high"


def test_dalfox_parse_empty():
    findings = _dalfox_parse("no json here\n", "http://target/")
    assert findings == []


def test_dalfox_parse_multiple():
    two = _DALFOX_LINE + _DALFOX_LINE.replace('"q"', '"search"')
    findings = _dalfox_parse(two, "http://target/?q=x")
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# DalfoxRunner — dalfox not installed
# ---------------------------------------------------------------------------

def test_dalfox_runner_not_available():
    runner = DalfoxRunner(config={"scan_type": "xss"})
    with patch("scanner.tools.is_available", return_value=False):
        findings = runner.run("http://target/?q=1")
    assert findings == []
