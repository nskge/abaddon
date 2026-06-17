"""Tests for the insecure-deserialization and race-condition modules."""

import base64
import pytest
from unittest.mock import MagicMock

from scanner.modules.deserialization import (
    detect_serialized, DeserializationScanner, _viewstate_unprotected,
)
from scanner.modules.race import (
    looks_stateful, analyze_burst, RaceConditionScanner,
)
from scanner.exploit_hints import suggest
from scanner.modules.base import Finding


# ---------------------------------------------------------------------------
# Deserialization — format detection
# ---------------------------------------------------------------------------

def test_detect_java_base64():
    # base64 of 0xAC 0xED 0x00 0x05 ...
    blob = base64.b64encode(b"\xac\xed\x00\x05testdata").decode()
    hit = detect_serialized(blob)
    assert hit is not None and hit[0] == "Java"


def test_detect_java_ro0_prefix():
    hit = detect_serialized("rO0ABXNyABZqYXZh")
    assert hit[0] == "Java" and hit[1] == "high"


def test_detect_php_object():
    hit = detect_serialized('O:8:"stdClass":1:{s:4:"name";s:3:"abc";}')
    assert hit[0] == "PHP"


def test_detect_php_array():
    hit = detect_serialized('a:2:{i:0;s:1:"a";i:1;s:1:"b";}')
    assert hit[0] == "PHP"


def test_detect_pickle_base64():
    blob = base64.b64encode(b"\x80\x04test").decode()
    hit = detect_serialized(blob)
    assert hit[0] == "Python pickle"


def test_detect_pickle_raw_proto():
    hit = detect_serialized("\x80\x04\x95abc")
    assert hit[0] == "Python pickle"


def test_detect_ruby_marshal():
    blob = base64.b64encode(b"\x04\x08[\x06").decode()
    hit = detect_serialized(blob)
    assert hit[0] == "Ruby Marshal"


def test_detect_dotnet_viewstate():
    hit = detect_serialized("AAEAAAD/////AQAAAAAAAAAM")
    assert hit[0] == ".NET"


def test_detect_node_serialize():
    hit = detect_serialized('{"x":"_$$ND_FUNC$$_function(){}"}')
    assert hit[0] == "Node"


def test_detect_yaml_python():
    hit = detect_serialized("!!python/object/apply:os.system ['id']")
    assert hit[0] == "YAML"


def test_detect_benign_value_none():
    assert detect_serialized("hello world") is None
    assert detect_serialized("12345") is None
    assert detect_serialized("") is None


def test_detect_url_encoded_php():
    # URL-encoded PHP object should still be recognised after unquote
    hit = detect_serialized('O%3A8%3A%22stdClass%22%3A0%3A%7B%7D')
    assert hit is not None and hit[0] == "PHP"


def test_viewstate_unprotected():
    assert _viewstate_unprotected("/wEPDwUKLT...")


# ---------------------------------------------------------------------------
# Deserialization — scanner integration
# ---------------------------------------------------------------------------

def test_deserial_scanner_flags_param():
    scanner = DeserializationScanner(MagicMock(), {})
    findings = scanner.scan_parameter(
        "http://t/load", "POST", {"data": "rO0ABXNyABZqYXZh"}, "data",
    )
    assert any("Java" in f.vuln_type for f in findings)


def test_deserial_scanner_flags_cookie():
    scanner = DeserializationScanner(MagicMock(), {"cookies": {"sess": "rO0ABXNy"}})
    findings = scanner.scan_parameter(
        "http://t/x", "GET", {"q": "benign"}, "q",
    )
    assert any("cookie:sess" in f.parameter for f in findings)


def test_deserial_scanner_clean_param_no_finding():
    scanner = DeserializationScanner(MagicMock(), {})
    findings = scanner.scan_parameter(
        "http://t/x", "GET", {"q": "normal text"}, "q",
    )
    assert findings == []


def test_deserial_hint_present():
    f = Finding("Insecure Deserialization (Java)", "http://t/x", "POST", "data",
                "rO0", "java blob", confidence="high")
    h = suggest(f)
    assert h and "ysoserial" in h


# ---------------------------------------------------------------------------
# Race condition — heuristics
# ---------------------------------------------------------------------------

def test_looks_stateful_post():
    assert looks_stateful("http://t/buy", "POST", {})


def test_looks_stateful_coupon_get():
    assert looks_stateful("http://t/apply?coupon=X", "GET", {"coupon": "X"})


def test_looks_stateful_plain_get_false():
    assert not looks_stateful("http://t/about", "GET", {"page": "1"})


def test_analyze_burst_mixed_statuses():
    baseline = (200, 100)
    burst = [(200, 100)] * 5 + [(429, 20)] * 5
    sig = analyze_burst(baseline, burst)
    assert sig and "mixed" in sig


def test_analyze_burst_all_success_overrun():
    baseline = (200, 100)
    burst = [(200, 100)] * 20
    sig = analyze_burst(baseline, burst)
    assert sig and "concurrent" in sig


def test_analyze_burst_no_signal_single_reject():
    # baseline succeeds but burst all rejected → no overrun signal
    baseline = (200, 100)
    burst = [(403, 10)] * 20
    sig = analyze_burst(baseline, burst)
    assert sig is None


def test_analyze_burst_empty():
    assert analyze_burst((200, 100), []) is None


def test_race_skips_non_stateful():
    scanner = RaceConditionScanner(MagicMock(), {})
    findings = scanner.scan_parameter("http://t/about", "GET", {"page": "1"}, "page")
    assert findings == []


def test_race_hint_present():
    f = Finding("Race Condition (potential limit-overrun)", "http://t/redeem",
                "POST", "coupon", "20x", "burst", confidence="low")
    h = suggest(f)
    assert h and "Turbo Intruder" in h
