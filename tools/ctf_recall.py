#!/usr/bin/env python3
"""Measure OkrScann's recall against the Lumen Store CTF ground truth.

Runs a single authenticated, orchestrated scan and maps the findings onto the
9 intentional vulnerabilities listed in ``expected_findings.json``, then prints
``recall = detected / total`` with a per-item breakdown.

Usage:
    # 1. start the CTF:  cd ../CaptureTheOkr/app && python app.py
    # 2. from vuln_scanner/:
    python tools/ctf_recall.py
    python tools/ctf_recall.py --base http://localhost:5000 --gabarito ../../CaptureTheOkr/expected_findings.json
"""

import argparse
import json
import os
import sys

# Make the scanner package importable when run from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core import Scanner  # noqa: E402


# ---------------------------------------------------------------------------
# Mapping: expected id -> predicate(finding) that recognises a detection.
# Kept deliberately loose (class + endpoint hints) so wording tweaks in a
# finding don't silently drop a true positive.
# ---------------------------------------------------------------------------
def _t(f):
    return (f.vuln_type or "").lower()


def _u(f):
    return (f.url or "").lower()


_MATCHERS = {
    "sqli_auth_bypass":   lambda f: "authentication bypass" in _t(f) and "login" in _u(f),
    "sqli_union":         lambda f: "union" in _t(f) and "shop" in _u(f),
    "xss_reflected":      lambda f: "reflected xss" in _t(f) and "shop" in _u(f),
    "xss_stored":         lambda f: "stored" in _t(f) and "xss" in _t(f),
    "idor_order":         lambda f: ("idor" in _t(f) or "bola" in _t(f)) and "order" in (_u(f) + (f.payload or "").lower()),
    "mass_assignment":    lambda f: "mass assignment" in _t(f),
    "broken_access_control": lambda f: "broken access" in _t(f) and "admin" in _u(f),
    "info_disclosure":    lambda f: "sensitive data exposure" in _t(f) or "information disclosure" in _t(f),
    "csrf_change_email":  lambda f: "csrf" in _t(f) and "email" in _u(f),
}


def run_scan(base_url: str, creds: dict) -> list:
    """Run one authenticated, orchestrated scan seeded so every class is reachable."""
    seed = base_url.rstrip("/") + "/shop?q=test"  # seed a searchable param for SQLi/XSS
    config = {
        "url": seed,
        "method": "GET",
        "scan_type": "all",
        "orchestrated": True,            # turn on auth + crawl + active checks
        "auth_login_url": "/login",
        "auth_username": creds["username"],
        "auth_password": creds["password"],
        "crawl_max_pages": 80,
        "crawl_max_depth": 3,
        # Crawl for the orchestrated checks, but only run the heavy per-param
        # module battery on the seed (/shop?q) — keeps the measurement fast.
        "crawl_scan_targets": False,
        "timeout": 10,
        "threads": 6,
        "quiet": True,
        "no_color": True,
        "follow_redirects": True,
        "delay_threshold": 5.0,
        "headers": {}, "cookies": {},
    }
    return Scanner(config).run()


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure scanner recall vs the CTF gabarito.")
    # Default to 127.0.0.1 (not 'localhost'): on Windows 'localhost' resolves to
    # IPv6 ::1 first, and a server bound to IPv4 makes every request pay a failed
    # ::1 connect + retry, turning a 3s scan into minutes.
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument(
        "--gabarito",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "..", "CaptureTheOkr", "expected_findings.json",
        ),
    )
    args = ap.parse_args()

    if not os.path.exists(args.gabarito):
        print(f"[!] gabarito not found: {args.gabarito}")
        print("    pass --gabarito <path to expected_findings.json>")
        return 2
    with open(args.gabarito, encoding="utf-8") as fh:
        gabarito = json.load(fh)
    expected = gabarito["expected"]
    creds = gabarito.get("auth", {}).get("credentials", {"username": "j.doe", "password": "password1"})

    print(f"[*] Scanning {args.base} as {creds['username']} ...")
    findings = run_scan(args.base, creds)
    print(f"[*] Scan produced {len(findings)} finding(s).\n")

    detected, missed = [], []
    matched_by = {}
    for item in expected:
        eid = item["id"]
        pred = _MATCHERS.get(eid, lambda f: False)
        hit = next((f for f in findings if pred(f)), None)
        if hit:
            detected.append(eid)
            matched_by[eid] = hit
        else:
            missed.append(eid)

    total = len(expected)
    n = len(detected)
    print("=" * 64)
    print(f"  RECALL: {n}/{total}  ({100 * n // total}%)")
    print("=" * 64)
    print("\n  DETECTED:")
    for eid in detected:
        f = matched_by[eid]
        print(f"   [+] {eid:24} <- {f.vuln_type} ({f.confidence})")
    print("\n  MISSED:")
    for eid in missed:
        item = next(i for i in expected if i["id"] == eid)
        print(f"   [-] {eid:24} {item['class']} @ {item['endpoint']}")
    print()
    return 0 if n >= 7 else 1


if __name__ == "__main__":
    raise SystemExit(main())
