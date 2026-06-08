#!/usr/bin/env python3
"""
OkrScann -- Web Vulnerability Scanner
======================================
Modular scanner for SQLi, XSS, LFI, CMDi, SSTI, CRLF, Open Redirects,
and Security Header analysis.

DISCLAIMER: This tool is provided for authorized security testing and
educational purposes ONLY. The author assumes NO responsibility or liability
for any misuse or damage. Only run against systems you own or have explicit
written permission to test. Unauthorized use may violate applicable laws.
"""

import argparse
import fnmatch
import sys
import time
from urllib.parse import urlparse

from scanner.banner import print_banner
from scanner.core import Scanner
from scanner.logger import setup_logger
from scanner.reporter import Reporter


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="okrscann",
        description="OkrScann -- Modular web vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Full scan on GET params
  python main.py -u "http://target.local/page?id=1"

  # Auto-detect forms on a page (no need to know field names)
  python main.py -u "http://target.local/search.php" --crawl

  # XSS-only on a POST form
  python main.py -u "http://target.local/search.php" -m POST -d "q=test" --scan-type xss

  # SQLi on a specific param
  python main.py -u "http://target.local/page?id=1&cat=2" --scan-type sqli -p id

  # Route through Burp Suite
  python main.py -u "http://target.local/?q=test" --proxy http://127.0.0.1:8080

  # Export findings to JSON
  python main.py -u "http://target.local/?q=test" -o report.json --format json

  # Custom payloads
  python main.py -u "http://target.local/?q=1" --scan-type sqli --payloads payloads/sqli.txt
        """,
    )

    # ---- Target ----
    tgt = parser.add_argument_group("Target")
    tgt.add_argument("-u", "--url", required=True, help="Target URL (include query params for GET)")
    tgt.add_argument(
        "-m", "--method",
        choices=["GET", "POST"], default="GET",
        help="HTTP method  (default: GET)",
    )
    tgt.add_argument(
        "-d", "--data",
        metavar="POST_DATA",
        help="POST body  e.g. 'user=admin&pass=test'",
    )
    tgt.add_argument(
        "-p", "--param",
        metavar="PARAM_NAME",
        help="Only test this parameter (default: all detected)",
    )

    # ---- Scan ----
    scan = parser.add_argument_group("Scan options")
    scan.add_argument(
        "--scan-type",
        choices=[
            "sqli", "xss", "lfi", "redirect", "cmdi", "crlf",
            "ssti", "headers", "jwt", "ssrf", "xxe", "all",
        ],
        default="all",
        help="Vulnerability type to scan for  (default: all)",
    )
    scan.add_argument(
        "--crawl", action="store_true",
        help="Auto-detect HTML forms on the page and test their fields",
    )
    scan.add_argument(
        "--payloads",
        metavar="FILE",
        help="Custom payload file (one payload per line; # = comment)",
    )
    scan.add_argument(
        "--delay", type=float, default=5.0,
        help="Time-based detection threshold in seconds  (default: 5.0)",
    )
    scan.add_argument(
        "--threads", type=int, default=4, metavar="N",
        help="Max concurrent module threads per parameter  (default: 4)",
    )
    scan.add_argument(
        "--waf-evasion", type=int, default=0, choices=[0, 1, 2, 3], metavar="LEVEL",
        help=(
            "Expand payloads with WAF bypass variants  "
            "0=off  1=url+null  2=+double+case  3=+html+sqli-comments  (default: 0)"
        ),
    )

    # ---- Recon extras ----
    recon = parser.add_argument_group("Recon extras")
    recon.add_argument(
        "--port-scan", action="store_true",
        help="Run a fast TCP port scan during recon phase",
    )
    recon.add_argument(
        "--discover-paths", action="store_true",
        help="Probe common URL paths on the target during recon",
    )
    recon.add_argument(
        "--discover-subs", action="store_true",
        help="Enumerate common subdomains of the target domain during recon",
    )

    # ---- Rate limiting ----
    rate = parser.add_argument_group("Rate limiting")
    rate.add_argument(
        "--rate-limit", action="store_true",
        help="Enable adaptive rate limiter (auto back-off on 429/503)",
    )
    rate.add_argument(
        "--rate-delay", type=float, default=0.0, metavar="SECS",
        help="Minimum delay between requests when rate limiting is on  (default: 0.0)",
    )

    # ---- Bug bounty ----
    bb = parser.add_argument_group("Bug bounty")
    bb.add_argument(
        "--bb-note", metavar="EMAIL",
        help=(
            "Add X-Bug-Bounty header to all requests identifying you as the researcher. "
            "e.g. --bb-note researcher@example.com"
        ),
    )
    bb.add_argument(
        "--bb-program", metavar="PROGRAM",
        help="Bug bounty program name appended to User-Agent  e.g. h1/program-slug",
    )
    bb.add_argument(
        "--scope", metavar="PATTERNS",
        help=(
            "Comma-separated allowed scope patterns  e.g. '*.example.com,api.example.com'. "
            "The scanner will warn and abort if the target is out of scope."
        ),
    )

    # ---- HTTP ----
    http = parser.add_argument_group("HTTP options")
    http.add_argument(
        "--headers", nargs="*", metavar="HEADER",
        help="Extra HTTP headers  e.g. 'Authorization: Bearer tok'",
    )
    http.add_argument(
        "--cookies", metavar="COOKIES",
        help="Cookie string  e.g. 'session=abc; role=admin'",
    )
    http.add_argument("--proxy", metavar="URL", help="Proxy  e.g. http://127.0.0.1:8080")
    http.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds  (default: 10)")
    http.add_argument("--user-agent", metavar="UA", help="Override the default User-Agent")
    http.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")

    # ---- Output ----
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE", help="Save report to file")
    out.add_argument("--format", choices=["txt", "json"], default="txt", help="Report format  (default: txt)")
    out.add_argument("-v", "--verbose", action="store_true", help="Debug-level logging")
    out.add_argument("-q", "--quiet", action="store_true", help="Minimal output -- findings only")
    out.add_argument("--no-color", action="store_true", help="Disable ANSI colours")

    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    # Scope check (before anything else)
    if args.scope:
        patterns = [p.strip() for p in args.scope.split(",") if p.strip()]
        target_host = urlparse(args.url).hostname or ""
        if not any(fnmatch.fnmatch(target_host, pat) for pat in patterns):
            print(
                f"[!] OUT OF SCOPE: '{target_host}' does not match scope patterns: "
                + ", ".join(patterns)
            )
            print("    Aborting to avoid scanning out-of-scope targets.")
            return 2

    # Print banner (suppressed in quiet mode)
    use_color = not args.no_color
    if not args.quiet:
        print_banner(color=use_color)

    logger = setup_logger(verbose=args.verbose, quiet=args.quiet)

    # Build headers dict
    headers: dict = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    # Bug bounty identification headers
    if args.bb_note:
        headers["X-Bug-Bounty"] = args.bb_note
        headers["X-HackerOne-Research"] = args.bb_note

    # User-Agent: optionally append BB program slug
    ua = args.user_agent or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    if args.bb_program:
        ua = f"{ua} (BugBounty/{args.bb_program})"
    headers["User-Agent"] = ua

    # Build cookies dict
    cookies: dict = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    config = {
        "url": args.url,
        "method": args.method,
        "data": args.data or "",
        "param": args.param,
        "scan_type": args.scan_type,
        "crawl": args.crawl,
        "custom_payloads": args.payloads,
        "delay_threshold": args.delay,
        "headers": headers,
        "cookies": cookies,
        "proxy": args.proxy,
        "timeout": args.timeout,
        "follow_redirects": args.follow_redirects,
        "threads": args.threads,
        "verbose": args.verbose,
        "quiet": args.quiet,
        "no_color": args.no_color,
        # New features
        "waf_evasion":      args.waf_evasion,
        "port_scan":        args.port_scan,
        "discover_paths":   args.discover_paths,
        "discover_subs":    args.discover_subs,
        "rate_limit":       args.rate_limit,
        "rate_limit_delay": args.rate_delay,
        "bb_note":          args.bb_note,
        "bb_program":       args.bb_program,
    }

    scanner = Scanner(config, logger)
    t0 = time.monotonic()
    findings = scanner.run()
    elapsed = time.monotonic() - t0

    reporter = Reporter(no_color=args.no_color)
    reporter.print_summary(
        findings,
        elapsed=elapsed,
        interrupted=scanner._interrupted,
    )

    if args.output and findings:
        reporter.save_report(findings, args.output, args.format)
        logger.info("[+] Report saved: %s", args.output)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
