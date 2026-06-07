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
import sys
import time

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
        choices=["sqli", "xss", "lfi", "redirect", "cmdi", "crlf", "ssti", "headers", "all"],
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
    if args.user_agent:
        headers["User-Agent"] = args.user_agent

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
