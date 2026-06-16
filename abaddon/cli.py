"""ABADDON command-line interface (rich-powered).

Usage::

    python -m abaddon -u https://target.example.com
    python -m abaddon -u https://target.example.com -t abaddon/templates --scope "*.example.com"

Authorized testing only — when ``--scope`` is set, out-of-scope hosts are
refused before any packet is sent.
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from . import __version__
from .core.logger import ResultSink, configure
from .core.oast import MockOASTProvider, OASTProvider, WebhookOASTProvider
from .core.runner import Scanner
from .core.scope import Scope
from .network.engine import AsyncEngine
from .network.evasion import Evasion
from .parsers.template_engine import load_templates

_BANNER = r"""
   ▄▄▄       ▄▄▄▄    ▄▄▄      ▓█████▄ ▓█████▄  ▒█████   ███▄    █
  ▒████▄    ▓█████▄ ▒████▄    ▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █
  ▒██  ▀█▄  ▒██▒ ▄██▒██  ▀█▄  ░██   █▌░██   █▌▒██░  ██▒▓██  ▀█ ██▒
  ░██▄▄▄▄██ ▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒
   ▓█   ▓██▒░▓█  ▀█▓ ▓█   ▓██▒░▒████▓ ░▒████▓ ░ ████▓▒░▒██░   ▓██░
   ▒▒   ▓▒█░░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
        async offensive engine · authorized testing only
"""

console = Console(stderr=True)


def _build_oast(args) -> Optional[OASTProvider]:
    if args.oast_domain and args.oast_poll_url:
        return WebhookOASTProvider(args.oast_domain, args.oast_poll_url)
    if args.oast_mock:
        return MockOASTProvider()
    return None


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="abaddon", description="ABADDON async scanner")
    p.add_argument("-u", "--url", required=True, help="Base target URL")
    p.add_argument(
        "-t", "--templates",
        default=str(Path(__file__).parent / "templates"),
        help="Template directory (default: bundled templates)",
    )
    p.add_argument("-c", "--concurrency", type=int, default=150)
    p.add_argument("--rate", type=float, default=0.0, help="Global requests/sec cap (0=unlimited)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--no-http2", action="store_true")
    p.add_argument("--scope", default="", help="Comma-separated host globs e.g. '*.example.com'")
    p.add_argument("--scope-cidr", default="", help="Comma-separated CIDRs e.g. '10.0.0.0/8'")
    p.add_argument("--no-baseline", action="store_true", help="Skip baseline request")
    p.add_argument("--ua-rotate", action="store_true", help="Rotate User-Agent per request")
    p.add_argument("--ip-spoof", action="store_true", help="Inject X-Forwarded-For et al.")
    p.add_argument("--oast-domain", default="", help="OAST base domain")
    p.add_argument("--oast-poll-url", default="", help="OAST poll endpoint URL")
    p.add_argument("--oast-mock", action="store_true", help="Use in-memory mock OAST")
    p.add_argument("-o", "--output", default="abaddon_results.jsonl", help="JSONL results file")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"ABADDON {__version__}")
    return p.parse_args(argv)


async def _run(args) -> int:
    scope = Scope(
        patterns=[s for s in args.scope.split(",") if s.strip()],
        cidrs=[c for c in args.scope_cidr.split(",") if c.strip()],
    )
    if scope.enabled and not scope.allows(args.url):
        console.print(f"[red]Target {args.url} is out of scope — aborting.[/red]")
        return 2

    report = load_templates(args.templates)
    console.print(
        f"[cyan]Templates:[/cyan] {report.ok_count} loaded, {report.error_count} rejected"
    )
    if not report.loaded:
        console.print("[red]No valid templates — nothing to do.[/red]")
        return 1

    evasion = (
        Evasion(rotate_ua=args.ua_rotate, ip_spoof=args.ip_spoof)
        if (args.ua_rotate or args.ip_spoof)
        else None
    )
    oast = _build_oast(args)
    sink = ResultSink(args.output)

    async with AsyncEngine(
        concurrency=args.concurrency,
        rate=args.rate,
        timeout=args.timeout,
        http2=not args.no_http2,
        scope=scope,
        evasion=evasion,
    ) as engine:
        scanner = Scanner(
            engine, report.loaded, oast=oast, use_baseline=not args.no_baseline
        )
        with console.status("[bold]Scanning…[/bold]"):
            findings = await scanner.scan(args.url)

    _print_findings(args.url, findings, sink, engine)
    return 0


def _print_findings(target, findings, sink, engine) -> None:
    if not findings:
        console.print(
            f"[green]No findings.[/green] "
            f"({engine.stats.sent} requests, {engine.stats.errors} errors, "
            f"{engine.stats.rps:.0f} req/s)"
        )
        return

    table = Table(title=f"ABADDON findings — {target}")
    table.add_column("Severity", style="bold")
    table.add_column("Template")
    table.add_column("Confidence", justify="right")
    table.add_column("URL")
    for f in sorted(findings, key=lambda x: -x.confidence):
        sink.write(target, f)
        table.add_row(f.severity.upper(), f.template_id, f"{f.confidence:.0%}", f.url)
    console.print(table)
    console.print(
        f"[bold]{len(findings)}[/bold] finding(s) written to {sink.path} · "
        f"{engine.stats.sent} requests, {engine.stats.errors} errors, "
        f"{engine.stats.rps:.0f} req/s, {engine.throttle.throttled_hosts} host(s) throttled"
    )


def main(argv: Optional[List[str]] = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]
    # No arguments → drop into the interactive menu.
    if not raw:
        from .menu import run_menu

        return run_menu()
    args = parse_args(raw)
    configure(args.verbose)
    console.print(f"[red]{_BANNER}[/red]")
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — returning partial results.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
