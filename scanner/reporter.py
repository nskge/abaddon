"""Output formatting and report generation for OkrScann."""

import json
import sys
from datetime import datetime, timezone
from typing import List

from .correlate import correlate_findings
from .modules.base import Finding
from . import __version__

# ---------------------------------------------------------------------------
# ANSI colour helpers (gracefully degraded when colorama is absent)
# ---------------------------------------------------------------------------
try:
    from colorama import init as _cinit
    _cinit(autoreset=True)
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
MAGENTA = "\033[95m"
RESET  = "\033[0m"

_CONF_COLOR = {
    "high":   RED,
    "medium": YELLOW,
    "low":    CYAN,
}

_CONF_ICON = {
    "high":   "[!!!]",
    "medium": "[!!]",
    "low":    "[!]",
}

_TYPE_COLOR = {
    "SQL Injection":       RED,
    "Cross-Site Scripting": MAGENTA,
    "XSS":                 MAGENTA,
    "Local File Inclusion": YELLOW,
    "LFI":                 YELLOW,
    "Open Redirect":       BLUE,
    "Command Injection":   RED,
    "CMDi":                RED,
    "SSTI":                RED,
    "Template Injection":  RED,
    "CRLF":                YELLOW,
    "Response Splitting":  YELLOW,
    "Missing Security":    CYAN,
    "Information Disclosure": CYAN,
    "CORS":                YELLOW,
    "Header":              CYAN,
    "CVE":                 RED,
    "Known CVE":           RED,
}


def _color_for_type(vuln_type: str) -> str:
    """Pick a color based on the vuln type string."""
    for key, color in _TYPE_COLOR.items():
        if key.lower() in vuln_type.lower():
            return color
    return WHITE


class Reporter:
    """Formats findings for console and file output."""

    def __init__(self, no_color: bool = False) -> None:
        self._color_ok = (
            _HAS_COLORAMA
            and not no_color
            and sys.stdout.isatty()
        )

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def print_summary(
        self,
        findings: List[Finding],
        elapsed: float = 0.0,
        interrupted: bool = False,
    ) -> None:
        """Print a structured, human-readable summary to stdout."""
        if interrupted:
            header_line = "  PARTIAL RESULTS (scan interrupted by Ctrl+C)"
        else:
            header_line = "  SCAN RESULTS"
        sep = self._c("  " + "=" * 52, BOLD)

        print()
        print(sep)
        if interrupted:
            print(self._c(header_line, BOLD + YELLOW))
        else:
            print(self._c(header_line, BOLD + CYAN))
        print(sep)

        if not findings:
            print()
            print(self._c("  [*] No vulnerabilities detected.", GREEN))
            print(self._c("      Target appears clean for tested vectors.", DIM))
            print()
            print(sep)
            return

        # Stats
        high   = sum(1 for f in findings if f.confidence == "high")
        medium = sum(1 for f in findings if f.confidence == "medium")
        low    = sum(1 for f in findings if f.confidence == "low")

        print()
        stats = f"  Found {len(findings)} issue(s):"
        if high:
            stats += self._c(f"  {high} HIGH", RED)
        if medium:
            stats += self._c(f"  {medium} MEDIUM", YELLOW)
        if low:
            stats += self._c(f"  {low} LOW", CYAN)
        print(stats)
        print()

        # Sort: HIGH first, then MEDIUM, then LOW
        _severity_order = {"high": 0, "medium": 1, "low": 2}
        sorted_findings = sorted(
            findings, key=lambda f: _severity_order.get(f.confidence, 3),
        )

        for idx, f in enumerate(sorted_findings, 1):
            conf_c = _CONF_COLOR.get(f.confidence, "")
            type_c = _color_for_type(f.vuln_type)
            icon   = _CONF_ICON.get(f.confidence, "[!]")

            # Header bar
            print(self._c(f"  {icon} [{idx}] {f.vuln_type}", BOLD + type_c))
            print(self._c("  " + "-" * 52, DIM))

            # Details
            self._field("URL", f.url)
            self._field("Method", f.method)
            self._field("Param", f.parameter, CYAN)
            self._field("Payload", f.payload)
            self._field("Evidence", f.evidence)
            self._field("Confidence", f.confidence.upper(), conf_c)

            if f.details:
                print()
                for sentence in f.details.split(". "):
                    sentence = sentence.strip().rstrip(".")
                    if sentence:
                        if sentence.startswith("Remediation"):
                            print(self._c(f"      > {sentence}.", GREEN))
                        else:
                            print(self._c(f"      {sentence}.", DIM))

            if f.reproduction:
                print()
                print(self._c("      -- How to verify manually --", BOLD + YELLOW))
                for line in f.reproduction.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        print()
                    elif line.startswith("$"):
                        # Shell command — highlight it
                        print(self._c(f"      {line}", WHITE + BOLD))
                    elif line.startswith("#"):
                        # Comment / step header
                        print(self._c(f"      {line}", YELLOW))
                    else:
                        print(self._c(f"      {line}", DIM))
            print()

        # Attack-path correlation (BloodHound-style) — composes confirmed
        # findings into escalation chains. Printed before the closing summary.
        self._print_attack_paths(findings)

        print(sep)
        summary_text = f"  {len(findings)} finding(s) -- review and validate before reporting."
        print(self._c(summary_text, BOLD))
        if elapsed > 0:
            if interrupted:
                print(self._c(
                    f"  Scan interrupted after {elapsed:.1f}s "
                    f"-- partial results above", YELLOW,
                ))
            else:
                print(self._c(f"  Scan completed in {elapsed:.1f}s", DIM))
        print()

    _PATH_SEV_COLOR = {"critical": RED, "high": RED, "medium": YELLOW}

    def _print_attack_paths(self, findings: List[Finding]) -> None:
        """Render correlated attack paths (chains of confirmed findings)."""
        paths = correlate_findings(findings)
        if not paths:
            return

        print()
        print(self._c("  " + "=" * 52, BOLD))
        print(self._c(f"  ATTACK PATHS ({len(paths)})", BOLD + MAGENTA))
        print(self._c("  Confirmed findings chained into escalation paths", DIM))
        print(self._c("  " + "=" * 52, BOLD))
        print()

        for idx, p in enumerate(paths, 1):
            sev_c = self._PATH_SEV_COLOR.get(p.severity, WHITE)
            host = f" @ {p.host}" if p.host else ""
            print(self._c(f"  [{idx}] [{p.severity.upper()}] {p.name}{host}", BOLD + sev_c))
            for i, step in enumerate(p.steps, 1):
                connector = "    " if i == 1 else "  ->"
                print(self._c(f"   {connector} {step}", CYAN))
            print()
            for sentence in p.narrative.split(". "):
                sentence = sentence.strip().rstrip(".")
                if sentence:
                    print(self._c(f"      {sentence}.", DIM))
            print(self._c(f"      > {p.recommendation}", GREEN))
            print()

    def _field(self, label: str, value: str, color: str = "") -> None:
        """Print a single key-value field line."""
        label_str = f"      {label:12s}: "
        val_str = self._c(value, color) if color else value
        print(f"{self._c(label_str, DIM)}{val_str}")

    # ------------------------------------------------------------------
    # File output
    # ------------------------------------------------------------------

    def save_report(self, findings: List[Finding], path: str, fmt: str = "txt") -> None:
        """Persist findings to *path* in *fmt* format ('json' or 'txt')."""
        if fmt == "json":
            self._write_json(findings, path)
        else:
            self._write_txt(findings, path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _c(self, text: str, code: str) -> str:
        """Apply ANSI code if colour output is enabled."""
        return f"{code}{text}{RESET}" if self._color_ok else text

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _write_json(self, findings: List[Finding], path: str) -> None:
        attack_paths = correlate_findings(findings)
        data = {
            "tool": f"OkrScann v{__version__}",
            "timestamp": self._ts(),
            "total": len(findings),
            "findings": [f.to_dict() for f in findings],
            "attack_paths": [p.to_dict() for p in attack_paths],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    def _write_txt(self, findings: List[Finding], path: str) -> None:
        lines = [
            f"OkrScann v{__version__} -- Scan Report",
            f"Generated : {self._ts()}",
            f"Findings  : {len(findings)}",
            "=" * 60,
            "",
        ]
        for idx, f in enumerate(findings, 1):
            lines += [
                f"[{idx}] {f.vuln_type}",
                f"    URL        : {f.url}",
                f"    Method     : {f.method}",
                f"    Parameter  : {f.parameter}",
                f"    Payload    : {f.payload}",
                f"    Evidence   : {f.evidence}",
                f"    Confidence : {f.confidence.upper()}",
            ]
            if f.details:
                lines.append(f"    Details    : {f.details}")
            if f.reproduction:
                lines.append(f"    Reproduce  :")
                for rline in f.reproduction.strip().split("\n"):
                    lines.append(f"                 {rline.strip()}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
