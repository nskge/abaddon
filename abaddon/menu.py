"""Interactive menu interface for Abaddon — dark-purple themed TUI.

Launches with no CLI arguments (``python -m abaddon`` or ``python main.py``).
All functionality is reachable from nested menus: the classic module scanner,
the async template engine, recon tools, and session options. Logic (dispatch
table, config builder, session state) is kept separate from the interactive
input loop so it can be unit-tested without simulating a keyboard.
"""

import asyncio
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Dark-purple spectrum palette
# ---------------------------------------------------------------------------
_PURPLE_SPECTRUM = [
    "#240046",
    "#3c096c",
    "#5a189a",
    "#7b2cbf",
    "#9d4edd",
    "#c77dff",
    "#e0aaff",
]

ABADDON_THEME = Theme(
    {
        "banner": "#9d4edd",
        "title": "bold #c77dff",
        "subtitle": "#9d4edd",
        "num": "bold #e0aaff",
        "label": "#c77dff",
        "accent": "#7b2cbf",
        "ok": "bold #c77dff",
        "warn": "#ff7b7b",
        "dim": "#5a189a",
        "value": "#e0aaff",
    }
)

# Demon ascii art (braille). Kept verbatim; rendered with a vertical gradient.
ABADDON_ART = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⢡⡀⢀⣠⣤⠤⠷⠤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⣀⡴⠟⠉⢠⡀⠠⢤⣄⣠⠀⠉⠻⢦⡀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠄⠀⠀⠈⢳⡞⠉⠀⠀⠀⣠⡇⢀⠄⠀⢷⡀⠀⠀⠀⠘⣶⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⡟⠉⠒⠦⣄⣠⡏⠀⠀⠀⠀⢰⣿⢀⣴⣶⣦⡄⣻⠄⢀⢀⣠⣤⢧⣄⣠⠤⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣿⡋⠀⠀⠀⠀⠀⡟⠀⠀⢠⣠⠀⠀⠹⣿⣿⣿⣿⣿⠋⠀⠈⡍⠀⠀⠈⣿⠀⠀⠀⠀⠒⢦⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡏⠀⠀⠀⣀⣀⣸⠁⠀⠀⣆⠙⣿⣆⢠⣿⣷⣿⣿⣷⠀⣠⣾⣷⡞⠀⠀⢹⣀⣀⣀⣀⠀⢸⣷⣧⣤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠸⡄⠀⢀⡘⢦⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⣿⣩⠇⡀⠀⢸⠀⠀⠀⠀⠉⢸⣿⣿⣿⣮⡁⡀⠀⠀⠀⠀
⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⢄⡀⠀⠀⠀⢀⣷⡸⣄⣙⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣖⡚⠁⢀⣞⡀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡴⣔⠀⠀⠀
⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠐⠺⡏⣍⣁⠀⣽⣿⣿⣿⣿⣿⣿⣽⣿⣯⣽⣿⣿⣿⣍⢁⡜⠉⠉⠓⢤⣄⣾⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀
⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠠⣷⣿⣗⡤⠈⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⠛⢤⡀⠀⠀⣨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀
⠀⣿⣿⣿⣿⣿⠿⢿⣿⣿⠿⢿⣿⣿⣿⣿⣷⡀⠈⣿⣿⣄⠀⣿⣿⣿⠁⠹⣿⣿⣿⣿⣿⢿⣿⣗⠀⠀⠀⠉⠂⣠⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀
⢀⡿⡿⠉⣿⡟⠀⢸⣿⠏⠀⠀⢹⠿⠿⢿⣿⣷⣄⠚⢿⣿⣿⣿⡿⠃⢈⣹⣿⣿⣿⣿⣿⡎⢿⣿⣇⠀⠀⣶⣴⣿⣿⣿⣿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⢸⣿⣿⣾⣿⡇⠀⢸⠋⠀⠀⠀⠸⠀⠀⠀⠉⠛⣿⣷⣟⣙⠿⣿⡁⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⡿⢿⣿⠟⢿⡏⠀⢸⠉⠁⠀⠈⢹⢿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⡇⠀⠾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠍⠛⢿⠷⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣆⠀⠁⠀⠀⠀⠀⠈⠀⠀⠀⠀⠞⠀⠘⣿⣿⣟
⢸⣿⣿⣏⣿⡗⠀⠀⠀⠀⠀⠀⣠⠒⠊⠉⠉⠉⢉⣒⠦⣄⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣤⣿⣿⠿⠶⠶⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇
⠘⣿⣷⣿⡝⠁⠀⠀⠀⠀⠀⠉⢁⠀⠀⠀⠀⠀⠀⠈⢹⣮⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠙⠀⠀⠀⠀⠀⠀⠈⠛⢆⠀⠀⠀⠀⠀⠀⠀⠋⢻⡇
⠀⠻⣿⣤⠁⠀⠀⠀⠀⠀⣤⠈⠋⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀⢠⡿⠁
⠀⠀⢻⣧⡀⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡀⠀⠀⠀⠀⣼⠃⠀
⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣧⠀⠀⣀⡼⠁⠀⠀
⠀⠀⠀⠀⠙⢶⡀⠀⠀⠀⠀⢿⣷⠀⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡟⠀⠀⠛⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠙⠏⠉⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⢿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣷⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣞⣿⣿⣿⣿⣿⣿⣿⣼⣿⣿⣿⡿⣾⢻⣿⣿⡟⢻⣿⣿⣿⣿⣿⣿⠙⠳⢤⣀⣀⣀⣠⡤⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⣿⣿⣿⣿⣿⣿⣿⠇⣿⣿⣿⣿⢳⣿⣿⣿⣿⡇⣾⣿⣿⣿⣿⣿⠹⠄⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣟⣿⣿⣿⣿⣻⣿⣾⣿⣿⢸⣿⣿⣿⣿⡇⣿⣿⣿⢹⣿⣿⣇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣾⣅⡿⣫⠟⣿⣿⡿⢹⡿⠿⣿⣿⣧⢸⣿⣿⣿⣿⠇⣿⣿⠇⡞⣿⡏⠉⢷⠴⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⡿⠿⠟⠁⠀⡇⢸⡇⢀⣧⡤⢰⣿⡟⢸⡇⡏⢹⣿⠀⣿⡟⠀⢳⣿⡇⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠞⠁⠀⠀⡠⠀⠀⠁⣿⠃⢸⣿⠙⢺⣻⡗⠸⡇⠡⢸⣿⣰⠈⠀⠀⢘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⢸⠁⠀⠀⠀⣿⠀⠘⣿⡄⠀⠁⠁⠀⠃⠀⠈⣿⠿⠀⠀⠀⠘⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠙⡇⠀⠀⠀⠀⠀⠀⢀⣏⣥⠀⠀⠀⢠⣤⠔⠀⠦⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""


# Scan modules surfaced in the single-module submenu.
SCAN_MODULES: List[Tuple[str, str]] = [
    ("sqli", "SQL Injection (error/boolean/time)"),
    ("xss", "Cross-Site Scripting (reflected)"),
    ("lfi", "Local File Inclusion / traversal"),
    ("cmdi", "OS Command Injection"),
    ("ssti", "Server-Side Template Injection"),
    ("crlf", "CRLF / header injection"),
    ("redirect", "Open Redirect"),
    ("headers", "Security headers / CORS"),
    ("jwt", "JWT weaknesses"),
    ("ssrf", "Server-Side Request Forgery"),
    ("xxe", "XML External Entity"),
    ("bypass403", "403 / forbidden bypass"),
    ("graphql", "GraphQL introspection / IDEs"),
    ("idor", "IDOR / object reference"),
    ("domxss", "DOM-based XSS (source→sink + Playwright)"),
    ("prototype", "Prototype Pollution (server-side)"),
    ("smuggling", "HTTP Request Smuggling (CL.TE / TE.CL)"),
    ("deserial", "Insecure Deserialization (Java/PHP/pickle/.NET)"),
    ("race", "Race Condition (limit-overrun burst)"),
]


@dataclass
class MenuState:
    """Session options shared across scans (set via the Options menu)."""

    method: str = "GET"
    data: str = ""
    cookies_raw: str = ""   # raw cookie string: "session=abc; token=xyz"
    threads: int = 4
    timeout: int = 10
    proxy: str = ""
    scope: str = ""
    waf_evasion: int = 0
    rate_limit: bool = False
    rate_delay: float = 0.0
    crawl: bool = False
    follow_redirects: bool = False
    verbose: bool = False
    use_sqlmap: bool = False
    use_dalfox: bool = False
    use_nuclei: bool = False
    use_nikto: bool = False
    use_wpscan: bool = False

    def _parse_cookies(self) -> Dict[str, str]:
        """Parse raw cookie string 'k=v; k2=v2' into a dict."""
        cookies: Dict[str, str] = {}
        for pair in self.cookies_raw.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def build_config(self, url: str, scan_type: str, **overrides) -> Dict:
        """Build the classic-scanner config dict (mirrors main.py)."""
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
        config: Dict = {
            "url": url,
            "method": self.method,
            "data": self.data,
            "param": None,
            "scan_type": scan_type,
            "crawl": self.crawl,
            "js_crawl": False,
            "custom_payloads": None,
            "delay_threshold": 5.0,
            "auth_username": None,
            "auth_password": None,
            "auth_login_url": "/login",
            "auth_username2": None,
            "auth_password2": None,
            "orchestrated": False,
            "headers": {"User-Agent": ua},
            "cookies": self._parse_cookies(),
            "proxy": self.proxy or None,
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "threads": self.threads,
            "verbose": self.verbose,
            "quiet": False,
            "no_color": False,
            "waf_evasion": self.waf_evasion,
            "port_scan": False,
            "discover_paths": False,
            "discover_subs": False,
            "rate_limit": self.rate_limit,
            "rate_limit_delay": self.rate_delay,
            "aggressive": False,
            "bb_note": None,
            "bb_program": None,
            "use_sqlmap": self.use_sqlmap,
            "use_dalfox": self.use_dalfox,
            "use_nuclei": self.use_nuclei,
            "use_nikto":  self.use_nikto,
            "use_wpscan": self.use_wpscan,
            "ext_tools": False,
        }
        config.update(overrides)
        return config

    def summary(self) -> str:
        parts = [
            f"method={self.method}",
            f"threads={self.threads}",
            f"timeout={self.timeout}s",
            f"waf={self.waf_evasion}",
            f"proxy={self.proxy or '-'}",
            f"scope={self.scope or '-'}",
        ]
        if self.cookies_raw:
            # Show first key only to avoid spilling session tokens in the header
            first_key = self.cookies_raw.split("=")[0].strip()
            parts.append(f"cookies={first_key}=...")
        if self.use_sqlmap:
            parts.append("sqlmap=on")
        if self.use_dalfox:
            parts.append("dalfox=on")
        if self.use_nuclei:
            parts.append("nuclei=on")
        if self.use_nikto:
            parts.append("nikto=on")
        if self.use_wpscan:
            parts.append("wpscan=on")
        return "  ".join(parts)


# Main-menu dispatch keys (kept as data so it can be asserted in tests).
MAIN_MENU: List[Tuple[str, str, str]] = [
    ("1", "Quick Scan", "Run every module against a target"),
    ("2", "Single Module", "Pick one vulnerability class"),
    ("3", "Abaddon Engine", "Async template-based scan (OAST, fuzzing)"),
    ("4", "Recon Tools", "Port scan / path & subdomain discovery"),
    ("5", "Options", "Threads, proxy, scope, WAF evasion, timeout"),
    ("6", "Help / About", "Usage and safety notes"),
    ("0", "Exit", "Leave Abaddon"),
]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# Plain fallback for terminals that cannot encode braille (e.g. cp1252 pipes).
ABADDON_ASCII = r"""
   ___    ____   ___    ____   ____    ___    _   _
  / _ \  | __ ) / _ \  |  _ \ |  _ \  / _ \  | \ | |
 | |_| | |  _ \| |_| | | | | || | | || | | | |  \| |
 |  _  | | |_) |  _  | | |_| || |_| || |_| | | |\  |
 |_| |_| |____/|_| |_| |____/ |____/  \___/  |_| \_|
"""


def _supports_braille(console: Console) -> bool:
    enc = (getattr(console, "encoding", "") or "").lower()
    if "utf" in enc:
        return True
    try:
        "⣿".encode(enc or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def make_console() -> Console:
    # Give the braille art the best chance on the user's real terminal.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    return Console(theme=ABADDON_THEME, highlight=False)


def render_banner(console: Console) -> None:
    if _supports_braille(console):
        lines = ABADDON_ART.split("\n")
        n = len(lines)
        art = Text()
        for i, line in enumerate(lines):
            # Vertical gradient across the purple spectrum.
            color = _PURPLE_SPECTRUM[
                min(len(_PURPLE_SPECTRUM) - 1, i * len(_PURPLE_SPECTRUM) // max(1, n))
            ]
            art.append(line + "\n", style=color)
        try:
            console.print(art, justify="center")
        except Exception:
            _render_ascii_banner(console)
    else:
        _render_ascii_banner(console)

    title = Text("A B A D D O N", style="title")
    subtitle = Text("async offensive engine · authorized testing only", style="subtitle")
    try:
        console.print(title, justify="center")
        console.print(subtitle, justify="center")
    except Exception:
        console.print("A B A D D O N", justify="center")
    console.print()


def _render_ascii_banner(console: Console) -> None:
    lines = ABADDON_ASCII.strip("\n").split("\n")
    n = len(lines)
    art = Text()
    for i, line in enumerate(lines):
        color = _PURPLE_SPECTRUM[
            min(len(_PURPLE_SPECTRUM) - 1, 2 + i * (len(_PURPLE_SPECTRUM) - 2) // max(1, n))
        ]
        art.append(line + "\n", style=color)
    console.print(art, justify="center")


def render_menu(console: Console, items: List[Tuple[str, str, str]], state: Optional[MenuState] = None) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right")
    table.add_column()
    table.add_column(style="dim")
    for key, label, desc in items:
        table.add_row(f"[num]{key}[/num]", f"[label]{label}[/label]", desc)
    console.print(Panel(table, border_style="accent", title="[title]MENU[/title]", title_align="left"))
    if state is not None:
        console.print(f"  [dim]profile:[/dim] [value]{state.summary()}[/value]")
    console.print()


# ---------------------------------------------------------------------------
# Scope helper
# ---------------------------------------------------------------------------

def _in_scope(url: str, scope: str) -> bool:
    """True if scope is empty or the URL host matches a comma-separated glob."""
    if not scope.strip():
        return True
    import fnmatch
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    patterns = [p.strip().lower() for p in scope.split(",") if p.strip()]
    return any(fnmatch.fnmatch(host, pat) for pat in patterns)


# ---------------------------------------------------------------------------
# Scan runners
# ---------------------------------------------------------------------------

def _run_classic(console: Console, state: MenuState, url: str, scan_type: str, **overrides) -> None:
    if not _in_scope(url, state.scope):
        console.print(f"[warn]OUT OF SCOPE:[/warn] {url} does not match '{state.scope}' — aborted.")
        return
    from scanner.core import Scanner
    from scanner.logger import setup_logger
    from scanner.reporter import Reporter

    config = state.build_config(url, scan_type, **overrides)
    logger = setup_logger(verbose=state.verbose, quiet=False)
    console.print(f"[accent]>>[/accent] launching [label]{scan_type}[/label] against [value]{url}[/value]\n")
    scanner = Scanner(config, logger)
    t0 = time.monotonic()
    findings = scanner.run()
    elapsed = time.monotonic() - t0
    Reporter(no_color=False).print_summary(
        findings, elapsed=elapsed, interrupted=getattr(scanner, "_interrupted", False)
    )


def _run_abaddon(console: Console, state: MenuState, url: str) -> None:
    if not _in_scope(url, state.scope):
        console.print(f"[warn]OUT OF SCOPE:[/warn] {url} does not match '{state.scope}' — aborted.")
        return
    import os

    from .core.runner import Scanner as TemplateScanner
    from .core.scope import Scope
    from .network.engine import AsyncEngine
    from .parsers.template_engine import load_templates

    tdir = os.path.join(os.path.dirname(__file__), "templates")
    report = load_templates(tdir)
    console.print(
        f"[accent]>>[/accent] Abaddon engine: [value]{report.ok_count}[/value] templates "
        f"([dim]{report.error_count} rejected[/dim]) vs [value]{url}[/value]\n"
    )
    if not report.loaded:
        console.print("[warn]No templates loaded.[/warn]")
        return

    scope = Scope(patterns=[p.strip() for p in state.scope.split(",") if p.strip()])

    async def go():
        async with AsyncEngine(timeout=state.timeout, scope=scope) as engine:
            scanner = TemplateScanner(engine, report.loaded)
            return await scanner.scan(url)

    try:
        findings = asyncio.run(go())
    except KeyboardInterrupt:
        console.print("[warn]Interrupted.[/warn]")
        return

    if not findings:
        console.print("[ok]No findings.[/ok]")
        return
    table = Table(border_style="accent")
    table.add_column("Severity", style="num")
    table.add_column("Template", style="label")
    table.add_column("Conf.", justify="right", style="value")
    table.add_column("URL", style="dim")
    for f in sorted(findings, key=lambda x: -x.confidence):
        table.add_row(f.severity.upper(), f.template_id, f"{f.confidence:.0%}", f.url)
    console.print(table)


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def _ask_url(console: Console):
    from rich.prompt import Prompt

    url = Prompt.ask("[label]target URL[/label]", default="", console=console).strip()
    if not url:
        console.print("[dim]cancelled.[/dim]")
        return None
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def action_quick_scan(console: Console, state: MenuState) -> None:
    url = _ask_url(console)
    if url:
        _run_classic(console, state, url, "all")


def action_single_module(console: Console, state: MenuState) -> None:
    from rich.prompt import Prompt

    items = [(str(i + 1), label, key) for i, (key, label) in enumerate(SCAN_MODULES)]
    render_menu(console, items + [("0", "Back", "")])
    choice = Prompt.ask(
        "[label]module[/label]",
        choices=[str(i) for i in range(len(SCAN_MODULES) + 1)],
        show_choices=False,
        console=console,
    )
    if choice == "0":
        return
    key = SCAN_MODULES[int(choice) - 1][0]
    url = _ask_url(console)
    if url:
        _run_classic(console, state, url, key)


def action_abaddon_engine(console: Console, state: MenuState) -> None:
    url = _ask_url(console)
    if url:
        _run_abaddon(console, state, url)


def action_recon(console: Console, state: MenuState) -> None:
    from rich.prompt import Confirm

    url = _ask_url(console)
    if not url:
        return
    port_scan = Confirm.ask("[label]port scan?[/label]", default=True, console=console)
    paths = Confirm.ask("[label]discover paths?[/label]", default=True, console=console)
    subs = Confirm.ask("[label]enumerate subdomains?[/label]", default=False, console=console)
    _run_classic(
        console, state, url, "headers",
        port_scan=port_scan, discover_paths=paths, discover_subs=subs,
    )


def action_options(console: Console, state: MenuState) -> None:
    from rich.prompt import IntPrompt, Prompt

    console.print("[title]Options[/title] [dim](enter = keep current)[/dim]\n")
    state.method = Prompt.ask("HTTP method", default=state.method, console=console)
    state.data   = Prompt.ask("POST data (blank=none)", default=state.data, console=console)

    raw_ck = Prompt.ask(
        "cookies (key=val; key2=val2, blank=none)",
        default=state.cookies_raw,
        console=console,
    ).strip()
    state.cookies_raw = raw_ck

    state.threads = IntPrompt.ask("threads", default=state.threads, console=console)
    state.timeout = IntPrompt.ask("timeout (s)", default=state.timeout, console=console)
    state.waf_evasion = IntPrompt.ask("WAF evasion (0-3)", default=state.waf_evasion, console=console)
    state.proxy = Prompt.ask("proxy URL (blank=none)", default=state.proxy, console=console)
    state.scope = Prompt.ask("scope globs (blank=none)", default=state.scope, console=console)
    state.crawl = Prompt.ask("crawl forms? (y/n)", default="y" if state.crawl else "n", console=console).lower().startswith("y")

    console.print()
    console.print("[title]External tools[/title] [dim](secondary pass — only when native finds nothing or WAF blocks)[/dim]")

    def _yn(label: str, current: bool) -> bool:
        return Prompt.ask(label, default="y" if current else "n", console=console).lower().startswith("y")

    state.use_sqlmap = _yn("sqlmap for SQLi? (y/n)", state.use_sqlmap)
    state.use_dalfox = _yn("dalfox for XSS? (y/n)", state.use_dalfox)
    state.use_nuclei = _yn("nuclei CVE/template scan? (y/n)", state.use_nuclei)
    state.use_nikto  = _yn("nikto web server audit? (y/n)", state.use_nikto)
    state.use_wpscan = _yn("wpscan (WordPress)? (y/n)", state.use_wpscan)

    if any([state.use_sqlmap, state.use_dalfox, state.use_nuclei, state.use_nikto, state.use_wpscan]):
        from .tools_check import check_ext_tools
        check_ext_tools(
            console,
            state.use_sqlmap,
            state.use_dalfox,
            state.use_nuclei,
            state.use_nikto,
            state.use_wpscan,
        )

    console.print("\n[ok]options updated.[/ok]")


def action_help(console: Console, state: MenuState) -> None:
    from . import __version__

    body = (
        "[title]ABADDON[/title] — modular + async web vulnerability scanner.\n\n"
        "[label]Quick Scan[/label]   run all classic modules\n"
        "[label]Single Module[/label] pick one class (SQLi, XSS, IDOR, …)\n"
        "[label]Abaddon Engine[/label] async template scan with OAST + fuzzing\n"
        "[label]Recon Tools[/label]  port scan, path & subdomain discovery\n"
        "[label]Options[/label]      tune threads/proxy/scope/WAF/timeout\n\n"
        "[warn]Authorized targets ONLY.[/warn] You are responsible for scope.\n"
        f"[dim]version {__version__} · CLI still available: python -m abaddon -u <url>[/dim]"
    )
    console.print(Panel(body, border_style="accent"))


_DISPATCH = {
    "1": action_quick_scan,
    "2": action_single_module,
    "3": action_abaddon_engine,
    "4": action_recon,
    "5": action_options,
    "6": action_help,
}


def run_menu(state: Optional[MenuState] = None, console: Optional[Console] = None) -> int:
    """Interactive main loop. Returns process exit code."""
    from rich.prompt import Prompt

    state = state or MenuState()
    console = console or make_console()
    try:
        console.clear()
    except Exception:
        pass
    while True:
        render_banner(console)
        render_menu(console, MAIN_MENU, state)
        try:
            choice = Prompt.ask(
                "[label]abaddon[/label] [dim]>[/dim]",
                choices=[k for k, _, _ in MAIN_MENU],
                show_choices=False,
                console=console,
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[accent]bye.[/accent]")
            return 0
        if choice == "0":
            console.print("[accent]bye.[/accent]")
            return 0
        handler = _DISPATCH.get(choice)
        if handler:
            try:
                handler(console, state)
            except KeyboardInterrupt:
                console.print("\n[warn]action interrupted.[/warn]")
        console.print()
        try:
            console.input("[dim]press enter to continue…[/dim] ")
            console.clear()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[accent]bye.[/accent]")
            return 0


if __name__ == "__main__":
    sys.exit(run_menu())
