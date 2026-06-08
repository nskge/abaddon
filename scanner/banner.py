"""ASCII banner and visual branding for OkrScann."""

from scanner import __version__
from scanner.cve_db import _CVE_DB

_CVE_COUNT = len(_CVE_DB)
_MODULE_LIST = "SQLi  XSS  LFI  CMDi  SSTI  CRLF  Redirect  Headers"

# Hand-crafted logo -- ASCII-safe for all terminal encodings (Windows cp1252+)
_LOGO = r"""
     ____  _        ____
    / __ \| | _____/ ___|  ___ __ _ _ __  _ __
   | |  | | |/ / __\___ \ / __/ _` | '_ \| '_ \
   | |__| |   <| |  ___) | (_| (_| | | | | | | |
    \____/|_|\_\_| |____/ \___\__,_|_| |_|_| |_|
"""

_FRAME_WIDTH = 62


def _pad(text: str, width: int) -> str:
    """Left-align *text* padded to *width* characters."""
    return text + " " * max(0, width - len(text))


def print_banner(color: bool = True) -> None:
    """Print the full banner to stdout."""
    if not color:
        _print_plain()
        return
    _print_color()


# ---------------------------------------------------------------------------
# Plain (no ANSI)
# ---------------------------------------------------------------------------

def _print_plain() -> None:
    top    = "  //" + "=" * _FRAME_WIDTH + "\\\\"
    bottom = "  \\\\" + "=" * _FRAME_WIDTH + "//"
    side_l = "  ||  "
    side_r = "  ||"
    blank  = side_l + " " * (_FRAME_WIDTH - 2) + side_r

    print(top)
    print(blank)
    for line in _LOGO.strip("\n").split("\n"):
        content = _pad(line, _FRAME_WIDTH - 2)
        print(f"{side_l}{content}{side_r}")
    print(blank)
    print(bottom)
    print()
    print(f"  [>] Web Vulnerability Scanner   v{__version__}")
    print(f"  [>] CVE DB: {_CVE_COUNT} entries  ::  Metasploit-ready")
    print(f"  [>] Modules: {_MODULE_LIST}")
    print()
    print("  [!] Authorized targets ONLY -- author assumes NO liability")
    print()


# ---------------------------------------------------------------------------
# Colored
# ---------------------------------------------------------------------------

def _print_color() -> None:
    # ANSI codes
    DARK_RED  = "\033[31m"
    RED       = "\033[91m"
    BOLD      = "\033[1m"
    CYAN      = "\033[96m"
    DIM       = "\033[2m"
    YELLOW    = "\033[93m"
    GREEN     = "\033[92m"
    WHITE     = "\033[97m"
    RESET     = "\033[0m"

    def c(text: str, code: str) -> str:
        return f"{code}{text}{RESET}"

    top    = "  //" + "=" * _FRAME_WIDTH + "\\\\"
    bottom = "  \\\\" + "=" * _FRAME_WIDTH + "//"
    side_l = "  ||  "
    side_r = "  ||"
    blank  = side_l + " " * (_FRAME_WIDTH - 2) + side_r

    print(c(top, DARK_RED + BOLD))
    print(c(blank, DARK_RED))

    logo_lines = _LOGO.strip("\n").split("\n")
    n = len(logo_lines)
    for i, line in enumerate(logo_lines):
        content = _pad(line, _FRAME_WIDTH - 2)
        # Gradient: center line boldest, edges darker
        dist = abs(i - n // 2)
        if dist == 0:
            logo_c = RED + BOLD
        elif dist <= 1:
            logo_c = RED
        else:
            logo_c = DARK_RED + BOLD
        print(
            c(side_l, DARK_RED)
            + c(content, logo_c)
            + c(side_r, DARK_RED)
        )

    print(c(blank, DARK_RED))
    print(c(bottom, DARK_RED + BOLD))
    print()

    # Stats block below the frame
    ver_line    = f"  [>] Web Vulnerability Scanner  v{__version__}"
    cve_line    = f"  [>] CVE DB : {_CVE_COUNT} entries  ::  Metasploit-ready"
    mod_line1   = f"  [>] Modules: SQLi  XSS  LFI  CMDi  SSTI  CRLF"
    mod_line2   = f"               Redirect  Headers  CVE Detection"
    warn_line   = "  [!] Authorized targets ONLY -- author assumes NO liability"

    print(c(ver_line,  CYAN + BOLD))
    print(c(cve_line,  GREEN))
    print(c(mod_line1, WHITE))
    print(c(mod_line2, WHITE))
    print()
    print(c(warn_line, YELLOW))
    print()
