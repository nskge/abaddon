"""ASCII banner and visual branding for OkrScann."""

from scanner import __version__

# Safe ASCII-only art that works on every terminal encoding
BANNER = r"""
   ___  _          ____
  / _ \| | ___ __ / ___|  ___ __ _ _ __  _ __
 | | | | |/ / '__\___ \ / __/ _` | '_ \| '_ \
 | |_| |   <| |   ___) | (_| (_| | | | | | | |
  \___/|_|\_\_|  |____/ \___\__,_|_| |_|_| |_|
"""

TAGLINE = f"  [ OkrScann v{__version__} -- Web Vulnerability Scanner ]"

INFO_LINE = "  [ SQLi | XSS | LFI | CMDi | Open Redirect ]"

SEPARATOR = "  " + "=" * 52

WARN_LINE = "  [ Use only on targets you have permission to test ]"


def print_banner(color: bool = True) -> None:
    """Print the full banner to stdout."""
    if color:
        RED = "\033[91m"
        CYAN = "\033[96m"
        YELLOW = "\033[93m"
        DIM = "\033[2m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        print(f"{RED}{BOLD}{BANNER}{RESET}")
        print(f"{CYAN}{BOLD}{TAGLINE}{RESET}")
        print(f"{CYAN}{INFO_LINE}{RESET}")
        print(f"{DIM}{WARN_LINE}{RESET}")
        print(f"{CYAN}{SEPARATOR}{RESET}")
        print()
    else:
        print(BANNER)
        print(TAGLINE)
        print(INFO_LINE)
        print(WARN_LINE)
        print(SEPARATOR)
        print()
