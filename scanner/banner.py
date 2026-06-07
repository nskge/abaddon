"""ASCII banner and visual branding for OkrScann."""

from scanner import __version__

# Hand-crafted angular banner -- ASCII-safe for all terminal encodings
BANNER = r"""
     ____  _        ____
    / __ \| | _____/ ___|  ___ __ _ _ __  _ __
   | |  | | |/ / __\___ \ / __/ _` | '_ \| '_ \
   | |__| |   <| |  ___) | (_| (_| | | | | | | |
    \____/|_|\_\_| |____/ \___\__,_|_| |_|_| |_|
"""

INFO_BOX = f"""\
   +---------------------------------------------------------+
   |  OkrScann v{__version__:<8s} -- Web Vulnerability Scanner       |
   |  Modules: SQLi XSS LFI CMDi SSTI CRLF Redirect Headers |
   +---------------------------------------------------------+"""

WARN_LINE = "   [!] Authorized targets ONLY -- author assumes NO liability"


def print_banner(color: bool = True) -> None:
    """Print the full banner to stdout."""
    if not color:
        print(BANNER)
        print(INFO_BOX)
        print(WARN_LINE)
        print()
        return

    # Gradient: dark red -> bright red -> dark red (line by line)
    DARK_RED = "\033[31m"
    RED      = "\033[91m"
    BOLD     = "\033[1m"
    CYAN     = "\033[96m"
    DIM      = "\033[2m"
    YELLOW   = "\033[93m"
    RESET    = "\033[0m"

    banner_lines = BANNER.strip("\n").split("\n")
    n = len(banner_lines)
    for i, line in enumerate(banner_lines):
        # Gradient: edges dark, center bright
        dist = abs(i - n // 2)
        if dist == 0:
            c = RED + BOLD
        elif dist <= 1:
            c = RED
        else:
            c = DARK_RED + BOLD
        print(f"{c}{line}{RESET}")

    print()
    # Info box in cyan
    for line in INFO_BOX.split("\n"):
        if line.strip().startswith("+"):
            print(f"{DIM}{line}{RESET}")
        else:
            print(f"{CYAN}{line}{RESET}")

    print(f"{YELLOW}{WARN_LINE}{RESET}")
    print()
