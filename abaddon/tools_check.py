"""Availability check for external tools — shown in the Options menu."""

from rich.console import Console


def check_ext_tools(console: Console, check_sqlmap: bool, check_dalfox: bool) -> None:
    from scanner.tools import is_available, check_version
    console.print()
    if check_sqlmap:
        if is_available("sqlmap"):
            ver = check_version("sqlmap") or "?"
            console.print(f"  [ok]sqlmap[/ok] [dim]{ver}[/dim]")
        else:
            console.print("  [warn]sqlmap not found[/warn] — install: pip install sqlmap  or  apt install sqlmap")
    if check_dalfox:
        if is_available("dalfox"):
            ver = check_version("dalfox") or "?"
            console.print(f"  [ok]dalfox[/ok] [dim]{ver}[/dim]")
        else:
            console.print("  [warn]dalfox not found[/warn] — install: go install github.com/hahwul/dalfox/v2@latest")
    console.print()
