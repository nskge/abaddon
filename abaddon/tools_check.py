"""Availability check for external tools — shown in the Options menu."""

from rich.console import Console


_INSTALL_HINTS = {
    "sqlmap":  "pip install sqlmap  or  apt install sqlmap",
    "dalfox":  "go install github.com/hahwul/dalfox/v2@latest",
    "nuclei":  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "nikto":   "apt install nikto  or  brew install nikto",
    "wpscan":  "gem install wpscan",
}


def check_ext_tools(
    console: Console,
    check_sqlmap: bool = False,
    check_dalfox: bool = False,
    check_nuclei: bool = False,
    check_nikto: bool = False,
    check_wpscan: bool = False,
) -> None:
    from scanner.tools import is_available, check_version
    console.print()
    checks = [
        ("sqlmap",  check_sqlmap),
        ("dalfox",  check_dalfox),
        ("nuclei",  check_nuclei),
        ("nikto",   check_nikto),
        ("wpscan",  check_wpscan),
    ]
    for binary, enabled in checks:
        if not enabled:
            continue
        if is_available(binary):
            ver = check_version(binary) or "installed"
            console.print(f"  [ok]{binary}[/ok] [dim]{ver}[/dim]")
        else:
            hint = _INSTALL_HINTS.get(binary, "check your PATH")
            console.print(f"  [warn]{binary} not found[/warn] — install: {hint}")
    console.print()
