"""External tool integration layer.

External tools (sqlmap, dalfox) run as a secondary pass when our engine
finds nothing or is blocked by a WAF. Results are normalized to Finding
objects so the reporter treats them identically to native findings.

Tools are opt-in: nothing happens unless the caller explicitly enables them
via config["use_sqlmap"], config["use_dalfox"], or config["ext_tools"].
"""

import shutil
import subprocess
from typing import List, Optional


def is_available(binary: str) -> bool:
    """Return True if *binary* exists on PATH."""
    return shutil.which(binary) is not None


def check_version(binary: str) -> Optional[str]:
    """Return version string of *binary*, or None if not found/runnable."""
    if not is_available(binary):
        return None
    try:
        r = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=8,
        )
        out = (r.stdout + r.stderr).strip()
        return out.split("\n")[0] if out else "unknown"
    except Exception:
        return None
