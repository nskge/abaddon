"""nikto integration — web server vulnerability audit.

Nikto is a comprehensive web server scanner that checks for dangerous files,
outdated software, and server misconfigurations that our native engine does not
cover (e.g. /server-status, PHP-CGI RCE, IIS shortname enum).

Activated via config["use_nikto"] or config["ext_tools"].
"""

import logging
import re
import subprocess
import tempfile
import json
import os
from typing import Dict, List, Optional

from ..modules.base import Finding

logger = logging.getLogger("vulnscanner")

# nikto output item type → confidence
_SEVERITY_RE = re.compile(r"OSVDB-(\d+)|CVE-(\d{4}-\d+)", re.I)

# nikto -Format json produces: {"host":"...","ip":"...","port":"...","banner":"...","vulnerabilities":[...]}
# Older versions without -Format json fall back to plain-text parsing.


def _build_command(
    url: str,
    proxy: Optional[str],
    cookies: str,
    headers: Dict[str, str],
    timeout: int,
    output_file: str,
) -> List[str]:
    cmd = [
        "nikto",
        "-host", url,
        "-Format", "json",
        "-output", output_file,
        "-maxtime", f"{timeout}s",
        "-nointeractive",
    ]
    if proxy:
        cmd += ["-useproxy", proxy]
    if cookies:
        cmd += ["-cookies", cookies]
    for k, v in (headers or {}).items():
        if k.lower() == "user-agent":
            cmd += ["-useragent", v]
    return cmd


def _parse_json_output(path: str, url: str) -> List[Finding]:
    findings = []
    if not os.path.exists(path):
        return findings
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return findings

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        msg  = v.get("msg", "")
        uri  = v.get("uri", "/")
        osvdb = v.get("OSVDB", "")
        refs  = v.get("references", {})
        cve   = refs.get("CVE", "") if isinstance(refs, dict) else ""
        full_url = url.rstrip("/") + uri

        if not msg:
            continue

        is_high = bool(_SEVERITY_RE.search(msg + osvdb + cve))
        conf = "medium" if is_high else "low"

        repro = [
            "# nikto finding:",
            f"$ curl -sk '{full_url}'",
        ]
        if osvdb:
            repro.append(f"# OSVDB: {osvdb}")
        if cve:
            repro.append(f"# CVE: {cve}  → https://nvd.nist.gov/vuln/detail/{cve}")

        findings.append(Finding(
            vuln_type=f"Web Server Issue [nikto]",
            url=full_url,
            method="GET",
            parameter="(nikto)",
            payload=uri,
            evidence=msg[:200],
            confidence=conf,
            details=msg,
            reproduction="\n".join(repro),
        ))
    return findings


def _parse_text_output(text: str, url: str) -> List[Finding]:
    """Fallback parser for nikto versions that don't support -Format json."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("+") or "Server:" in line or "Start Time:" in line:
            continue
        # Strip leading '+' and whitespace
        msg = line.lstrip("+ ").strip()
        if not msg:
            continue
        # Try to extract a URI from the line
        uri_match = re.search(r"(/[^\s:,]+)", msg)
        uri = uri_match.group(1) if uri_match else "/"
        is_high = bool(_SEVERITY_RE.search(msg))
        findings.append(Finding(
            vuln_type="Web Server Issue [nikto]",
            url=url.rstrip("/") + uri,
            method="GET",
            parameter="(nikto)",
            payload=uri,
            evidence=msg[:200],
            confidence="medium" if is_high else "low",
            details=msg,
            reproduction=f"# nikto finding:\n$ curl -sk '{url.rstrip('/')}{uri}'",
        ))
    return findings


class NiktoRunner:
    """Run nikto against a target and return normalised Finding objects."""

    def __init__(self, config: Dict) -> None:
        self.config = config

    def run(self, url: str) -> List[Finding]:
        from . import is_available
        if not is_available("nikto"):
            logger.warning("[nikto] not found on PATH — skipping.")
            return []

        cookies_d = self.config.get("cookies") or {}
        cookies_s = "; ".join(f"{k}={v}" for k, v in cookies_d.items())
        proxy     = self.config.get("proxy")
        headers   = {k: v for k, v in (self.config.get("headers") or {}).items()}
        # nikto can be slow; 5 min is reasonable for a targeted audit
        timeout   = min(300, max(60, self.config.get("timeout", 10) * 10))

        with tempfile.NamedTemporaryFile(
            prefix="abaddon_nikto_", suffix=".json", delete=False
        ) as tf:
            out_path = tf.name

        try:
            cmd = _build_command(
                url=url, proxy=proxy, cookies=cookies_s,
                headers=headers, timeout=timeout, output_file=out_path,
            )
            logger.info("[nikto] command: %s", " ".join(cmd))
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout + 30,
                )
            except subprocess.TimeoutExpired:
                logger.warning("[nikto] timed out.")
                return _parse_text_output("", url)
            except FileNotFoundError:
                logger.warning("[nikto] binary not found.")
                return []

            findings = _parse_json_output(out_path, url)
            if not findings:
                # Try text parser on stdout as fallback
                findings = _parse_text_output(proc.stdout, url)

            if findings:
                logger.info("[nikto] %d finding(s).", len(findings))
            else:
                logger.info("[nikto] no findings.")
            return findings
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
