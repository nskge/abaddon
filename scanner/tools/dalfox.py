"""dalfox integration — secondary XSS pass for WAF-protected targets.

Runs dalfox with pre-tuned bypass flags and normalises its output into
native Finding objects. Activated via config["use_dalfox"] or config["ext_tools"].
"""

import json
import logging
import re
import subprocess
from typing import Dict, List, Optional

from ..modules.base import Finding

logger = logging.getLogger("vulnscanner")

# Dalfox outputs one JSON object per finding when --format json is used.
_RE_PARAM = re.compile(r"param=([^\s&]+)")


def _build_command(
    url: str,
    method: str,
    data: str,
    cookies: str,
    proxy: Optional[str],
    headers: Dict[str, str],
    waf_evasion: int,
    timeout: int,
    delay: float,
) -> List[str]:
    cmd = [
        "dalfox", "url", url,
        "--format", "json",
        "--no-color",
        "--silence",
        "--timeout", str(timeout),
    ]

    if method.upper() == "POST" and data:
        cmd += ["--data", data]
    if cookies:
        cmd += ["--cookie", cookies]
    if proxy:
        cmd += ["--proxy", proxy]
    if delay > 0:
        cmd += ["--delay", str(int(delay * 1000))]  # dalfox uses ms

    for k, v in (headers or {}).items():
        if k.lower() == "user-agent":
            cmd += ["--user-agent", v]
        else:
            cmd += ["--header", f"{k}: {v}"]

    if waf_evasion >= 1:
        cmd += ["--waf-evasion"]
    if waf_evasion >= 2:
        cmd += ["--encode-url"]
    if waf_evasion >= 3:
        cmd += ["--ignore-return", "403,429"]

    return cmd


def _parse_output(text: str, url: str) -> List[Finding]:
    findings: List[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # dalfox JSON schema: type, data, param, evidence, poc
        poc     = obj.get("poc", "")
        param   = obj.get("param") or _RE_PARAM.search(poc or "")
        param   = param.group(1) if hasattr(param, "group") else (param or "unknown")
        payload = obj.get("data", "")
        ctype   = obj.get("type", "XSS")
        ev      = obj.get("evidence", poc[:120] if poc else "")

        findings.append(Finding(
            vuln_type=f"Cross-Site Scripting ({ctype}) [dalfox]",
            url=url,
            method="GET",
            parameter=param,
            payload=payload,
            evidence=ev,
            confidence="high",
            details=(
                f"dalfox confirmed a {ctype} XSS on parameter '{param}'. "
                "The payload executes JavaScript in the victim's browser. "
                "Remediation: HTML-encode all reflected output."
            ),
            reproduction=(
                f"# Confirmed by dalfox:\n"
                f"$ curl -s '{poc}'\n"
                f"# Or open in browser:\n"
                f"# {poc}"
            ),
        ))
    return findings


class DalfoxRunner:
    """Run dalfox against a target and return normalised Finding objects."""

    def __init__(self, config: Dict) -> None:
        self.config = config

    def run(
        self,
        url: str,
        waf_name: str = "",
        override_method: str = "",
        override_data: str = "",
    ) -> List[Finding]:
        from . import is_available
        if not is_available("dalfox"):
            logger.warning("[dalfox] not found on PATH — skipping.")
            return []

        method   = (override_method or self.config.get("method", "GET")).upper()
        data     = override_data or self.config.get("data") or ""
        cookies_d = self.config.get("cookies") or {}
        cookies_s = "; ".join(f"{k}={v}" for k, v in cookies_d.items())
        proxy    = self.config.get("proxy")
        timeout  = max(30, self.config.get("timeout", 10) * 3)
        waf_ev   = self.config.get("waf_evasion", 0)
        headers  = {k: v for k, v in (self.config.get("headers") or {}).items()}
        delay    = float(self.config.get("rate_limit_delay") or 0)

        if "cloudflare" in (waf_name or "").lower() and delay == 0:
            delay = 2.0

        cmd = _build_command(
            url=url, method=method, data=data, cookies=cookies_s,
            proxy=proxy, headers=headers, waf_evasion=waf_ev,
            timeout=timeout, delay=delay,
        )
        logger.info("[dalfox] command: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.warning("[dalfox] timed out after 5 minutes.")
            return []
        except FileNotFoundError:
            logger.warning("[dalfox] binary not found.")
            return []

        output = proc.stdout + proc.stderr
        logger.debug("[dalfox] output:\n%s", output[:2000])

        findings = _parse_output(output, url)
        if findings:
            logger.info("[dalfox] %d XSS finding(s) confirmed.", len(findings))
        else:
            logger.info("[dalfox] no XSS found.")
        return findings
