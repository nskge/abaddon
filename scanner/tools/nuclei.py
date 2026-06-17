"""nuclei integration — template-based CVE/vulnerability scan.

Runs nuclei against the target and normalises JSON-line output into native
Finding objects. Activated via config["use_nuclei"] or config["ext_tools"].

nuclei is the broadest secondary pass: it covers CVEs, misconfigurations,
exposed panels, default credentials, and more — categories our native engine
doesn't handle. Run it AFTER the native scan to avoid duplicate findings.
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Optional

from ..modules.base import Finding

logger = logging.getLogger("vulnscanner")

# Map nuclei severity → confidence field
_SEVERITY_MAP = {
    "critical": "high",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "low",
    "unknown":  "low",
}

# Tags to include by default (skips purely informational noise)
_DEFAULT_TAGS = "cve,rce,sqli,xss,lfi,ssrf,xxe,misconfig,exposure,default-login,panel"

# Severities to report
_DEFAULT_SEVERITY = "critical,high,medium"


def _build_command(
    url: str,
    templates_dir: Optional[str],
    tags: str,
    severity: str,
    proxy: Optional[str],
    headers: Dict[str, str],
    cookies: str,
    timeout: int,
    output_file: str,
) -> List[str]:
    cmd = [
        "nuclei", "-u", url,
        "-j",                           # JSON output (one object per line)
        "-o", output_file,
        "-severity", severity,
        "-silent",
        "-no-interactsh",               # avoid OAST callbacks that delay scans
        "-timeout", str(timeout),
        "-retries", "2",
    ]

    if templates_dir and os.path.isdir(templates_dir):
        cmd += ["-t", templates_dir]
    else:
        cmd += ["-tags", tags]

    if proxy:
        cmd += ["-proxy", proxy]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cmd += ["-H", f"Cookie: {cookies}"]

    return cmd


def _parse_output(path: str, url: str) -> List[Finding]:
    findings: List[Finding] = []
    if not os.path.exists(path):
        return findings
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {})
        template_id = obj.get("template-id", obj.get("templateID", "unknown"))
        name        = info.get("name", template_id)
        severity    = info.get("severity", "unknown").lower()
        description = info.get("description", "")
        reference   = info.get("reference", [])
        if isinstance(reference, list):
            reference = reference[0] if reference else ""
        matched_at  = obj.get("matched-at") or obj.get("matched") or url
        curl_cmd    = obj.get("curl-command", "")
        extracted   = obj.get("extracted-results") or obj.get("matched-results") or []
        evidence    = "; ".join(extracted[:3]) if extracted else matched_at[:120]

        repro_lines = [
            f"# nuclei template: {template_id}",
            f"# Severity: {severity.upper()}",
        ]
        if curl_cmd:
            repro_lines += ["# PoC:", f"$ {curl_cmd}"]
        if reference:
            repro_lines.append(f"# Reference: {reference}")
        repro_lines += [
            "",
            "# Re-run targeted:",
            f"$ nuclei -u '{url}' -t ~/nuclei-templates/{template_id}.yaml -j",
        ]

        findings.append(Finding(
            vuln_type=f"{name} [nuclei]",
            url=matched_at,
            method="GET",
            parameter="(nuclei)",
            payload=template_id,
            evidence=evidence,
            confidence=_SEVERITY_MAP.get(severity, "low"),
            details=description or f"nuclei matched template {template_id!r} on {matched_at}.",
            reproduction="\n".join(repro_lines),
        ))
    return findings


class NucleiRunner:
    """Run nuclei against a target and return normalised Finding objects."""

    def __init__(self, config: Dict) -> None:
        self.config = config

    def run(
        self,
        url: str,
        tags: str = _DEFAULT_TAGS,
        severity: str = _DEFAULT_SEVERITY,
    ) -> List[Finding]:
        from . import is_available
        if not is_available("nuclei"):
            logger.warning("[nuclei] not found on PATH — skipping.")
            return []

        templates_dir = self.config.get("nuclei_templates") or os.path.expanduser(
            "~/nuclei-templates"
        )
        cookies_d = self.config.get("cookies") or {}
        cookies_s = "; ".join(f"{k}={v}" for k, v in cookies_d.items())
        proxy     = self.config.get("proxy")
        headers   = {k: v for k, v in (self.config.get("headers") or {}).items()
                     if k.lower() not in ("user-agent", "cookie")}
        timeout   = max(10, self.config.get("timeout", 10))

        with tempfile.NamedTemporaryFile(
            prefix="abaddon_nuclei_", suffix=".jsonl", delete=False
        ) as tf:
            out_path = tf.name

        try:
            cmd = _build_command(
                url=url,
                templates_dir=templates_dir if os.path.isdir(templates_dir) else None,
                tags=tags,
                severity=severity,
                proxy=proxy,
                headers=headers,
                cookies=cookies_s,
                timeout=timeout,
                output_file=out_path,
            )
            logger.info("[nuclei] command: %s", " ".join(cmd))
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                logger.warning("[nuclei] timed out after 10 minutes.")
            except FileNotFoundError:
                logger.warning("[nuclei] binary not found.")
                return []

            findings = _parse_output(out_path, url)
            if findings:
                logger.info("[nuclei] %d finding(s).", len(findings))
            else:
                logger.info("[nuclei] no findings.")
            return findings
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
