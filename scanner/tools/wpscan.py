"""wpscan integration — WordPress vulnerability scanner.

wpscan enumerates WordPress version, plugins, themes, and users, then checks
them against a CVE database. Activated via config["use_wpscan"].

Auto-skips targets that don't look like WordPress to avoid wasting time.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional

from ..modules.base import Finding

logger = logging.getLogger("vulnscanner")

_WP_INDICATORS = [
    "wp-content/", "wp-includes/", "/wp-json/", "wp-login.php",
    "WordPress", "/xmlrpc.php",
]

_SEVERITY_MAP = {
    "critical": "high",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "low",
}


def _looks_like_wordpress(config: Dict, url: str) -> bool:
    """Quick heuristic — skip wpscan on non-WP sites."""
    # Check fingerprinted technologies stored during recon (not always available)
    techs = config.get("_detected_techs", [])
    if any("WordPress" in t or "wordpress" in t for t in techs):
        return True
    # Check if /wp-login.php is in the URL or a common WP path exists
    return any(ind.lower() in url.lower() for ind in _WP_INDICATORS)


def _build_command(
    url: str,
    api_token: Optional[str],
    enumerate: str,
    proxy: Optional[str],
    cookies: str,
    timeout: int,
    output_file: str,
) -> List[str]:
    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--output", output_file,
        "--no-banner",
        "--disable-tls-checks",
        "--enumerate", enumerate,
        "--request-timeout", str(timeout),
        "--connect-timeout", str(min(timeout, 15)),
    ]
    if api_token:
        cmd += ["--api-token", api_token]
    if proxy:
        cmd += ["--proxy", proxy]
    if cookies:
        cmd += ["--cookie", cookies]
    return cmd


def _parse_output(path: str, url: str) -> List[Finding]:
    findings = []
    if not os.path.exists(path):
        return findings
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("[wpscan] parse error: %s", exc)
        return findings

    wp_version = data.get("version", {})
    if isinstance(wp_version, dict) and wp_version.get("number"):
        ver = wp_version["number"]
        vulns = wp_version.get("vulnerabilities", [])
        for v in vulns:
            _add_vuln_finding(findings, url, v, f"WordPress {ver}", "core")

    for slug, plugin in (data.get("plugins") or {}).items():
        version = (plugin.get("version") or {}).get("number", "?")
        for v in plugin.get("vulnerabilities", []):
            _add_vuln_finding(findings, url, v, f"Plugin: {slug} {version}", "plugin")

    for slug, theme in (data.get("themes") or {}).items():
        version = (theme.get("version") or {}).get("number", "?")
        for v in theme.get("vulnerabilities", []):
            _add_vuln_finding(findings, url, v, f"Theme: {slug} {version}", "theme")

    # User enumeration
    users = data.get("users", {})
    if users:
        usernames = list(users.keys())[:10]
        findings.append(Finding(
            vuln_type="WordPress User Enumeration [wpscan]",
            url=url,
            method="GET",
            parameter="(user enum)",
            payload="?author=1",
            evidence=f"Found {len(usernames)} user(s): {', '.join(usernames)}",
            confidence="medium",
            details=(
                f"wpscan enumerated {len(usernames)} WordPress user(s). "
                "Valid usernames can be used for brute-force attacks against wp-login.php. "
                "Disable user enumeration via REST API: add 'remove_action(\"rest_api_init\", \"...)' in functions.php."
            ),
            reproduction=(
                f"# Enumerate users:\n"
                f"$ curl -s '{url}/wp-json/wp/v2/users'\n"
                f"# Or:\n"
                f"$ wpscan --url '{url}' --enumerate u\n"
                f"# Brute-force (authorized only):\n"
                f"$ wpscan --url '{url}' -U {usernames[0]} -P /usr/share/wordlists/rockyou.txt"
            ),
        ))

    return findings


def _add_vuln_finding(
    findings: List[Finding], url: str, vuln: Dict, component: str, kind: str,
) -> None:
    title = vuln.get("title", "Unknown vulnerability")
    refs  = vuln.get("references", {})
    cves  = refs.get("cve", []) if isinstance(refs, dict) else []
    wpv_url = refs.get("url", [])
    cve_str = ", ".join(f"CVE-{c}" for c in (cves or [])[:3])
    ref_url = wpv_url[0] if wpv_url else ""

    repro_lines = [
        f"# wpscan: {component} — {title}",
    ]
    if cve_str:
        repro_lines.append(f"# CVE(s): {cve_str}")
    if ref_url:
        repro_lines.append(f"# Reference: {ref_url}")
    repro_lines += [
        "",
        f"# Scan with nuclei for CVE-specific PoC:",
    ]
    for cve in (cves or [])[:2]:
        repro_lines.append(f"$ nuclei -u '{url}' -tags CVE-{cve} -j")
    if cves:
        repro_lines.append(f"$ searchsploit 'CVE-{cves[0]}'")

    findings.append(Finding(
        vuln_type=f"WordPress {kind.title()} Vulnerability [wpscan]",
        url=url,
        method="GET",
        parameter=f"({component})",
        payload=cve_str or title[:60],
        evidence=f"{component}: {title[:100]}",
        confidence="high" if cves else "medium",
        details=(
            f"wpscan found a vulnerability in {component}: {title}. "
            + (f"CVE(s): {cve_str}." if cve_str else "")
        ),
        reproduction="\n".join(repro_lines),
    ))


class WPScanRunner:
    """Run wpscan against a target and return normalised Finding objects."""

    def __init__(self, config: Dict) -> None:
        self.config = config

    def run(self, url: str) -> List[Finding]:
        from . import is_available
        if not is_available("wpscan"):
            logger.warning("[wpscan] not found on PATH — skipping.")
            return []

        if not _looks_like_wordpress(self.config, url):
            logger.info("[wpscan] target does not appear to be WordPress — skipping.")
            return []

        api_token = self.config.get("wpscan_api_token") or os.environ.get("WPSCAN_API_TOKEN")
        cookies_d = self.config.get("cookies") or {}
        cookies_s = "; ".join(f"{k}={v}" for k, v in cookies_d.items())
        proxy     = self.config.get("proxy")
        timeout   = max(30, self.config.get("timeout", 10) * 3)

        # Enumerate: WordPress version (v), plugins (p), themes (t), users (u), timthumbs (tt)
        enumerate = "vp,vt,u,tt"

        with tempfile.NamedTemporaryFile(
            prefix="abaddon_wpscan_", suffix=".json", delete=False
        ) as tf:
            out_path = tf.name

        try:
            cmd = _build_command(
                url=url, api_token=api_token, enumerate=enumerate,
                proxy=proxy, cookies=cookies_s,
                timeout=timeout, output_file=out_path,
            )
            logger.info("[wpscan] command: %s", " ".join(cmd))
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout + 60,
                )
            except subprocess.TimeoutExpired:
                logger.warning("[wpscan] timed out.")
                return []
            except FileNotFoundError:
                logger.warning("[wpscan] binary not found.")
                return []

            findings = _parse_output(out_path, url)
            if findings:
                logger.info("[wpscan] %d finding(s).", len(findings))
            else:
                logger.info("[wpscan] no findings (or no WP detected).")
            return findings
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
