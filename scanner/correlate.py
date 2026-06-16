"""Attack-path correlation -- compose individual findings into escalation chains.

Inspired by BloodHound: rather than inventing new signals, this module only
draws *edges between findings that were already confirmed*, exactly as
BloodHound only draws paths over relationships it actually collected.  It issues
no network requests and never lowers the bar for a finding, so it introduces
zero new false positives.

The output turns a flat list of isolated issues ("8 findings") into a small set
of prioritised attack paths ("1 path to RCE"), the same way BloodHound turns
scattered ACLs into a shortest path to Domain Admin.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from .modules.base import Finding

# Severity ordering for sorting (lower = more severe / printed first)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2}


@dataclass
class AttackPath:
    """A confirmed escalation chain built from two or more findings."""

    name: str
    severity: str  # "critical" | "high" | "medium"
    steps: List[str]
    narrative: str
    recommendation: str
    host: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "steps": self.steps,
            "narrative": self.narrative,
            "recommendation": self.recommendation,
        }


def _host(f: Finding) -> str:
    try:
        return urlparse(f.url).hostname or ""
    except Exception:
        return ""


class _HostView:
    """Convenience lookups over the findings for a single host."""

    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings

    def all(self, *substrings: str) -> List[Finding]:
        """Findings whose type contains ALL of *substrings* (case-insensitive)."""
        out = []
        for f in self.findings:
            t = f.vuln_type.lower()
            if all(s.lower() in t for s in substrings):
                out.append(f)
        return out

    def any(self, *substrings: str) -> List[Finding]:
        """Findings whose type contains ANY of *substrings*."""
        out = []
        for f in self.findings:
            t = f.vuln_type.lower()
            if any(s.lower() in t for s in substrings):
                out.append(f)
        return out

    def first(self, *substrings: str) -> Optional[Finding]:
        matches = self.all(*substrings)
        return matches[0] if matches else None

    def evidence_blob(self) -> str:
        return " ".join(
            f"{f.vuln_type} {f.payload} {f.evidence} {f.details or ''}"
            for f in self.findings
        ).lower()


# ---------------------------------------------------------------------------
# Chain rules.  Each rule inspects one host's findings and returns an
# AttackPath when the combination is present, else None.
# ---------------------------------------------------------------------------


def _chain_sqli_jwt(v: _HostView) -> Optional[AttackPath]:
    sqli = v.first("sql injection")
    jwt = v.first("weak hmac") or v.first("jwt", "secret")
    if sqli and jwt:
        return AttackPath(
            name="Account Takeover: SQLi data theft + forgeable sessions",
            severity="critical",
            steps=[
                f"SQLi on param {sqli.parameter!r} ({sqli.vuln_type})",
                f"Weak/forgeable JWT ({jwt.vuln_type})",
            ],
            narrative=(
                "The SQL injection lets an attacker dump the user table "
                "(usernames, password hashes, the JWT signing secret if stored "
                "in the DB). The weak JWT secret then lets them forge a valid "
                "session for any user (including admins) without cracking a "
                "single password. Together these escalate from data disclosure "
                "to full, persistent account takeover."
            ),
            recommendation=(
                "Fix the SQLi with parameterised queries AND rotate the JWT "
                "signing key to a long random secret; revoke existing tokens."
            ),
        )
    return None


def _chain_lfi_rce(v: _HostView) -> Optional[AttackPath]:
    lfi = v.first("local file inclusion")
    if not lfi:
        return None
    blob = v.evidence_blob()
    log_reachable = any(k in blob for k in ("access.log", "error.log", "/proc/self/environ"))
    php_filter = "php filter" in lfi.vuln_type.lower() or "php://filter" in blob
    if log_reachable or php_filter:
        vector = "log poisoning" if log_reachable else "PHP source disclosure → deserialisation/config leak"
        return AttackPath(
            name="LFI escalation to RCE / source disclosure",
            severity="high",
            steps=[
                f"LFI on param {lfi.parameter!r}",
                f"Reachable sink: {'web/auth logs or /proc/self/environ' if log_reachable else 'php://filter source read'}",
            ],
            narrative=(
                "The confirmed local file inclusion is not just a read primitive: "
                f"it can be escalated to code execution via {vector}. "
                "An attacker injects PHP into a log line (User-Agent / auth attempt), "
                "then includes that log through the same LFI to execute it; or reads "
                "application source and secrets to find further footholds."
            ),
            recommendation=(
                "Whitelist includable resources and disable user-controlled stream "
                "wrappers (allow_url_include=Off, open_basedir); never include logs."
            ),
        )
    return None


def _chain_ssrf_cloud(v: _HostView) -> Optional[AttackPath]:
    ssrf = v.first("ssrf")
    if not ssrf:
        return None
    blob = (ssrf.evidence + " " + (ssrf.details or "")).lower()
    cloud = any(k in blob for k in (
        "metadata", "ami-id", "instance-id", "169.254.169.254",
        "iam", "computemetadata", "local-ipv4",
    ))
    if cloud:
        return AttackPath(
            name="SSRF to cloud credential theft",
            severity="critical",
            steps=[
                f"SSRF on param {ssrf.parameter!r}",
                "Reaches cloud metadata endpoint (169.254.169.254)",
            ],
            narrative=(
                "The SSRF reaches the cloud instance metadata service. An attacker "
                "can read short-lived IAM credentials from "
                "/latest/meta-data/iam/security-credentials/ and assume the "
                "instance role, pivoting from a web bug to full cloud account access."
            ),
            recommendation=(
                "Enforce IMDSv2 (hop limit 1, token required), egress-filter the "
                "metadata IP, and validate/allow-list outbound URLs."
            ),
        )
    return None


def _chain_open_redirect_token(v: _HostView) -> Optional[AttackPath]:
    redir = v.first("open redirect")
    auth = v.first("jwt") or v.first("weak hmac")
    if redir and auth:
        return AttackPath(
            name="Open Redirect to OAuth/token theft",
            severity="high",
            steps=[
                f"Open redirect on param {redir.parameter!r}",
                f"Token-based auth present ({auth.vuln_type})",
            ],
            narrative=(
                "The open redirect on an authentication-adjacent endpoint lets an "
                "attacker craft a link that bounces the victim (and any token in "
                "the URL fragment / OAuth code) to an attacker-controlled host, "
                "capturing the session or authorization code."
            ),
            recommendation=(
                "Allow-list redirect targets; never reflect user-supplied absolute "
                "URLs in redirect_uri / next parameters."
            ),
        )
    return None


def _chain_xss_session(v: _HostView) -> Optional[AttackPath]:
    """XSS → session hijack — but only assert the *real* containment gap.

    The previous version hard-coded "no CSP / no HttpOnly" in the narrative even
    when a CSP was present, which is a false statement in the report. Instead we
    derive the actual state from the sibling findings that the header/secret
    modules already produced:
      • CSP absent  -> a "Missing Security Header: Content-Security-Policy" finding
      • CSP weak    -> a "Weak Content-Security-Policy" finding
      • cookie risk -> a finding noting a non-HttpOnly session cookie
    We only build the chain when at least one of these containment gaps is real,
    and we phrase it according to which gap actually exists.
    """
    xss = v.first("cross-site scripting") or v.first("xss")
    if not xss:
        return None

    blob = v.evidence_blob()
    csp_absent = bool(v.all("missing", "content-security-policy")) \
        or "no content-security-policy" in blob or "no csp" in blob
    csp_weak = bool(v.all("weak", "content-security-policy")) or "weak csp" in blob
    # Only treat the cookie as a gap on an explicit NEGATIVE phrasing — never on
    # bare "httponly" (which also appears in remediation advice like "set HttpOnly").
    cookie_no_httponly = any(p in blob for p in (
        "without httponly", "no httponly", "not httponly",
        "lacks httponly", "non-httponly", "missing httponly",
    ))

    # No demonstrated containment gap → don't claim one. (A strong CSP + HttpOnly
    # cookie would actually mitigate the XSS, so asserting a hijack path would be
    # wrong.)
    if not (csp_absent or csp_weak or cookie_no_httponly):
        return None

    if csp_absent:
        csp_step = "no Content-Security-Policy is set to contain injected script"
    elif csp_weak:
        csp_step = "the Content-Security-Policy is weak (e.g. script-src 'unsafe-inline'), so inline script still runs"
    else:
        csp_step = "the session cookie is not HttpOnly, so document.cookie is readable from script"

    return AttackPath(
        name="Reflected XSS to session hijack",
        severity="high",
        steps=[
            f"Reflected XSS on param {xss.parameter!r}",
            csp_step,
        ],
        narrative=(
            "The reflected XSS executes attacker JavaScript in the victim's "
            f"session, and {csp_step}. The payload can therefore steal the "
            "session (or act in the victim's name) rather than being contained."
        ),
        recommendation=(
            "Output-encode reflected values, set HttpOnly+Secure+SameSite on "
            "session cookies, and deploy a strict Content-Security-Policy "
            "(no 'unsafe-inline', no wildcard sources)."
        ),
    )


def _chain_rce_cve(v: _HostView) -> Optional[AttackPath]:
    cve = v.first("known cve")
    if cve and cve.confidence == "high":
        return AttackPath(
            name="Outdated service with public exploit",
            severity="critical",
            steps=[
                f"{cve.evidence}",
                f"{cve.vuln_type} (confidence: {cve.confidence})",
            ],
            narrative=(
                "A confirmed outdated service version matches a known, "
                "high-severity CVE. Public exploits / Metasploit modules likely "
                "exist, giving a direct path to compromise without any further "
                "application bug."
            ),
            recommendation="Patch/upgrade the affected service immediately.",
        )
    return None


def _chain_idor_massassign(v: _HostView) -> Optional[AttackPath]:
    """IDOR/BOLA + mass assignment on the same host → full account takeover.

    Each is serious alone, but together they compound: mass assignment lets an
    attacker elevate their OWN account (grant admin/credit), while BOLA lets them
    read or act on OTHER users' objects. Chained, an attacker self-promotes and
    then operates across every account — the classic path to total takeover.
    """
    idor = v.first("idor") or v.first("bola")
    massa = v.first("mass assignment")
    if idor and massa:
        return AttackPath(
            name="Account takeover: self-escalation + cross-account access",
            severity="critical",
            steps=[
                f"Mass assignment ({massa.parameter}) — elevate own privileges",
                f"IDOR/BOLA ({idor.url}) — read/act on other users' objects",
            ],
            narrative=(
                "Mass assignment lets the attacker grant their own account "
                "privileges the server should control (admin / tier / credit). "
                "Broken object-level authorization then lets that account reach "
                "every other user's data and actions. Combined, a normal user "
                "becomes an admin operating across all accounts."
            ),
            recommendation=(
                "Bind only allow-listed fields on profile updates AND enforce a "
                "per-object ownership check on every object access."
            ),
        )
    return None


_RULES: List[Callable[[_HostView], Optional[AttackPath]]] = [
    _chain_sqli_jwt,
    _chain_idor_massassign,
    _chain_lfi_rce,
    _chain_ssrf_cloud,
    _chain_open_redirect_token,
    _chain_xss_session,
    _chain_rce_cve,
]


def correlate_findings(findings: List[Finding]) -> List[AttackPath]:
    """Group findings by host and return the attack paths that apply.

    Pure post-processing over confirmed findings — issues no requests and adds
    no new findings, only relationships between existing ones.
    """
    if not findings:
        return []

    by_host: Dict[str, List[Finding]] = {}
    for f in findings:
        by_host.setdefault(_host(f), []).append(f)

    paths: List[AttackPath] = []
    for host, host_findings in by_host.items():
        view = _HostView(host_findings)
        for rule in _RULES:
            path = rule(view)
            if path is not None:
                path.host = host
                paths.append(path)

    paths.sort(key=lambda p: _SEVERITY_RANK.get(p.severity, 9))
    return paths
