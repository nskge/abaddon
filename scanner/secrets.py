"""Passive secret detection over fetched response bodies.

Why this exists
---------------
Front-end bundles, JSON responses, and HTML comments routinely leak API keys,
tokens, and other credentials that were meant to stay server-side. These are
*passive* findings: we don't inject anything, we just scan every body the
crawler already fetched. That makes the check free of false positives from
probing and lets it cover the entire crawled surface (HTML, JS, JSON, CSS).

The patterns are intentionally high-signal. Each is anchored either to a
provider-specific shape (``AKIA…``, ``sk_live_…``, JWT ``eyJ…``) or to an
assignment whose *key name* says "secret"/"token"/"api key" — so an analytics
id or a long random CSS class won't trip it.
"""

import base64
import re
from typing import Dict, List, Tuple

import logging

from .modules.base import Finding

logger = logging.getLogger("vulnscanner")


def _to_grep_pattern(rx: "re.Pattern") -> str:
    """Convert a Python regex to a shell-safe grep -iE pattern.

    Strips inline-flag groups ((?i), (?m) etc.) and converts non-capturing
    groups (?:...) to plain groups so the pattern is valid POSIX ERE.
    Double-quotes inside are escaped so the caller can wrap the result in
    double-quotes on the command line.
    """
    p = rx.pattern
    p = re.sub(r"\(\?[a-z]+\)", "", p)   # remove (?i), (?m), etc.
    p = p.replace("(?:", "(")            # (?:...) → (...) — ERE-compatible
    p = p.replace('"', '\\"')            # escape " so the shell string is valid
    return p[:120]

# (name, compiled regex, confidence, description)
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern", str, str]] = [
    (
        "CTF flag",
        re.compile(r"FLAG\{[^}\s]{3,}\}"),
        "high",
        "A CTF flag string is exposed in the response body.",
    ),
    (
        "AWS access key id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
        "An AWS access key id is exposed; pair with a secret it grants cloud access.",
    ),
    (
        "Stripe live secret key",
        re.compile(r"\bsk_live_[0-9A-Za-z]{10,}\b"),
        "high",
        "A live Stripe secret key is exposed; it can move real money.",
    ),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
        "medium",
        "A JWT is embedded in the response; it may contain credentials or grant access.",
    ),
    (
        "Hardcoded credential assignment",
        # key name must signal a secret; value must be a non-trivial literal.
        re.compile(
            r"""(?i)(?:api[_-]?key|secret|token|password|passwd|bearer|access[_-]?key)"""
            r"""["']?\s*[:=]\s*["']([^"']{12,})["']"""
        ),
        "medium",
        "A credential-looking value is hardcoded in the response body.",
    ),
]

# Obvious placeholders we never want to flag.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x+|\*+|\.+|changeme|your[_-]?\w+|example|placeholder|none|null|true|false|"
    r"\$\{[^}]+\}|<[^>]+>)$",
    re.IGNORECASE,
)

# Only scan text-ish content (skip binary/image bodies the crawler may hold).
_TEXT_CT_HINTS = ("text", "json", "javascript", "xml", "html", "css", "")


def _is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(h in ct for h in _TEXT_CT_HINTS)


# base64 blobs: explicit atob("…") wrappers and standalone quoted base64 strings.
_B64_RE = re.compile(r"""(?:atob\(\s*["']|["'])([A-Za-z0-9+/]{12,}={0,2})["']""")


def _decode_layer(body: str) -> str:
    """Return decoded text for base64/atob-wrapped values found in *body*.

    Secrets are increasingly hidden behind ``atob("…")`` or plain base64 so a
    naive ``FLAG{`` / ``sk_live_`` regex misses them. We decode candidate blobs
    and hand the printable results back to the same pattern set.
    """
    out: List[str] = []
    for m in _B64_RE.finditer(body):
        blob = m.group(1)
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        # keep only printable decodes that look like content, not binary noise
        if dec and (dec.isprintable() or "FLAG{" in dec):
            out.append(dec)
    return "\n".join(out)


def _matched_value(m: "re.Match") -> str:
    """Return the captured secret (group 1 if present, else whole match)."""
    return m.group(1) if m.groups() else m.group(0)


def scan_pages(pages) -> List[Finding]:
    """Scan crawler pages for exposed secrets; one finding per unique secret.

    *pages* is any iterable of objects exposing ``url``, ``body`` and
    ``content_type`` (the crawler's :class:`~scanner.crawler.Page`).
    """
    findings: List[Finding] = []
    seen: set = set()  # dedup by secret VALUE (a secret is one finding even if
                       # several patterns match it; patterns are ordered
                       # most-specific first, so the best label wins).

    for page in pages:
        if not _is_textual(getattr(page, "content_type", "")):
            continue
        body = getattr(page, "body", "") or ""
        url = getattr(page, "url", "")

        # Scan the raw body and, separately, anything we can base64/atob-decode
        # from it (so obfuscated secrets are still caught).
        corpora = [(body, "")]
        decoded = _decode_layer(body)
        if decoded:
            corpora.append((decoded, " [base64-decoded]"))

        for corpus, origin in corpora:
            for name, rx, confidence, desc in _SECRET_PATTERNS:
                for m in rx.finditer(corpus):
                    value = _matched_value(m).strip()
                    if not value or _PLACEHOLDER_RE.match(value):
                        continue
                    if value in seen:
                        continue
                    seen.add(value)

                    masked = value if value.startswith("FLAG{") else _mask(value)
                    snippet = _context(corpus, m.start())
                    findings.append(Finding(
                        vuln_type=f"Sensitive Data Exposure ({name}{origin})",
                        url=url,
                        method="GET",
                        parameter="(response body)",
                        payload="N/A",
                        evidence=f"{name} found in {url}: {masked}  (…{snippet}…)",
                        confidence=confidence,
                        details=(
                            f"{desc} "
                            f"Secrets shipped to the client are readable by anyone. "
                            f"Remediation: move secrets server-side, rotate the exposed "
                            f"value, and scan bundles in CI to prevent regressions."
                        ),
                        reproduction=(
                            f"# 1. Fetch the resource:\n"
                            f"$ curl -s '{url}'\n"
                            f"# 2. Search the body for the secret:\n"
                            f'$ curl -s \'{url}\' | grep -iEo "{_to_grep_pattern(rx)}"\n'
                            f"# 3. The value above is served to every client — rotate it."
                        ),
                    ))

    if findings:
        logger.info("Secret scan: %d exposed secret(s) found", len(findings))
    return findings


def _mask(value: str) -> str:
    """Mask the middle of a secret so the report doesn't re-leak it in full."""
    if len(value) <= 8:
        return value[0] + "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _context(body: str, idx: int, radius: int = 25) -> str:
    start = max(0, idx - radius)
    end = min(len(body), idx + radius)
    return body[start:end].replace("\n", " ").strip()
