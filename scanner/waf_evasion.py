"""WAF evasion payload transforms.

Expands a base payload list with encoded and obfuscated variants that
commonly bypass signature-based filters.  Three levels of aggression:

    level 1  -- URL encoding + null byte             (fast, low noise)
    level 2  -- + double encoding + mixed case       (moderate)
    level 3  -- + HTML entities + SQL comment breaks (thorough)

Usage example::

    from scanner.waf_evasion import apply_evasion
    payloads = apply_evasion(["' OR 1=1--", "<script>"], level=2)
"""

import urllib.parse
from typing import Callable, List, Tuple


# ---------------------------------------------------------------------------
# Individual transforms
# ---------------------------------------------------------------------------

def _url_encode(s: str) -> str:
    """Percent-encode every character."""
    return urllib.parse.quote(s, safe="")


def _double_url_encode(s: str) -> str:
    """Double percent-encode (bypasses single-decode filters)."""
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _null_byte_suffix(s: str) -> str:
    """Append a URL-encoded null byte (truncates string in some parsers)."""
    return s + "%00"


def _mixed_case(s: str) -> str:
    """Alternate upper/lower on alphabetic chars (keyword detection bypass)."""
    out = []
    upper = True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def _html_entities(s: str) -> str:
    """Replace < > \" ' with HTML entities."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#x27;")
    )


_SQL_KEYWORDS = [
    "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER",
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
    "EXEC", "EXECUTE", "CAST", "CONVERT", "CHAR",
]


def _sql_comment_break(s: str) -> str:
    """Inject /**/ between SQL keywords to break pattern matching."""
    result = s
    for kw in _SQL_KEYWORDS:
        result = result.replace(kw, f"/**/{ kw}/**/")
        result = result.replace(kw.lower(), f"/**/{kw.lower()}/**/")
    return result


# (name, function, min_level_required)
_TRANSFORMS: List[Tuple[str, Callable[[str], str], int]] = [
    ("url_encode",        _url_encode,        1),
    ("null_byte",         _null_byte_suffix,  1),
    ("double_encode",     _double_url_encode, 2),
    ("mixed_case",        _mixed_case,        2),
    ("html_entities",     _html_entities,     3),
    ("sql_comments",      _sql_comment_break, 3),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_evasion(payloads: List[str], level: int = 1) -> List[str]:
    """Return *payloads* expanded with WAF evasion variants up to *level*.

    Args:
        payloads: Original payload list.
        level:    Evasion intensity 1–3.  Higher = more variants, more noise.

    Returns:
        New list starting with original payloads followed by unique variants.
    """
    level = max(1, min(3, level))
    active = [(name, fn) for name, fn, min_lv in _TRANSFORMS if min_lv <= level]

    result = list(payloads)
    seen = set(result)

    for payload in payloads:
        for _, fn in active:
            variant = fn(payload)
            if variant and variant != payload and variant not in seen:
                seen.add(variant)
                result.append(variant)

    return result
