"""Smart matchers — the inference layer that beats naive ``grep``.

Each matcher consumes a :class:`MatchContext` (the contaminated response plus an
optional clean baseline and an OAST provider) and emits a :class:`MatchResult`
carrying a **confidence** in ``[0, 1]``. The correlation engine combines those
confidences across signals so a finding is promoted only when the *aggregate*
evidence is strong — eliminating the single-regex false positive.

Matcher types
-------------
``word`` / ``regex`` / ``status``   classic content signals (low confidence alone)
``time``                            response-time delta vs baseline (blind timing)
``entropy``                         normalised size delta vs baseline (blind diff)
``reflection``                      context-aware XSS reflection via lxml parsing
``oast``                            out-of-band interaction (strongest proof)
"""

import html
import math
import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..models.schemas import (
    EntropyMatcher,
    OASTMatcher,
    ReflectionMatcher,
    RegexMatcher,
    StatusMatcher,
    TimeMatcher,
    WordMatcher,
)
from .oast import OASTProvider


@dataclass
class MatchContext:
    """Everything a matcher needs to make a decision."""

    body: str
    headers: dict
    status_code: Optional[int]
    elapsed: float
    baseline_body: str = ""
    baseline_elapsed: float = 0.0
    baseline_status: Optional[int] = None
    oast: Optional[OASTProvider] = None
    oast_correlation_id: Optional[str] = None
    reflection_marker: Optional[str] = None

    def part_text(self, part: str) -> str:
        if part == "header":
            return "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        if part == "all":
            header_text = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            return header_text + "\n" + self.body
        return self.body


@dataclass
class MatchResult:
    matched: bool
    confidence: float
    name: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _apply_negative(found: bool, negative: bool) -> bool:
    """A negative matcher inverts: it 'matches' when the pattern is absent."""
    return (not found) if negative else found


# ---------------------------------------------------------------------------
# Runtime matchers
# ---------------------------------------------------------------------------

def eval_word(m: WordMatcher, ctx: MatchContext) -> MatchResult:
    text = ctx.part_text(m.part)
    if m.case_insensitive:
        text = text.lower()
        words = [w.lower() for w in m.words]
    else:
        words = list(m.words)
    hits = [w for w in words if w in text]
    found = (len(hits) == len(words)) if m.condition == "and" else bool(hits)
    matched = _apply_negative(found, m.negative)
    return MatchResult(matched, m.confidence if matched else 0.0, "word",
                       f"matched words: {hits}" if hits else "no words matched")


def eval_regex(m: RegexMatcher, ctx: MatchContext) -> MatchResult:
    text = ctx.part_text(m.part)
    hits = [p for p in m.regex if re.search(p, text)]
    found = (len(hits) == len(m.regex)) if m.condition == "and" else bool(hits)
    matched = _apply_negative(found, m.negative)
    return MatchResult(matched, m.confidence if matched else 0.0, "regex",
                       f"matched regex: {hits}" if hits else "no regex matched")


def eval_status(m: StatusMatcher, ctx: MatchContext) -> MatchResult:
    found = ctx.status_code in m.status
    matched = _apply_negative(found, m.negative)
    return MatchResult(matched, m.confidence if matched else 0.0, "status",
                       f"status={ctx.status_code}")


def eval_time(m: TimeMatcher, ctx: MatchContext) -> MatchResult:
    delta = ctx.elapsed - ctx.baseline_elapsed
    found = delta >= m.threshold
    matched = _apply_negative(found, m.negative)
    # Confidence scales with how far past the threshold we are (capped).
    conf = 0.0
    if matched and not m.negative:
        ratio = delta / m.threshold if m.threshold else 1.0
        conf = min(m.confidence, m.confidence * min(ratio, 2.0) / 2.0 + m.confidence / 2.0)
    elif matched and m.negative:
        conf = m.confidence
    return MatchResult(matched, conf, "time",
                       f"delta={delta:.3f}s threshold={m.threshold}s")


def eval_entropy(m: EntropyMatcher, ctx: MatchContext) -> MatchResult:
    base_len = len(ctx.baseline_body)
    cur_len = len(ctx.body)
    if base_len == 0:
        return MatchResult(False, 0.0, "entropy", "no baseline")
    size_delta = abs(cur_len - base_len) / base_len
    ent_delta = abs(shannon_entropy(ctx.body) - shannon_entropy(ctx.baseline_body))
    found = size_delta >= m.size_delta
    matched = _apply_negative(found, m.negative)
    conf = 0.0
    if matched and not m.negative:
        conf = min(m.confidence, m.confidence * min(size_delta / m.size_delta, 2.0) / 2.0)
        conf = max(conf, m.confidence * 0.5)
    elif matched and m.negative:
        conf = m.confidence
    return MatchResult(matched, conf, "entropy",
                       f"size_delta={size_delta:.2%} entropy_delta={ent_delta:.3f}")


def eval_reflection(m: ReflectionMatcher, ctx: MatchContext) -> MatchResult:
    marker = ctx.reflection_marker or m.marker
    body = ctx.body
    if marker not in body:
        return MatchResult(_apply_negative(False, m.negative),
                           m.confidence if m.negative else 0.0,
                           "reflection", "marker not reflected")

    escaped = html.escape(marker)
    raw_unescaped = marker in body and (escaped not in body or escaped == marker)

    # Determine context with lxml: is the marker inside a <script> block?
    in_script = False
    try:
        from lxml import html as lxml_html

        tree = lxml_html.fromstring(body)
        for script in tree.iter("script"):
            if script.text and marker in script.text:
                in_script = True
                break
    except Exception:
        in_script = False

    if in_script:
        conf, detail = min(0.95, m.confidence + 0.2), "reflected in <script> (JS context)"
        found = True
    elif raw_unescaped:
        conf, detail = m.confidence, "reflected unescaped (HTML context broken)"
        found = True
    else:
        conf, detail = 0.0, "reflected but escaped/sanitised"
        found = False

    matched = _apply_negative(found, m.negative)
    if m.negative:
        conf = m.confidence if matched else 0.0
    return MatchResult(matched, conf if matched else 0.0, "reflection", detail)


def eval_oast(m: OASTMatcher, ctx: MatchContext) -> MatchResult:
    if ctx.oast is None or ctx.oast_correlation_id is None:
        return MatchResult(False, 0.0, "oast", "no OAST provider/correlation id")
    interactions = ctx.oast.poll(ctx.oast_correlation_id)
    relevant = [i for i in interactions if i.protocol in m.protocols]
    found = bool(relevant)
    matched = _apply_negative(found, m.negative)
    detail = (
        f"{len(relevant)} OAST interaction(s): "
        + ", ".join(sorted({i.protocol for i in relevant}))
        if relevant
        else "no OAST interaction"
    )
    return MatchResult(matched, m.confidence if matched else 0.0, "oast", detail)


# Dispatch table: schema class -> runtime evaluator.
_DISPATCH = {
    WordMatcher: eval_word,
    RegexMatcher: eval_regex,
    StatusMatcher: eval_status,
    TimeMatcher: eval_time,
    EntropyMatcher: eval_entropy,
    ReflectionMatcher: eval_reflection,
    OASTMatcher: eval_oast,
}


def evaluate_matcher(matcher, ctx: MatchContext) -> MatchResult:
    """Polymorphic dispatch to the right evaluator for *matcher*'s type."""
    evaluator = _DISPATCH.get(type(matcher))
    if evaluator is None:
        raise TypeError(f"no evaluator for matcher type {type(matcher).__name__}")
    return evaluator(matcher, ctx)
