"""Correlation engine — turn matcher confidences into a single verdict.

A finding is only as trustworthy as the *combination* of signals behind it. A
lone ``word`` match is weak; a ``word`` + ``entropy`` + ``oast`` agreement is
near-certain. The engine combines per-matcher confidences with **noisy-OR**::

    P(vuln) = 1 - Π (1 - confidence_i)

which rewards multiple *independent* confirmations without ever exceeding 1.0.
The aggregate is compared against the template's ``confidence_threshold`` to
decide whether to emit a confirmed :class:`Finding`.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from ..models.schemas import RequestSpec, Template
from .matchers import MatchContext, MatchResult, evaluate_matcher


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    url: str
    confidence: float
    matched_signals: List[str] = field(default_factory=list)
    poc: str = ""

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "confidence": round(self.confidence, 3),
            "matched_signals": self.matched_signals,
            "poc": self.poc,
        }


def noisy_or(confidences: List[float]) -> float:
    product = 1.0
    for c in confidences:
        product *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - product


class CorrelationEngine:
    """Combine matcher results per request and emit confirmed findings."""

    def evaluate_request(
        self,
        template: Template,
        request: RequestSpec,
        ctx: MatchContext,
        url: str,
    ) -> Optional[Finding]:
        if not request.matchers:
            return None

        results: List[MatchResult] = [
            evaluate_matcher(m, ctx) for m in request.matchers
        ]
        matched = [r for r in results if r.matched]

        condition = request.matchers_condition
        if condition == "and":
            gate = len(matched) == len(results)
        else:  # "or" and "dsl" (dsl falls back to or-of-matched for now)
            gate = len(matched) > 0

        if not gate or not matched:
            return None

        confidence = noisy_or([r.confidence for r in matched])
        if confidence < template.confidence_threshold:
            return None

        signals = [f"{r.name}: {r.detail}" for r in matched]
        return Finding(
            template_id=template.id,
            name=template.info.name,
            severity=template.info.severity.value,
            url=url,
            confidence=confidence,
            matched_signals=signals,
            poc=f"curl -ksi '{url}'",
        )
