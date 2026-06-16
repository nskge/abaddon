"""Strict Pydantic V2 schemas for the ABADDON template DSL (Nuclei-inspired).

A template declares *what* to send and *how* to decide a hit — never imperative
Python. Every field is validated with ``extra="forbid"`` so a typo fails loudly
at load time instead of silently disabling a check.

Template shape (YAML)::

    id: git-config-exposure
    info:
      name: Exposed .git/config
      severity: medium
      tags: [exposure, git]
    requests:
      - method: GET
        path: ["/.git/config"]
        matchers-condition: and
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["[core]", "repositoryformatversion"]
            condition: or
        extractors:
          - type: regex
            name: remote_url
            regex: ['url = (.+)']
"""

from enum import Enum
from typing import Annotated, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class _Strict(BaseModel):
    """Base model that forbids unknown fields."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TemplateInfo(_Strict):
    name: str
    severity: Severity = Severity.info
    author: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    reference: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Matchers
# --------------------------------------------------------------------------

class _BaseMatcher(_Strict):
    # When true, a positive match means "NOT vulnerable" (logical negation).
    negative: bool = False
    # Per-matcher confidence weight fed into the correlation engine.
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class WordMatcher(_BaseMatcher):
    type: Literal["word"]
    words: List[str]
    part: Literal["body", "header", "all"] = "body"
    condition: Literal["and", "or"] = "or"
    case_insensitive: bool = False


class RegexMatcher(_BaseMatcher):
    type: Literal["regex"]
    regex: List[str]
    part: Literal["body", "header", "all"] = "body"
    condition: Literal["and", "or"] = "or"

    @field_validator("regex")
    @classmethod
    def _compile_ok(cls, value: List[str]) -> List[str]:
        import re

        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
        return value


class StatusMatcher(_BaseMatcher):
    type: Literal["status"]
    status: List[int]


class TimeMatcher(_BaseMatcher):
    type: Literal["time"]
    # Response must be slower than baseline by at least `threshold` seconds.
    threshold: float = Field(gt=0.0)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class EntropyMatcher(_BaseMatcher):
    type: Literal["entropy"]
    # Minimum normalised size delta (fraction) vs baseline to flag.
    size_delta: float = Field(default=0.25, ge=0.0)
    confidence: float = Field(default=0.4, ge=0.0, le=1.0)


class ReflectionMatcher(_BaseMatcher):
    type: Literal["reflection"]
    # Marker injected in the payload; matcher confirms it breaks HTML/JS context.
    marker: str
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class OASTMatcher(_BaseMatcher):
    type: Literal["oast"]
    # Protocols to count as a hit (dns/http).
    protocols: List[Literal["dns", "http"]] = Field(default_factory=lambda: ["dns", "http"])
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)


Matcher = Annotated[
    Union[
        WordMatcher,
        RegexMatcher,
        StatusMatcher,
        TimeMatcher,
        EntropyMatcher,
        ReflectionMatcher,
        OASTMatcher,
    ],
    Field(discriminator="type"),
]


# --------------------------------------------------------------------------
# Extractors (workflow chaining)
# --------------------------------------------------------------------------

class Extractor(_Strict):
    type: Literal["regex", "header", "json"]
    name: str
    part: Literal["body", "header", "all"] = "body"
    regex: List[str] = Field(default_factory=list)
    group: int = 1
    # For header extractor: header name. For json extractor: dotted JSON path.
    key: Optional[str] = None

    @field_validator("regex")
    @classmethod
    def _compile_ok(cls, value: List[str]) -> List[str]:
        import re

        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
        return value


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------

class RequestSpec(_Strict):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] = "GET"
    # Path templates appended to the base target. Support {{var}} interpolation.
    path: List[str] = Field(default_factory=lambda: ["/"])
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    matchers: List[Matcher] = Field(default_factory=list)
    extractors: List[Extractor] = Field(default_factory=list)
    matchers_condition: Literal["and", "or", "dsl"] = Field(
        default="or", alias="matchers-condition"
    )
    # Send N times and require consistent matching (for time/differential checks).
    repeat: int = Field(default=1, ge=1, le=10)

    model_config = ConfigDict(
        extra="forbid", str_strip_whitespace=True, populate_by_name=True
    )


class Template(_Strict):
    id: str
    info: TemplateInfo
    requests: List[RequestSpec] = Field(min_length=1)
    # Global confidence threshold to promote a finding to "confirmed".
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)

    @field_validator("id")
    @classmethod
    def _id_slug(cls, value: str) -> str:
        if not value or " " in value:
            raise ValueError("template id must be a non-empty slug without spaces")
        return value
