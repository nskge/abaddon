"""Base classes shared across all scanner modules."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger("vulnscanner")


class Finding:
    """Represents a single confirmed or suspected vulnerability."""

    def __init__(
        self,
        vuln_type: str,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        evidence: str,
        confidence: str = "medium",
        details: Optional[str] = None,
    ) -> None:
        """
        Args:
            vuln_type:  Human-readable vulnerability label (e.g. "SQL Injection (Error-based)").
            url:        Target URL (without injected payload).
            method:     HTTP method used ("GET" or "POST").
            parameter:  Name of the vulnerable parameter.
            payload:    Payload string that triggered the finding.
            evidence:   Short excerpt proving the vulnerability (error snippet, timing, etc.).
            confidence: Reliability level — "high", "medium", or "low".
            details:    Optional longer explanation / remediation hint.
        """
        self.vuln_type = vuln_type
        self.url = url
        self.method = method
        self.parameter = parameter
        self.payload = payload
        self.evidence = evidence
        self.confidence = confidence
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (suitable for JSON export)."""
        return {
            "type": self.vuln_type,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return (
            f"Finding(type={self.vuln_type!r}, param={self.parameter!r}, "
            f"confidence={self.confidence!r})"
        )


class BaseModule(ABC):
    """Abstract base for every vulnerability scanner module."""

    NAME: str = "base"

    def __init__(self, http_client: Any, config: Dict) -> None:
        self.http = http_client
        self.config = config
        self.findings: List[Finding] = []

    @abstractmethod
    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """Test a single parameter for this vulnerability type.

        Args:
            url:        Base URL (query string already stripped for GET).
            method:     "GET" or "POST".
            params:     All current parameter values.
            param_name: The specific parameter being fuzzed.

        Returns:
            List of Finding objects (empty when nothing found).
        """

    def load_payloads(
        self,
        defaults: List[str],
        payload_file: Optional[str] = None,
    ) -> List[str]:
        """Return payloads from *payload_file* if given, else *defaults*.

        Lines starting with '#' and blank lines are skipped.
        Falls back to *defaults* on any file-read error.
        """
        if not payload_file:
            return defaults
        try:
            with open(payload_file, "r", encoding="utf-8") as fh:
                loaded = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
            logger.debug("Loaded %d payloads from %s", len(loaded), payload_file)
            return loaded
        except OSError as exc:
            logger.warning("Cannot read payload file %s (%s) — using defaults.", payload_file, exc)
            return defaults
