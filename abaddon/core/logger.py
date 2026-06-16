"""Observability — structlog console + JSONL result sink.

Confirmed findings are appended to ``abaddon_results.jsonl`` as one pure JSON
object per line (timestamp, target, template_id, severity, confidence, url,
poc) — no decoration, ready for SIEM/C2 ingestion.
"""

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import structlog


def configure(verbose: bool = False) -> None:
    """Configure structlog for human-readable console logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


class ResultSink:
    """Append confirmed findings to a JSONL file."""

    def __init__(self, path: Optional[str] = "abaddon_results.jsonl") -> None:
        self.path = Path(path) if path else None
        self.count = 0

    def write(self, target: str, finding) -> None:
        if self.path is None:
            return
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "target": target,
            "template_id": finding.template_id,
            "severity": finding.severity,
            "confidence": round(finding.confidence, 3),
            "url": finding.url,
            "poc": finding.poc,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.count += 1
