"""Template loader — parse + strictly validate YAML templates.

Every ``*.yaml`` / ``*.yml`` file under the template directory is parsed and
validated against :class:`~abaddon.models.schemas.Template`. Malformed templates
are **discarded silently from the run** but recorded with a structured error so
a broken template can never crash the engine or — worse — load a half-valid
check that produces garbage findings.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Tuple, Union

import yaml
from pydantic import ValidationError

from ..models.schemas import Template

logger = logging.getLogger("abaddon")


@dataclass
class LoadReport:
    """Outcome of a template-directory load."""

    loaded: List[Template] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)  # (path, reason)

    @property
    def ok_count(self) -> int:
        return len(self.loaded)

    @property
    def error_count(self) -> int:
        return len(self.errors)


def load_template_file(path: Union[str, Path]) -> Template:
    """Load and validate a single template file. Raises on invalid input."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("template root must be a mapping")
    return Template.model_validate(raw)


def _iter_template_paths(directory: Path) -> Iterable[Path]:
    for ext in ("*.yaml", "*.yml"):
        yield from sorted(directory.rglob(ext))


def load_templates(directory: Union[str, Path]) -> LoadReport:
    """Load every template under *directory*, validating each one strictly."""
    directory = Path(directory)
    report = LoadReport()

    if not directory.exists():
        logger.warning("template directory not found: %s", directory)
        return report

    seen_ids: dict = {}
    for path in _iter_template_paths(directory):
        rel = str(path)
        try:
            template = load_template_file(path)
        except ValidationError as exc:
            reason = f"schema validation failed: {exc.error_count()} error(s)"
            report.errors.append((rel, reason))
            logger.error("template rejected (%s): %s", rel, reason)
            continue
        except (yaml.YAMLError, ValueError, OSError) as exc:
            reason = f"{type(exc).__name__}: {exc}"
            report.errors.append((rel, reason))
            logger.error("template rejected (%s): %s", rel, reason)
            continue

        if template.id in seen_ids:
            reason = f"duplicate id (already defined in {seen_ids[template.id]})"
            report.errors.append((rel, reason))
            logger.error("template rejected (%s): %s", rel, reason)
            continue

        seen_ids[template.id] = rel
        report.loaded.append(template)

    logger.info(
        "templates loaded: %d ok, %d rejected", report.ok_count, report.error_count
    )
    return report
