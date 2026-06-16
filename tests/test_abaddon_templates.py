"""Tests for ABADDON template schemas and loader."""

import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import ValidationError

from abaddon.models.schemas import Severity, Template
from abaddon.parsers.template_engine import load_template_file, load_templates


_VALID = """
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

_UNKNOWN_FIELD = """
id: bad-template
info:
  name: Bad
  severity: low
requests:
  - method: GET
    path: ["/"]
    bogus_field: 123
    matchers:
      - type: status
        status: [200]
"""

_BAD_MATCHER_TYPE = """
id: bad-matcher
info:
  name: Bad matcher
requests:
  - method: GET
    path: ["/"]
    matchers:
      - type: nonexistent
        foo: bar
"""

_BAD_REGEX = """
id: bad-regex
info:
  name: Bad regex
requests:
  - method: GET
    path: ["/"]
    matchers:
      - type: regex
        regex: ['(unclosed']
"""


def _write(d: Path, name: str, content: str) -> Path:
    p = d / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


class TestSchemas(unittest.TestCase):

    def test_valid_template_parses(self):
        with TemporaryDirectory() as d:
            path = _write(Path(d), "t.yaml", _VALID)
            tpl = load_template_file(path)
        self.assertEqual(tpl.id, "git-config-exposure")
        self.assertEqual(tpl.info.severity, Severity.medium)
        self.assertEqual(len(tpl.requests), 1)
        req = tpl.requests[0]
        self.assertEqual(req.matchers_condition, "and")
        self.assertEqual(len(req.matchers), 2)
        self.assertEqual(len(req.extractors), 1)

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValidationError):
            Template.model_validate(
                {
                    "id": "x",
                    "info": {"name": "x"},
                    "requests": [{"method": "GET", "path": ["/"], "junk": 1}],
                }
            )

    def test_bad_matcher_type_rejected(self):
        with self.assertRaises(ValidationError):
            Template.model_validate(
                {
                    "id": "x",
                    "info": {"name": "x"},
                    "requests": [
                        {"path": ["/"], "matchers": [{"type": "nope"}]}
                    ],
                }
            )

    def test_id_with_space_rejected(self):
        with self.assertRaises(ValidationError):
            Template.model_validate(
                {"id": "bad id", "info": {"name": "x"}, "requests": [{"path": ["/"]}]}
            )

    def test_invalid_regex_rejected(self):
        with self.assertRaises(ValidationError):
            Template.model_validate(
                {
                    "id": "x",
                    "info": {"name": "x"},
                    "requests": [
                        {"path": ["/"], "matchers": [{"type": "regex", "regex": ["(unclosed"]}]}
                    ],
                }
            )

    def test_empty_requests_rejected(self):
        with self.assertRaises(ValidationError):
            Template.model_validate({"id": "x", "info": {"name": "x"}, "requests": []})


class TestLoader(unittest.TestCase):

    def test_loads_valid_skips_malformed(self):
        with TemporaryDirectory() as d:
            dpath = Path(d)
            _write(dpath, "good.yaml", _VALID)
            _write(dpath, "unknown.yaml", _UNKNOWN_FIELD)
            _write(dpath, "badmatcher.yaml", _BAD_MATCHER_TYPE)
            _write(dpath, "badregex.yaml", _BAD_REGEX)
            _write(dpath, "notyaml.yaml", "{[this is : not valid yaml")
            report = load_templates(dpath)

        self.assertEqual(report.ok_count, 1)
        self.assertEqual(report.loaded[0].id, "git-config-exposure")
        self.assertGreaterEqual(report.error_count, 4)

    def test_duplicate_id_rejected(self):
        with TemporaryDirectory() as d:
            dpath = Path(d)
            _write(dpath, "a.yaml", _VALID)
            _write(dpath, "b.yaml", _VALID)  # same id
            report = load_templates(dpath)
        self.assertEqual(report.ok_count, 1)
        self.assertEqual(report.error_count, 1)
        self.assertIn("duplicate", report.errors[0][1])

    def test_missing_directory_returns_empty(self):
        report = load_templates(Path("does/not/exist/anywhere"))
        self.assertEqual(report.ok_count, 0)
        self.assertEqual(report.error_count, 0)


if __name__ == "__main__":
    unittest.main()
