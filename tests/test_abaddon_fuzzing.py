"""Tests for ABADDON payload fuzzing + bundled template library."""

import asyncio
import html
import unittest
from pathlib import Path

import httpx

from abaddon.core.runner import Scanner
from abaddon.models.schemas import Template
from abaddon.network.engine import AsyncEngine
from abaddon.parsers.template_engine import load_template_file, load_templates

_BUNDLED = Path(__file__).resolve().parents[1] / "abaddon" / "templates"


def _scan(template: Template, handler, base="http://target.local", oast=None, baseline=True):
    transport = httpx.MockTransport(handler)

    async def go():
        async with AsyncEngine(transport=transport) as engine:
            scanner = Scanner(engine, [template], oast=oast, use_baseline=baseline)
            return await scanner.scan(base)

    return asyncio.run(go())


class TestBundledTemplates(unittest.TestCase):

    def test_all_bundled_templates_valid(self):
        report = load_templates(_BUNDLED)
        self.assertEqual(report.error_count, 0, msg=f"rejected: {report.errors}")
        self.assertGreaterEqual(report.ok_count, 6)

    def test_template_ids_unique(self):
        report = load_templates(_BUNDLED)
        ids = [t.id for t in report.loaded]
        self.assertEqual(len(ids), len(set(ids)))


class TestReflectedXSSFuzzing(unittest.TestCase):

    def setUp(self):
        self.tpl = load_template_file(_BUNDLED / "vulnerabilities" / "reflected-xss.yaml")

    def test_unescaped_reflection_detected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q") or request.url.params.get("s") or ""
            return httpx.Response(200, text=f"<div>results for {q}</div>")

        findings = _scan(self.tpl, handler)
        self.assertTrue(findings)
        self.assertEqual(findings[0].template_id, "reflected-xss-generic")
        self.assertEqual(findings[0].severity, "high")

    def test_escaped_reflection_not_detected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q") or request.url.params.get("s") or ""
            return httpx.Response(200, text=f"<div>results for {html.escape(q)}</div>")

        findings = _scan(self.tpl, handler)
        self.assertEqual(findings, [])


class TestErrorSQLiFuzzing(unittest.TestCase):

    def setUp(self):
        self.tpl = load_template_file(_BUNDLED / "vulnerabilities" / "error-sqli.yaml")

    def test_sql_error_detected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            ident = request.url.params.get("id", "")
            if "'" in ident or '"' in ident or ")" in ident:
                return httpx.Response(
                    500,
                    text="You have an error in your SQL syntax near MySQL server version",
                )
            return httpx.Response(200, text="ok normal page content")

        findings = _scan(self.tpl, handler)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "critical")

    def test_no_error_no_finding(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="normal page, nothing leaks here at all")

        findings = _scan(self.tpl, handler)
        self.assertEqual(findings, [])


class TestLFIFuzzing(unittest.TestCase):

    def setUp(self):
        self.tpl = load_template_file(_BUNDLED / "vulnerabilities" / "lfi-traversal.yaml")

    def test_passwd_disclosure_detected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            f = request.url.params.get("file") or request.url.params.get("page") or ""
            if "etc/passwd" in f or "passwd" in f:
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
            return httpx.Response(200, text="default page body content here")

        findings = _scan(self.tpl, handler)
        self.assertTrue(findings)
        self.assertEqual(findings[0].template_id, "lfi-path-traversal-generic")


class TestExposureTemplates(unittest.TestCase):

    def test_dotenv_detected(self):
        tpl = load_template_file(_BUNDLED / "exposures" / "dotenv.yaml")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith(".env"):
                return httpx.Response(
                    200,
                    text="APP_KEY=base64:abc==\nDB_PASSWORD=s3cr3t\nDB_HOST=localhost\n",
                )
            return httpx.Response(404, text="nf")

        findings = _scan(tpl, handler)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "high")

    def test_phpinfo_detected(self):
        tpl = load_template_file(_BUNDLED / "exposures" / "phpinfo.yaml")

        def handler(request: httpx.Request) -> httpx.Response:
            if "info" in request.url.path or "phpinfo" in request.url.path:
                return httpx.Response(200, text="<title>phpinfo()</title> PHP Version 8.2.1")
            return httpx.Response(404, text="nf")

        findings = _scan(tpl, handler)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
