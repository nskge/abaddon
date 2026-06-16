"""End-to-end test: template + engine + matchers + correlation via the runner."""

import asyncio
import unittest
from pathlib import Path

import httpx

from abaddon.core.oast import MockOASTProvider
from abaddon.core.runner import Scanner
from abaddon.models.schemas import Template
from abaddon.network.engine import AsyncEngine
from abaddon.parsers.template_engine import load_template_file

_TEST_TEMPLATE = Path(__file__).parent / "test_abaddon.yaml"

_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tbare = false\n"
    '[remote "origin"]\n'
    "\turl = git@github.com:acme/secret-app.git\n"
)


def _target_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/.git/config":
        return httpx.Response(200, text=_GIT_CONFIG)
    return httpx.Response(404, text="Not Found")


class TestEndToEnd(unittest.TestCase):

    def test_git_exposure_detected(self):
        tpl = load_template_file(_TEST_TEMPLATE)
        transport = httpx.MockTransport(_target_handler)

        async def go():
            async with AsyncEngine(transport=transport) as engine:
                scanner = Scanner(engine, [tpl], use_baseline=True)
                return await scanner.scan("http://target.local")

        findings = asyncio.run(go())
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.template_id, "git-dir-exposed")
        self.assertEqual(f.severity, "medium")
        # status(0.4) + word(0.6) via noisy-or = 0.76 >= 0.6
        self.assertGreaterEqual(f.confidence, 0.6)

    def test_clean_target_no_finding(self):
        tpl = load_template_file(_TEST_TEMPLATE)

        def clean_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(clean_handler)

        async def go():
            async with AsyncEngine(transport=transport) as engine:
                scanner = Scanner(engine, [tpl], use_baseline=True)
                return await scanner.scan("http://target.local")

        findings = asyncio.run(go())
        self.assertEqual(findings, [])

    def test_oast_blind_template_end_to_end(self):
        """Template using {{oast}} + oast matcher confirms via injected callback."""
        oast = MockOASTProvider(base_domain="oast.test")

        # Capture the oast payload the runner injects, then trigger a callback.
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            # Simulate the target performing an out-of-band lookup:
            # find the active correlation id and trigger it.
            for cid in list(oast._interactions.keys()) or []:
                oast.trigger(cid, protocol="dns")
            # Trigger whatever handle exists by scanning payload in query.
            return httpx.Response(200, text="queued")

        # Build a template inline that injects {{oast}} and matches on oast.
        tpl = Template.model_validate(
            {
                "id": "blind-ssrf-oast",
                "info": {"name": "Blind SSRF via OAST", "severity": "high"},
                "confidence_threshold": 0.6,
                "requests": [
                    {
                        "method": "GET",
                        "path": ["/fetch?url=http://{{oast}}/x"],
                        "matchers": [{"type": "oast", "protocols": ["dns", "http"]}],
                    }
                ],
            }
        )

        # We need the callback to fire for the *allocated* handle. Patch new_handle
        # to register the id up-front so the handler can trigger it.
        original_new_handle = oast.new_handle

        def tracking_new_handle():
            h = original_new_handle()
            oast._interactions.setdefault(h.correlation_id, [])
            return h

        oast.new_handle = tracking_new_handle  # type: ignore[assignment]

        transport = httpx.MockTransport(handler)

        async def go():
            async with AsyncEngine(transport=transport) as engine:
                scanner = Scanner(engine, [tpl], oast=oast, use_baseline=False)
                return await scanner.scan("http://target.local")

        findings = asyncio.run(go())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].template_id, "blind-ssrf-oast")
        self.assertIn("oast.test", captured["url"])


if __name__ == "__main__":
    unittest.main()
