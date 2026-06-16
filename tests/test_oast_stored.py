"""Tests for the OAST listener, blind/second-order stored XSS, and the
IDOR+mass-assignment account-takeover correlation."""

import json
import unittest
import urllib.request

from scanner.oast import OASTListener
from scanner import active_checks as ac
from scanner.modules.base import Finding
from scanner.correlate import correlate_findings


class TestOASTListener(unittest.TestCase):
    def test_records_token_hit(self):
        oast = OASTListener().start()
        try:
            token = "abc123"
            self.assertFalse(oast.was_hit(token))
            urllib.request.urlopen(oast.url_for(token), timeout=3).read()
            self.assertTrue(oast.was_hit(token))
            self.assertFalse(oast.was_hit("never"))
        finally:
            oast.stop()


# --- fakes for the blind stored-XSS flow ---
class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class StatefulFake:
    """One backing store; the review POST 'fires the bot' by growing the
    collector log and unlocking the admin inbox."""

    def __init__(self, state):
        self.state = state
        self.follow_redirects = True

    def get(self, url, **kw):
        if "/collector" in url:
            return FakeResp(200, self.state["collector"])
        if "/admin/messages" in url:
            return FakeResp(200, "FLAG{stored_xss_proof}" if self.state["fired"] else "{}")
        if "/product/1" in url and "/review" not in url:
            return FakeResp(200, "<html>product 1, no review shown</html>")
        return FakeResp(404, "not found")

    def post(self, url, data=None, json=None, **kw):
        if "/review" in url:
            self.state["fired"] = True
            self.state["collector"] = (
                '[{"cookie":"lumen_sid=abcdef0123456789abcd",'
                '"source":"admin review-moderation @ product 1"}]'
            )
            return FakeResp(302, "", {"Location": "/product/1"})
        return FakeResp(404, "")


class _Crawl:
    def __init__(self):
        class P:
            url = "http://t.local/product/1"
            body = ""
            content_type = "text/html"
        self.pages = [P()]
        self.forms = []
        self.api_paths = []
        self.targets = []


class TestBlindStoredXSS(unittest.TestCase):
    def test_second_order_confirmed_and_cookie_replayed(self):
        state = {"collector": "[]", "fired": False}
        ctx = ac.ActiveContext(
            base_url="http://t.local",
            crawl=_Crawl(),
            make_client=lambda c: StatefulFake(state),
            primary_cookies={"sid": "j"},
            secondary_cookies={},
            auth=None,
            oast=None,                       # exercise the collector-polling path
            config={"stored_xss_wait": 3},   # one poll after ~2s
        )
        findings = ac.check_stored_xss(ctx)
        self.assertTrue(findings, "blind stored XSS should be detected via collector")
        f = findings[0]
        self.assertIn("Stored", f.vuln_type)
        # The leaked cookie was replayed to the admin inbox and pulled the secret.
        self.assertIn("FLAG{stored_xss_proof}", f.evidence)

    def test_no_finding_when_collector_unchanged(self):
        # Bot never fires -> collector stays "[]" -> no second-order confirmation.
        state = {"collector": "[]", "fired": False}

        class NoFire(StatefulFake):
            def post(self, url, data=None, json=None, **kw):
                return FakeResp(302, "", {"Location": "/product/1"})  # stored, but bot inert

        ctx = ac.ActiveContext(
            base_url="http://t.local", crawl=_Crawl(),
            make_client=lambda c: NoFire(state),
            primary_cookies={"sid": "j"}, secondary_cookies={}, auth=None, oast=None,
            config={"stored_xss_wait": 3},
        )
        self.assertEqual(ac.check_stored_xss(ctx), [])


class TestATOCorrelation(unittest.TestCase):
    def _f(self, vt, url="http://t.com/x", param="p"):
        return Finding(vt, url, "GET", param, "x", "ev", "high")

    def test_idor_plus_mass_assignment_is_account_takeover(self):
        findings = [
            self._f("IDOR / BOLA (Object-Level Authorization)", "http://t.com/api/orders/1"),
            self._f("Mass Assignment / Privilege Escalation", "http://t.com/api/account", "account_tier"),
        ]
        paths = correlate_findings(findings)
        ato = [p for p in paths if "account takeover" in p.name.lower()]
        self.assertTrue(ato)
        self.assertEqual(ato[0].severity, "critical")

    def test_idor_alone_no_ato(self):
        paths = correlate_findings([self._f("IDOR / BOLA", "http://t.com/api/orders/1")])
        self.assertFalse(any("account takeover" in p.name.lower() for p in paths))


if __name__ == "__main__":
    unittest.main()
