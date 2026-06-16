"""Unit tests for the orchestrated, session-aware checks (active_checks.py).

Each check is exercised with a fake crawl surface and fake HTTP clients so no
network is required. The goal is to lock in the *detection oracle* of each one:
  - auth bypass  -> login succeeds (302 + cookie) where wrong creds don't
  - broken access -> 200 + sensitive body for an anonymous admin request
  - mass assignment -> a privileged field sent by the client sticks
  - stored XSS   -> a canary posted in one place renders unencoded elsewhere
  - csrf         -> state-changing form, no token, cookie not SameSite=Strict
"""

import json
import unittest
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from scanner import active_checks as ac


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------
class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class FakeClient:
    """Configurable client: pass handlers for get / post / _request (PUT)."""

    def __init__(self, get=None, post=None, request=None):
        self.follow_redirects = True
        self._get, self._post, self._req = get, post, request

    def get(self, url, **kw):
        return self._get(url, **kw) if self._get else None

    def post(self, url, data=None, json=None, **kw):
        return self._post(url, data=data, json=json, **kw) if self._post else None

    def _request(self, method, url, **kw):
        return self._req(method, url, **kw) if self._req else None


@dataclass
class FakeForm:
    action: str
    method: str
    fields: Dict[str, str]
    field_types: Dict[str, str] = field(default_factory=dict)
    has_csrf_token: bool = False
    source_url: str = ""


@dataclass
class FakePage:
    url: str
    body: str = ""
    content_type: str = "text/html"


@dataclass
class FakeCrawl:
    forms: List[FakeForm] = field(default_factory=list)
    pages: List[FakePage] = field(default_factory=list)
    api_paths: List[str] = field(default_factory=list)
    targets: List[Dict] = field(default_factory=list)


def _ctx(crawl, make_client, primary=None, auth=None):
    return ac.ActiveContext(
        base_url="http://t.local",
        crawl=crawl,
        make_client=make_client,
        primary_cookies=primary or {},
        secondary_cookies={},
        auth=auth,
        config={},
    )


# --------------------------------------------------------------------------
# 1. Auth bypass
# --------------------------------------------------------------------------
class TestAuthBypass(unittest.TestCase):
    def test_comment_only_bypass_detected(self):
        login = FakeForm(
            action="http://t.local/login", method="POST",
            fields={"username": "", "password": ""},
            field_types={"username": "text", "password": "password"},
            source_url="http://t.local/login",
        )

        def post(url, data=None, json=None, **kw):
            u = (data or {}).get("username", "")
            # Comment-only injection logs in; everything else fails (WAF/normal).
            if u.startswith("admin'") and ("--" in u or "#" in u):
                return FakeResp(302, "", {"Location": "/", "Set-Cookie": "sid=abc; Path=/"})
            return FakeResp(200, "Invalid characters")  # WAF-style block / failed login

        ctx = _ctx(FakeCrawl(forms=[login]), lambda c: FakeClient(post=post))
        findings = ac.check_auth_bypass(ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("Authentication Bypass", findings[0].vuln_type)
        self.assertEqual(findings[0].parameter, "username")

    def test_no_bypass_when_login_never_succeeds(self):
        login = FakeForm(
            action="http://t.local/login", method="POST",
            fields={"username": "", "password": ""},
            field_types={"username": "text", "password": "password"},
            source_url="http://t.local/login",
        )
        post = lambda url, data=None, json=None, **kw: FakeResp(200, "Invalid credentials")
        ctx = _ctx(FakeCrawl(forms=[login]), lambda c: FakeClient(post=post))
        self.assertEqual(ac.check_auth_bypass(ctx), [])


# --------------------------------------------------------------------------
# 2. Broken access control
# --------------------------------------------------------------------------
class TestBrokenAccess(unittest.TestCase):
    def test_unauth_admin_page_flagged(self):
        def get(url, **kw):
            if url.endswith("/admin/orders"):
                return FakeResp(200, "Order #1 customer email total admin_note " * 5)
            if url == "http://t.local":
                return FakeResp(200, "home page")
            return FakeResp(401, "unauthorized")

        ctx = _ctx(FakeCrawl(pages=[FakePage("http://t.local/")]),
                   lambda c: FakeClient(get=get))
        findings = ac.check_broken_access(ctx)
        self.assertTrue(any("Broken Access" in f.vuln_type and "admin/orders" in f.url
                            for f in findings))

    def test_protected_redirect_not_flagged(self):
        # /admin/settings 302 -> /login. With follow_redirects disabled the check
        # sees a 302 (not a 200), so it must NOT be flagged as accessible.
        def get(url, **kw):
            return FakeResp(302, "", {"Location": "/login"}) if "admin" in url \
                else FakeResp(200, "home")
        ctx = _ctx(FakeCrawl(pages=[]), lambda c: FakeClient(get=get))
        self.assertEqual(ac.check_broken_access(ctx), [])


# --------------------------------------------------------------------------
# 3. Mass assignment
# --------------------------------------------------------------------------
class TestMassAssignment(unittest.TestCase):
    def test_privileged_field_sticks(self):
        state = {"username": "j", "account_tier": "standard", "store_credit": 0}

        def get(url, **kw):
            return FakeResp(200, json.dumps(state), {"Content-Type": "application/json"})

        def req(method, url, **kw):
            if method == "PUT":
                body = kw.get("json") or {}
                # Server naively binds whatever it receives (the bug).
                state.update(body)
                return FakeResp(200, json.dumps(state), {"Content-Type": "application/json"})
            return FakeResp(404, "")

        ctx = _ctx(FakeCrawl(api_paths=["/api/account"]),
                   lambda c: FakeClient(get=get, request=req), primary={"sid": "x"})
        findings = ac.check_mass_assignment(ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("Mass Assignment", findings[0].vuln_type)
        self.assertIn("account_tier", findings[0].parameter)

    def test_rejected_fields_no_finding(self):
        state = {"username": "j", "account_tier": "standard"}
        get = lambda url, **kw: FakeResp(200, json.dumps(state), {"Content-Type": "application/json"})
        # Server ignores extra keys -> state never changes.
        req = lambda method, url, **kw: FakeResp(200, json.dumps(state), {"Content-Type": "application/json"})
        ctx = _ctx(FakeCrawl(api_paths=["/api/account"]),
                   lambda c: FakeClient(get=get, request=req), primary={"sid": "x"})
        self.assertEqual(ac.check_mass_assignment(ctx), [])


# --------------------------------------------------------------------------
# 4. Stored / second-order XSS
# --------------------------------------------------------------------------
class TestStoredXSS(unittest.TestCase):
    def test_canary_rendered_unencoded_elsewhere(self):
        review = FakeForm(
            action="http://t.local/product/1/review", method="POST",
            fields={"rating": "5", "body": ""},
            field_types={"rating": "text", "body": "textarea"},
            source_url="http://t.local/product/1",
        )
        store = {"last": ""}

        def post(url, data=None, json=None, **kw):
            store["last"] = (data or {}).get("body", "")
            return FakeResp(302, "", {"Location": "/product/1"})

        def get(url, **kw):
            # The product page renders the stored review body verbatim.
            return FakeResp(200, f"<div class=review>{store['last']}</div>")

        ctx = _ctx(FakeCrawl(forms=[review], pages=[FakePage("http://t.local/product/1")]),
                   lambda c: FakeClient(get=get, post=post), primary={"sid": "x"})
        findings = ac.check_stored_xss(ctx)
        self.assertTrue(any("Stored" in f.vuln_type for f in findings))

    def test_encoded_output_no_finding(self):
        review = FakeForm(
            action="http://t.local/product/1/review", method="POST",
            fields={"rating": "5", "body": ""},
            field_types={"rating": "text", "body": "textarea"},
            source_url="http://t.local/product/1",
        )
        store = {"last": ""}

        def post(url, data=None, json=None, **kw):
            store["last"] = (data or {}).get("body", "")
            return FakeResp(302, "", {"Location": "/product/1"})

        def get(url, **kw):
            safe = store["last"].replace("<", "&lt;").replace(">", "&gt;")
            return FakeResp(200, f"<div>{safe}</div>")

        ctx = _ctx(FakeCrawl(forms=[review], pages=[FakePage("http://t.local/product/1")]),
                   lambda c: FakeClient(get=get, post=post), primary={"sid": "x"})
        self.assertEqual(ac.check_stored_xss(ctx), [])


# --------------------------------------------------------------------------
# 5. CSRF
# --------------------------------------------------------------------------
class TestCSRF(unittest.TestCase):
    class _Auth:
        cookie_samesite = "lax"

    def test_state_changing_no_token_flagged(self):
        form = FakeForm(
            action="http://t.local/api/account/email", method="POST",
            fields={"email": ""}, has_csrf_token=False,
        )
        ctx = _ctx(FakeCrawl(forms=[form]), lambda c: FakeClient(), auth=self._Auth())
        findings = ac.check_csrf(ctx)
        self.assertTrue(any("CSRF" in f.vuln_type for f in findings))

    def test_samesite_strict_not_flagged(self):
        class StrictAuth:
            cookie_samesite = "strict"
        form = FakeForm(
            action="http://t.local/api/account/email", method="POST",
            fields={"email": ""}, has_csrf_token=False,
        )
        ctx = _ctx(FakeCrawl(forms=[form]), lambda c: FakeClient(), auth=StrictAuth())
        self.assertEqual(ac.check_csrf(ctx), [])


if __name__ == "__main__":
    unittest.main()
