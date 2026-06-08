"""GraphQL introspection and misconfiguration detection module.

Checks for:
  1. Introspection enabled -- the __schema query returns type definitions,
     exposing the full API surface (mutations, queries, types, arguments).
  2. Batch query support -- arrays of operations accepted (DoS / auth bypass risk).
  3. Field suggestions -- even with introspection disabled, some servers leak
     field names via "Did you mean X?" error messages.
  4. Debug/IDE endpoints -- GraphiQL, Playground, Altair exposed to unauthenticated
     users.
"""

import json
import re
from typing import Dict, List, Optional
import logging

from .base import BaseModule, Finding
from ..http_client import HTTPClient

logger = logging.getLogger("vulnscanner")

# ---------------------------------------------------------------------------
# Known GraphQL endpoint paths (ordered by frequency in real apps)
# ---------------------------------------------------------------------------
_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/graphql/api",
    "/query",
    "/api/query",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/api/gql",
]

# Standard introspection query (minimal — just enough to confirm it works)
_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}types{name kind}}}"}'

# Batch introspection (array wrapping the same query)
_BATCH_QUERY = '[{"query":"{__schema{queryType{name}}}"}, {"query":"{__typename}"}]'

# Field suggestion probe — intentional typo to trigger "Did you mean …?"
_SUGGESTION_QUERY = '{"query":"{__typenme}"}'

# GraphiQL / IDE fingerprints in HTML responses
_IDE_FINGERPRINTS = [
    "graphiql",
    "GraphQL Playground",
    "Apollo Studio",
    "altair",
    "graphql-playground",
]


class GraphQLScanner(BaseModule):
    """Detects GraphQL introspection, batch queries, and debug endpoints."""

    NAME = "graphql"

    def __init__(self, http_client: HTTPClient, config: Dict) -> None:
        super().__init__(http_client, config)
        self._scanned_base: Optional[str] = None

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        """GraphQL scan runs once per base URL, not per-parameter."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        if self._scanned_base == base:
            return []
        self._scanned_base = base

        findings: List[Finding] = []
        seen_types: set = set()  # deduplicate by vuln_type across all probed paths

        for path in _GRAPHQL_PATHS:
            endpoint = base + path
            hits = self._probe_endpoint(endpoint)
            for hit in hits:
                if hit.vuln_type not in seen_types:
                    seen_types.add(hit.vuln_type)
                    findings.append(hit)
                    logger.debug("[GraphQL] %s at %s", hit.vuln_type, endpoint)

        return findings

    # ------------------------------------------------------------------
    # Per-endpoint probing
    # ------------------------------------------------------------------

    def _probe_endpoint(self, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []

        # Quick reachability check (GET — GraphiQL IDE usually responds here)
        get_resp = self.http.get(endpoint)
        if get_resp is None:
            return []

        # Check for IDE exposure
        ide_finding = self._check_ide(endpoint, get_resp)
        if ide_finding:
            findings.append(ide_finding)

        # POST introspection query
        headers = {"Content-Type": "application/json"}
        intr_resp = self.http.post(endpoint, data=_INTROSPECTION_QUERY, headers=headers)
        if intr_resp is None:
            return findings

        intr_finding = self._check_introspection(endpoint, intr_resp)
        if intr_finding:
            findings.append(intr_finding)

        # Only probe batch + suggestions if the endpoint is genuinely GraphQL
        if intr_finding or ide_finding or self._looks_like_graphql(intr_resp):
            batch_resp = self.http.post(endpoint, data=_BATCH_QUERY, headers=headers)
            if batch_resp is not None:
                batch_finding = self._check_batch(endpoint, batch_resp)
                if batch_finding:
                    findings.append(batch_finding)

            sug_resp = self.http.post(endpoint, data=_SUGGESTION_QUERY, headers=headers)
            if sug_resp is not None:
                sug_finding = self._check_suggestions(endpoint, sug_resp)
                if sug_finding:
                    findings.append(sug_finding)

        return findings

    # ------------------------------------------------------------------
    # Check helpers
    # ------------------------------------------------------------------

    def _check_introspection(self, endpoint: str, resp) -> Optional[Finding]:
        """Return a Finding if the introspection query exposed schema data."""
        if resp.status_code not in (200, 201):
            return None
        try:
            data = resp.json()
        except Exception:
            return None

        # Must have data.__schema with at least queryType or types
        schema = (data.get("data") or {}).get("__schema") or {}
        if not schema:
            # Handle list response (relay / some servers wrap in list)
            if isinstance(data, list):
                schema = (data[0].get("data") or {}).get("__schema") or {}
            if not schema:
                return None

        types = schema.get("types") or []
        query_type = (schema.get("queryType") or {}).get("name", "")
        n_types = len(types)

        logger.debug("[GraphQL] Introspection open: %s  types=%d", endpoint, n_types)
        return Finding(
            vuln_type="GraphQL Introspection Enabled",
            url=endpoint,
            method="POST",
            parameter="(GraphQL query)",
            payload=_INTROSPECTION_QUERY,
            evidence=(
                f"Introspection returned {n_types} types. "
                f"Root query type: {query_type!r}. "
                "Full API schema is publicly accessible."
            ),
            confidence="high",
            details=(
                "GraphQL introspection is enabled and unauthenticated. "
                f"The schema exposes {n_types} types including mutations, "
                "queries, and all their arguments — a roadmap for further attacks. "
                "Remediation: disable introspection in production "
                "(Apollo: introspection: false; graphene: introspection=False)."
            ),
            reproduction=(
                f"# 1. Confirm introspection is open:\n"
                f"$ curl -s -k -X POST '{endpoint}' \\\n"
                f"    -H 'Content-Type: application/json' \\\n"
                f"    -d '{_INTROSPECTION_QUERY}' | python -m json.tool\n"
                f"# 2. Look for '__schema' → 'types' in the response.\n"
                f"# 3. Dump the full schema for recon:\n"
                f"$ # Use a full introspection query or InQL/graphql-cop for automation\n"
                f"$ pip install graphql-cop && graphql-cop -t {endpoint}"
            ),
        )

    def _check_ide(self, endpoint: str, resp) -> Optional[Finding]:
        """Return a Finding if a GraphQL IDE is accessible."""
        if resp.status_code not in (200, 201):
            return None
        body_lower = resp.text.lower()
        matched = None
        for fp in _IDE_FINGERPRINTS:
            if fp.lower() in body_lower:
                matched = fp
                break
        if not matched:
            return None

        logger.debug("[GraphQL] IDE exposed: %s (%s)", endpoint, matched)
        return Finding(
            vuln_type="GraphQL IDE Exposed",
            url=endpoint,
            method="GET",
            parameter="(HTTP response body)",
            payload="N/A",
            evidence=f"GraphQL IDE fingerprint detected: {matched!r}",
            confidence="medium",
            details=(
                f"A GraphQL IDE ({matched}) is accessible without authentication. "
                "IDEs allow anyone to explore the schema, craft arbitrary queries, "
                "and execute mutations interactively. "
                "Remediation: restrict IDE access to local/dev environments; "
                "remove or auth-gate in production."
            ),
            reproduction=(
                f"# 1. Open in a browser or check for the IDE:\n"
                f"$ curl -s -k '{endpoint}' | grep -i 'graphiql\\|playground'\n"
                f"# 2. If the IDE loads, you can explore the schema visually.\n"
                f"# 3. Test mutations and queries interactively."
            ),
        )

    def _check_batch(self, endpoint: str, resp) -> Optional[Finding]:
        """Return a Finding if the server processes batched query arrays."""
        if resp.status_code not in (200, 201):
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        # Server accepted batch if it returned an array with multiple results
        if not isinstance(data, list) or len(data) < 2:
            return None

        logger.debug("[GraphQL] Batch queries accepted: %s", endpoint)
        return Finding(
            vuln_type="GraphQL Batch Queries Enabled",
            url=endpoint,
            method="POST",
            parameter="(GraphQL batch array)",
            payload=_BATCH_QUERY,
            evidence=f"Server returned {len(data)} results for a batched array request.",
            confidence="medium",
            details=(
                "The GraphQL endpoint accepts batched query arrays. "
                "Batching can be abused to amplify brute-force attacks "
                "(e.g. testing thousands of passwords in a single HTTP request), "
                "bypass rate-limiting (counted as 1 request), and trigger DoS. "
                "Remediation: disable batching or enforce per-batch query limits."
            ),
            reproduction=(
                f"# 1. Send a batched request and check for array response:\n"
                f"$ curl -s -k -X POST '{endpoint}' \\\n"
                f"    -H 'Content-Type: application/json' \\\n"
                f"    -d '[{{\"query\":\"{{__typename}}\"}},{{\"query\":\"{{__typename}}\"}}]'\n"
                f"# 2. If the response is a JSON array with 2+ results, batching is enabled.\n"
                f"# 3. Abuse: send 100 login mutations in one request to bypass rate-limiting."
            ),
        )

    def _check_suggestions(self, endpoint: str, resp) -> Optional[Finding]:
        """Return a Finding if field suggestions leak schema information."""
        if resp.status_code not in (200, 400, 422):
            return None
        try:
            data = resp.json()
        except Exception:
            return None

        errors = data.get("errors") or (data[0].get("errors") if isinstance(data, list) else []) or []
        for err in errors:
            msg = (err.get("message") or "").lower()
            if "did you mean" in msg:
                suggestion_match = re.search(r"did you mean[^?]*\?['\"]?\s*([^'\"?]+)", msg, re.IGNORECASE)
                suggested = suggestion_match.group(1).strip() if suggestion_match else "(see message)"
                logger.debug("[GraphQL] Field suggestions leaking: %s", endpoint)
                return Finding(
                    vuln_type="GraphQL Field Suggestion Leak",
                    url=endpoint,
                    method="POST",
                    parameter="(GraphQL error message)",
                    payload=_SUGGESTION_QUERY,
                    evidence=f"Server suggests field names in error: {err.get('message', '')!r}",
                    confidence="low",
                    details=(
                        "GraphQL server leaks valid field names via 'Did you mean X?' "
                        "error messages even with introspection disabled. "
                        "An attacker can enumerate the schema by typo-scanning field names. "
                        "Remediation: disable field suggestions "
                        "(Apollo: apollo-server >=3 has this off by default; "
                        "set apollo.nodeEnv=production)."
                    ),
                    reproduction=(
                        f"$ curl -s -k -X POST '{endpoint}' \\\n"
                        f"    -H 'Content-Type: application/json' \\\n"
                        f"    -d '{_SUGGESTION_QUERY}'\n"
                        f"# Look for 'Did you mean' in the errors array."
                    ),
                )
        return None

    @staticmethod
    def _looks_like_graphql(resp) -> bool:
        """Heuristic: does the response look like a GraphQL server?"""
        if resp.status_code not in (200, 400, 422):
            return False
        ct = resp.headers.get("Content-Type", "")
        if "application/json" not in ct and "application/graphql" not in ct:
            return False
        try:
            data = resp.json()
        except Exception:
            return False
        # Typical GraphQL error response has {"errors": [...]}
        return isinstance(data, dict) and ("data" in data or "errors" in data)
