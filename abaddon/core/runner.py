"""Scanner orchestration — bind engine + templates + matchers + correlation.

For each template request and path the runner:
  1. interpolates ``{{BaseURL}}``, ``{{oast}}``, ``{{marker}}`` variables,
  2. allocates an OAST handle / reflection marker when the check needs one,
  3. dispatches the probe (repeating for time-based checks and taking the median),
  4. builds a :class:`MatchContext` against an optional baseline,
  5. asks the :class:`CorrelationEngine` whether the aggregate evidence confirms
     a finding.
"""

import asyncio
import secrets
import statistics
from typing import Dict, List, Optional
from urllib.parse import urljoin

from ..models.schemas import RequestSpec, Template
from ..network.engine import AsyncEngine, Probe, ProbeResult
from .correlation import CorrelationEngine, Finding
from .matchers import MatchContext
from .oast import OASTProvider
from ..models.schemas import OASTMatcher, ReflectionMatcher


def _interpolate(text: str, variables: Dict[str, str]) -> str:
    for key, value in variables.items():
        text = text.replace("{{" + key + "}}", value)
    return text


class Scanner:
    """Drive a set of validated templates against a base target."""

    def __init__(
        self,
        engine: AsyncEngine,
        templates: List[Template],
        oast: Optional[OASTProvider] = None,
        use_baseline: bool = True,
    ) -> None:
        self.engine = engine
        self.templates = templates
        self.oast = oast
        self.use_baseline = use_baseline
        self.correlation = CorrelationEngine()

    async def scan(self, base_url: str) -> List[Finding]:
        baseline = None
        if self.use_baseline:
            baseline = await self.engine.send(Probe(url=base_url))

        findings: List[Finding] = []
        for template in self.templates:
            for request in template.requests:
                for path in request.path:
                    finding = await self._run_request(
                        base_url, template, request, path, baseline
                    )
                    if finding is not None:
                        findings.append(finding)
        return findings

    async def _run_request(
        self,
        base_url: str,
        template: Template,
        request: RequestSpec,
        path: str,
        baseline: Optional[ProbeResult],
    ) -> Optional[Finding]:
        # Decide which dynamic variables this request needs.
        needs_oast = any(isinstance(m, OASTMatcher) for m in request.matchers) or any(
            "{{oast}}" in s for s in self._request_strings(request, path)
        )
        needs_marker = any(
            isinstance(m, ReflectionMatcher) for m in request.matchers
        ) or any("{{marker}}" in s for s in self._request_strings(request, path))

        # One iteration per payload (or a single un-fuzzed iteration).
        payloads: List[Optional[str]] = list(request.payloads) or [None]
        for payload in payloads:
            finding = await self._run_one(
                base_url, template, request, path, baseline,
                payload, needs_oast, needs_marker,
            )
            if finding is not None:
                return finding
        return None

    async def _run_one(
        self,
        base_url: str,
        template: Template,
        request: RequestSpec,
        path: str,
        baseline: Optional[ProbeResult],
        payload: Optional[str],
        needs_oast: bool,
        needs_marker: bool,
    ) -> Optional[Finding]:
        handle = self.oast.new_handle() if (needs_oast and self.oast) else None

        # For reflection fuzzing the payload itself is the marker; otherwise use a
        # random canary so {{marker}} interpolation produces a detectable token.
        if needs_marker:
            marker = payload if payload is not None else "abdz" + secrets.token_hex(4)
        else:
            marker = None

        variables = {"BaseURL": base_url.rstrip("/")}
        if handle:
            variables["oast"] = handle.payload
        if marker:
            variables["marker"] = marker
        if payload is not None:
            variables["payload"] = payload

        url = urljoin(base_url, _interpolate(path, variables))
        headers = {k: _interpolate(v, variables) for k, v in request.headers.items()}
        body = _interpolate(request.body, variables) if request.body else None

        probe = Probe(
            url=url,
            method=request.method,
            headers=headers or None,
            data=body,
            meta={"template": template.id, "payload": payload},
        )

        # Repeat for time-based checks → median elapsed.
        elapseds: List[float] = []
        result: Optional[ProbeResult] = None
        for _ in range(request.repeat):
            result = await self.engine.send(probe)
            elapseds.append(result.elapsed)
        if result is None or (result.error and result.status_code is None):
            return None

        median_elapsed = statistics.median(elapseds) if elapseds else result.elapsed

        ctx = MatchContext(
            body=result.text,
            headers=result.headers,
            status_code=result.status_code,
            elapsed=median_elapsed,
            baseline_body=baseline.text if baseline else "",
            baseline_elapsed=baseline.elapsed if baseline else 0.0,
            baseline_status=baseline.status_code if baseline else None,
            oast=self.oast,
            oast_correlation_id=handle.correlation_id if handle else None,
            reflection_marker=marker,
        )

        return self.correlation.evaluate_request(template, request, ctx, url)

    @staticmethod
    def _request_strings(request: RequestSpec, path: str) -> List[str]:
        parts = [path, request.body or ""]
        parts.extend(request.headers.values())
        return parts
