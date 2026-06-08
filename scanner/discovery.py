"""Subdomain enumeration, URL/path discovery, and subdomain takeover detection."""

import concurrent.futures
import re
import socket
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Subdomain wordlist  (top ~80 most common)
# ---------------------------------------------------------------------------
_SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "ns1", "ns2", "m", "mobile",
    "api", "api2", "v1", "v2", "rest",
    "dev", "dev2", "staging", "stage", "uat", "pre-prod", "qa", "test", "demo",
    "beta", "alpha", "sandbox",
    "admin", "portal", "secure", "login", "auth", "sso",
    "app", "apps", "app2", "dashboard", "panel", "cp", "cpanel", "whm",
    "blog", "forum", "shop", "store", "cdn", "static", "assets",
    "media", "img", "images", "files", "upload",
    "smtp", "pop", "imap", "webmail", "email",
    "vpn", "vpn2", "remote", "rdp",
    "db", "database", "mysql", "sql", "mongo", "redis",
    "backup", "old", "archive", "new",
    "server", "cloud", "internal", "intranet", "corp", "office",
    "git", "svn", "repo", "code",
    "jenkins", "jira", "wiki", "confluence", "gitlab", "github",
    "grafana", "kibana", "prometheus", "elastic", "search",
    "logs", "monitor", "metrics", "status", "health", "ops",
    "webdisk", "autodiscover",
]

# ---------------------------------------------------------------------------
# URL path wordlist  (top ~130 most hit in real engagements)
# ---------------------------------------------------------------------------
_URL_WORDLIST: List[str] = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/administrator/", "/admin1",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/manager", "/manager/html", "/jmx-console",
    "/cpanel", "/panel", "/dashboard", "/console",
    # Auth
    "/login", "/login.php", "/login.html", "/logout", "/register", "/signup",
    "/forgot-password", "/reset-password", "/account",
    # APIs
    "/api", "/api/v1", "/api/v2", "/api/v1/users", "/api/v2/users",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger-ui.html", "/swagger/index.html",
    "/swagger.json", "/openapi.json", "/api-docs",
    # Actuator / debug
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/httptrace",
    "/debug", "/debug.php", "/trace", "/info.php", "/phpinfo.php", "/test.php",
    "/server-status", "/server-info",
    # Config / secrets
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/settings.php", "/settings.py", "/configuration.php",
    "/wp-config.php", "/web.config", "/app.config",
    "/application.properties", "/application.yml",
    "/.htpasswd", "/.htaccess",
    # Source control leaks
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/store",
    # Backups
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/old", "/old.php", "/bak", "/bak.php",
    # Uploads / files
    "/upload", "/uploads", "/files", "/static", "/assets", "/media",
    "/images", "/img", "/css", "/js",
    # CMS
    "/xmlrpc.php", "/wp-json", "/wp-json/wp/v2/users",
    "/feed", "/rss", "/sitemap.xml", "/sitemap_index.xml",
    # Info
    "/robots.txt", "/crossdomain.xml", "/security.txt",
    "/.well-known/security.txt",
    "/readme", "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/package.json", "/composer.json", "/Gemfile",
    # Common webshell names (detect existing compromises)
    "/shell.php", "/cmd.php", "/exec.php", "/c99.php", "/r57.php",
    "/cgi-bin/", "/cgi-bin/admin.cgi",
    # SOAP / XML
    "/soap", "/wsdl", "/xml",
    # Internal tooling
    "/jenkins", "/sonar", "/nexus", "/artifactory",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/adminer.php",
    # Containers / k8s
    "/api/v1/namespaces", "/metrics", "/healthz", "/readyz",
]

# Status codes that indicate something interesting
_INTERESTING = frozenset((200, 201, 204, 301, 302, 401, 403))

# ---------------------------------------------------------------------------
# Subdomain takeover fingerprints
# (service name, CNAME pattern, HTTP body fingerprint, confidence)
# ---------------------------------------------------------------------------
_TAKEOVER_FINGERPRINTS: List[Dict] = [
    {
        "service": "GitHub Pages",
        "cname_pattern": r"\.github\.io$",
        "body_pattern": r"There isn't a GitHub Pages site here|404 There is no GitHub Pages site",
        "confidence": "high",
    },
    {
        "service": "AWS S3",
        "cname_pattern": r"\.s3\.amazonaws\.com$|\.s3-website[.-]",
        "body_pattern": r"NoSuchBucket|The specified bucket does not exist",
        "confidence": "high",
    },
    {
        "service": "AWS CloudFront",
        "cname_pattern": r"\.cloudfront\.net$",
        "body_pattern": r"Bad request|ERROR: The request could not be satisfied",
        "confidence": "medium",
    },
    {
        "service": "Heroku",
        "cname_pattern": r"\.herokuapp\.com$|\.herokudns\.com$",
        "body_pattern": r"No such app|herokucdn\.com/error-pages/no-such-app",
        "confidence": "high",
    },
    {
        "service": "Netlify",
        "cname_pattern": r"\.netlify\.app$|\.netlify\.com$",
        "body_pattern": r"Not Found - Request ID|netlify",
        "confidence": "medium",
    },
    {
        "service": "Shopify",
        "cname_pattern": r"\.myshopify\.com$",
        "body_pattern": r"Sorry, this shop is currently unavailable|only accessible to authorized users",
        "confidence": "high",
    },
    {
        "service": "Azure / Blob Storage",
        "cname_pattern": r"\.azurewebsites\.net$|\.blob\.core\.windows\.net$|\.cloudapp\.net$",
        "body_pattern": r"404 Web Site not Found|BlobNotFound|The specified container does not exist",
        "confidence": "high",
    },
    {
        "service": "Fastly",
        "cname_pattern": r"\.fastly\.net$",
        "body_pattern": r"Fastly error: unknown domain",
        "confidence": "high",
    },
    {
        "service": "Ghost",
        "cname_pattern": r"\.ghost\.io$",
        "body_pattern": r"The thing you were looking for is no longer here",
        "confidence": "high",
    },
    {
        "service": "Zendesk",
        "cname_pattern": r"\.zendesk\.com$",
        "body_pattern": r"Help Center Closed|this help center no longer exists",
        "confidence": "high",
    },
    {
        "service": "Cargo",
        "cname_pattern": r"\.cargo\.site$",
        "body_pattern": r"404 Not Found",
        "confidence": "low",
    },
    {
        "service": "Webflow",
        "cname_pattern": r"\.webflow\.io$",
        "body_pattern": r"The page you are looking for doesn't exist",
        "confidence": "medium",
    },
]


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------

def _get_cname(fqdn: str) -> Optional[str]:
    """Return the CNAME target for *fqdn*, or None if it's an A/AAAA record."""
    try:
        # getaddrinfo doesn't follow CNAME separately, so use gethostbyname_ex
        # which returns (hostname, aliases, addresses) — aliases contains CNAMEs
        canonical, aliases, _ = socket.gethostbyname_ex(fqdn)
        # If canonical differs from fqdn it resolved through a CNAME chain
        if canonical and canonical.rstrip(".") != fqdn.rstrip("."):
            return canonical.rstrip(".")
        if aliases:
            return aliases[0].rstrip(".")
    except (socket.gaierror, OSError):
        pass
    return None


def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_workers: int = 40,
    timeout: float = 1.5,
) -> List[Tuple[str, str]]:
    """DNS-resolve common subdomain prefixes for *domain*.

    Returns:
        Sorted list of ``(fqdn, ip_address)`` for live subdomains.
    """
    words = wordlist if wordlist is not None else _SUBDOMAIN_WORDLIST

    def _resolve(sub: str) -> Optional[Tuple[str, str]]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except (socket.gaierror, OSError):
            return None

    results: List[Tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(_resolve, w): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit is not None:
                results.append(hit)

    results.sort(key=lambda r: r[0])
    return results


def check_subdomain_takeover(
    fqdn: str,
    http_client=None,
) -> Optional[Dict]:
    """Check if *fqdn* is vulnerable to subdomain takeover.

    Strategy:
      1. Resolve the CNAME chain — if the target is a known cloud service CNAME,
         check the HTTP response body for service-specific "unclaimed" fingerprints.
      2. If the CNAME matches a known-takeable service AND the body contains the
         unclaimed-site error message → subdomain takeover confirmed.

    Returns:
        A dict with keys (fqdn, cname, service, confidence, evidence) or None.
    """
    cname = _get_cname(fqdn)
    if not cname:
        return None

    # Match CNAME against known takeable services
    matched_fp = None
    for fp in _TAKEOVER_FINGERPRINTS:
        if re.search(fp["cname_pattern"], cname, re.IGNORECASE):
            matched_fp = fp
            break

    if not matched_fp:
        return None

    # Fetch the subdomain's HTTP response and check for unclaimed fingerprint
    if http_client is None:
        return None

    try:
        resp = http_client.get(f"http://{fqdn}")
        if resp is None:
            resp = http_client.get(f"https://{fqdn}")
    except Exception:
        return None

    if resp is None:
        return None

    if re.search(matched_fp["body_pattern"], resp.text, re.IGNORECASE):
        return {
            "fqdn": fqdn,
            "cname": cname,
            "service": matched_fp["service"],
            "confidence": matched_fp["confidence"],
            "evidence": (
                f"CNAME → {cname} ({matched_fp['service']}) "
                f"returns unclaimed-service response"
            ),
        }

    return None


# ---------------------------------------------------------------------------
# URL path discovery
# ---------------------------------------------------------------------------

def discover_paths(
    base_url: str,
    http_client,
    wordlist: Optional[List[str]] = None,
    max_workers: int = 12,
) -> List[Dict]:
    """Probe *wordlist* paths against *base_url* via HEAD/GET.

    Returns:
        List of dicts ``{path, url, status, size}`` for interesting responses,
        sorted by status code.
    """
    paths = wordlist if wordlist is not None else _URL_WORDLIST
    base = base_url.rstrip("/")
    results: List[Dict] = []

    def _probe(path: str) -> Optional[Dict]:
        url = base + path
        try:
            resp = http_client.get(url)
            if resp is not None and resp.status_code in _INTERESTING:
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.text),
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = [exe.submit(_probe, p) for p in paths]
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit is not None:
                results.append(hit)

    results.sort(key=lambda r: r["status"])
    return results
