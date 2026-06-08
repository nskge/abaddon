"""Subdomain enumeration and URL/path discovery via DNS + HTTP probing."""

import concurrent.futures
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
# Subdomain enumeration
# ---------------------------------------------------------------------------

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
