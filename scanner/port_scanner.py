"""Fast TCP port scanner with banner grabbing for recon phase."""

import concurrent.futures
import socket
from typing import Dict, List, Optional, Tuple


# Common web-adjacent ports: (port, service_name)
_COMMON_PORTS: List[Tuple[int, str]] = [
    (21,    "FTP"),
    (22,    "SSH"),
    (23,    "Telnet"),
    (25,    "SMTP"),
    (53,    "DNS"),
    (80,    "HTTP"),
    (110,   "POP3"),
    (143,   "IMAP"),
    (443,   "HTTPS"),
    (445,   "SMB"),
    (1433,  "MSSQL"),
    (3306,  "MySQL"),
    (3389,  "RDP"),
    (5432,  "PostgreSQL"),
    (5900,  "VNC"),
    (6379,  "Redis"),
    (8080,  "HTTP-Alt"),
    (8443,  "HTTPS-Alt"),
    (8888,  "HTTP-Alt"),
    (9000,  "PHP-FPM/SonarQube"),
    (9200,  "Elasticsearch"),
    (9300,  "Elasticsearch"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
    (2181,  "Zookeeper"),
    (4848,  "GlassFish"),
    (8500,  "Consul"),
    (10250, "Kubelet"),
    (6443,  "Kubernetes-API"),
    (2375,  "Docker-TCP"),
    (2376,  "Docker-TLS"),
]

_PORT_MAP: Dict[int, str] = dict(_COMMON_PORTS)


def _probe(host: str, port: int, timeout: float) -> Optional[Dict]:
    """Attempt TCP connect; return dict with port/service/banner or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(0.3)
                raw = sock.recv(256)
                banner = raw.decode("ascii", errors="replace").strip()[:120]
            except (socket.timeout, OSError):
                pass
            return {
                "port": port,
                "service": _PORT_MAP.get(port, "unknown"),
                "banner": banner,
                "state": "open",
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(
    host: str,
    ports: Optional[List[int]] = None,
    max_workers: int = 60,
    timeout: float = 0.7,
) -> List[Dict]:
    """Scan *host* for open TCP ports.

    Args:
        host:        IP address or hostname to scan.
        ports:       List of ports to probe.  Defaults to common web ports.
        max_workers: Thread pool size (more = faster, noisier).
        timeout:     Per-port connect timeout in seconds.

    Returns:
        List of dicts ``{port, service, banner, state}`` sorted by port number.
    """
    port_list = ports if ports is not None else [p for p, _ in _COMMON_PORTS]

    results: List[Dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(_probe, host, p, timeout): p for p in port_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results
