"""
Scanner Module: Port & Service Reconnaissance
Scans common ports for exposed services that shouldn't be public.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


# (port, service_name, severity, description)
COMMON_PORTS = [
    (21,   "FTP",            "high",     "FTP transfers credentials in plaintext"),
    (22,   "SSH",            "medium",   "SSH open to public internet"),
    (23,   "Telnet",         "critical", "Telnet transmits data in plaintext"),
    (25,   "SMTP",           "medium",   "SMTP port accessible"),
    (80,   "HTTP",           "info",     "HTTP port open"),
    (443,  "HTTPS",          "info",     "HTTPS port open"),
    (445,  "SMB",            "critical", "SMB port accessible — high risk (WannaCry, EternalBlue)"),
    (1433, "MSSQL",          "critical", "Microsoft SQL Server exposed to internet"),
    (1521, "Oracle DB",      "critical", "Oracle Database exposed to internet"),
    (2375, "Docker API",     "critical", "Docker daemon API exposed without TLS"),
    (2376, "Docker API TLS", "high",     "Docker daemon API exposed (TLS)"),
    (3000, "Node/Rails Dev", "medium",   "Development server port accessible"),
    (3306, "MySQL",          "critical", "MySQL database exposed to internet"),
    (3389, "RDP",            "critical", "Remote Desktop accessible — prime attack vector"),
    (4200, "Angular Dev",    "low",      "Development server port accessible"),
    (5000, "Flask Dev",      "medium",   "Flask development server accessible"),
    (5432, "PostgreSQL",     "critical", "PostgreSQL database exposed to internet"),
    (5601, "Kibana",         "high",     "Kibana dashboard accessible"),
    (5900, "VNC",            "critical", "VNC remote desktop exposed"),
    (6379, "Redis",          "critical", "Redis database exposed — often no auth by default"),
    (7474, "Neo4j",          "high",     "Neo4j graph database accessible"),
    (8080, "Alt HTTP",       "medium",   "Alternative HTTP port accessible"),
    (8443, "Alt HTTPS",      "medium",   "Alternative HTTPS port accessible"),
    (8888, "Jupyter",        "critical", "Jupyter Notebook accessible — often no auth"),
    (9000, "PHP-FPM/SonarQ", "high",     "Service port accessible"),
    (9200, "Elasticsearch",  "critical", "Elasticsearch exposed — often no auth by default"),
    (9300, "Elasticsearch",  "critical", "Elasticsearch cluster port exposed"),
    (27017,"MongoDB",        "critical", "MongoDB exposed — often no auth by default"),
    (27018,"MongoDB",        "critical", "MongoDB exposed"),
]


def probe_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int) -> str:
    """Attempt to grab service banner for evidence."""
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.sendall(b"\r\n")
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            return banner[:150] if banner else ""
    except Exception:
        return ""


def check_ports(url: str) -> dict:
    findings = []
    open_ports = []

    hostname = urlparse(url).hostname
    if not hostname:
        return {"findings": [], "open_ports": []}

    try:
        host_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"findings": [], "open_ports": [], "error": "Could not resolve hostname"}

    # Scan ports concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_map = {
            executor.submit(probe_port, host_ip, port): (port, service, sev, desc)
            for port, service, sev, desc in COMMON_PORTS
        }

        for future in as_completed(future_map):
            port, service, severity, description = future_map[future]
            if future.result():
                open_ports.append({"port": port, "service": service})

                # Skip expected ports from becoming high-severity findings
                if port in (80, 443):
                    continue

                # Try banner grab for database ports
                banner = ""
                if port in (3306, 5432, 6379, 27017, 9200):
                    banner = grab_banner(host_ip, port)

                evidence = f"Port {port} ({service}) open on {host_ip}"
                if banner:
                    evidence += f" — Banner: {banner[:100]}"

                findings.append({
                    "module": "ports",
                    "check": "exposed_port",
                    "name": f"Exposed Service: {service} (:{port})",
                    "severity": severity,
                    "detail": description,
                    "evidence": evidence,
                })

    return {"findings": findings, "open_ports": open_ports, "host_ip": host_ip}
