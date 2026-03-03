"""
Scanner Module: SSL/TLS Analysis
Checks certificate validity, expiry, weak ciphers, and protocol version.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS_PATTERNS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


def check_ssl(url: str) -> dict:
    findings = []
    hostname = urlparse(url).hostname

    if not hostname:
        return {"findings": [], "cert_info": {}}

    # If HTTP-only URL, flag it and skip
    if url.startswith("http://"):
        findings.append({
            "module": "ssl",
            "check": "no_ssl",
            "name": "Site Not Using HTTPS",
            "severity": "critical",
            "detail": "The website is not using SSL/TLS encryption. All traffic is sent in plaintext.",
            "evidence": f"Target URL uses http:// scheme: {url}",
        })
        return {"findings": findings, "cert_info": {}}

    cert_info = {}

    try:
        # Get cert details
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "not_before": cert.get("notBefore"),
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else "unknown",
                }

                # 1. Check certificate expiry
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days

                    if days_remaining < 0:
                        findings.append({
                            "module": "ssl",
                            "check": "cert_expired",
                            "name": "SSL Certificate Expired",
                            "severity": "critical",
                            "detail": f"The SSL certificate expired {abs(days_remaining)} days ago. Browsers will show security warnings.",
                            "evidence": f"notAfter: {not_after_str}",
                        })
                    elif days_remaining < 30:
                        findings.append({
                            "module": "ssl",
                            "check": "cert_expiring_soon",
                            "name": f"Certificate Expiring Soon ({days_remaining} days)",
                            "severity": "high",
                            "detail": "Certificate expires within 30 days. Failure to renew will cause service disruption.",
                            "evidence": f"notAfter: {not_after_str}",
                        })

                # 2. Check protocol version
                if protocol in WEAK_PROTOCOLS:
                    findings.append({
                        "module": "ssl",
                        "check": "weak_protocol",
                        "name": f"Weak TLS Protocol: {protocol}",
                        "severity": "critical",
                        "detail": f"{protocol} is deprecated and contains known vulnerabilities (BEAST, POODLE, etc.).",
                        "evidence": f"Negotiated protocol: {protocol}",
                    })

                # 3. Check cipher suite
                if cipher:
                    cipher_name = cipher[0]
                    for weak in WEAK_CIPHERS_PATTERNS:
                        if weak in cipher_name.upper():
                            findings.append({
                                "module": "ssl",
                                "check": "weak_cipher",
                                "name": f"Weak Cipher Suite: {cipher_name}",
                                "severity": "high",
                                "detail": f"The negotiated cipher suite contains {weak} which is considered cryptographically weak.",
                                "evidence": f"Cipher: {cipher_name}",
                            })
                            break

                # 4. Check for self-signed cert
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                if issuer == subject:
                    findings.append({
                        "module": "ssl",
                        "check": "self_signed_cert",
                        "name": "Self-Signed Certificate",
                        "severity": "high",
                        "detail": "The certificate is self-signed and not trusted by browsers. Users will see security warnings.",
                        "evidence": f"Issuer == Subject: {issuer.get('commonName', 'unknown')}",
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "module": "ssl",
            "check": "cert_verification_failed",
            "name": "Certificate Verification Failed",
            "severity": "critical",
            "detail": "The SSL certificate could not be verified. This may indicate a misconfiguration or MITM attack.",
            "evidence": str(e)[:300],
        })
    except ssl.SSLError as e:
        findings.append({
            "module": "ssl",
            "check": "ssl_error",
            "name": "SSL Error",
            "severity": "high",
            "detail": str(e)[:300],
            "evidence": "",
        })
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "module": "ssl",
            "check": "connection_error",
            "name": "Could Not Connect on Port 443",
            "severity": "info",
            "detail": "Unable to establish connection for SSL check.",
            "evidence": str(e)[:200],
        })

    return {"findings": findings, "cert_info": cert_info}
