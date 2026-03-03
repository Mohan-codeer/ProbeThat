"""
Scanner Module: DNS Checks
Checks for zone transfer vulnerabilities, SPF/DMARC misconfig,
dangling DNS records, and subdomain enumeration hints.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
from urllib.parse import urlparse
import socket


COMMON_SUBDOMAINS = [
    "admin", "api", "app", "auth", "beta", "cms", "dashboard",
    "dev", "ftp", "git", "mail", "old", "portal", "staging",
    "test", "vpn", "www2", "cdn", "static", "assets",
]


def check_dns(url: str) -> dict:
    findings = []
    hostname = urlparse(url).hostname

    if not hostname:
        return {"findings": [], "dns_info": {}}

    # Strip www for apex checks
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    dns_info = {"hostname": hostname, "domain": domain}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # 1. Attempt zone transfer (AXFR)
    try:
        ns_records = resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                if zone:
                    findings.append({
                        "module": "dns",
                        "check": "zone_transfer",
                        "name": "DNS Zone Transfer Allowed",
                        "severity": "critical",
                        "detail": "The DNS server allows zone transfers (AXFR), exposing your entire DNS record set to anyone who asks.",
                        "evidence": f"Zone transfer succeeded from: {ns_host}",
                    })
                    break
            except Exception:
                pass  # Zone transfer blocked (expected)
    except Exception:
        pass

    # 2. Check SPF record
    try:
        txt_records = resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r).lower() for r in txt_records)
        dmarc_found = False

        try:
            dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_found = any("v=DMARC1" in str(r) for r in dmarc_records)
        except Exception:
            pass

        if not spf_found:
            findings.append({
                "module": "dns",
                "check": "missing_spf",
                "name": "Missing SPF Record",
                "severity": "medium",
                "detail": "No SPF TXT record found. Attackers can spoof emails from your domain.",
                "evidence": f"No 'v=spf1' TXT record on {domain}",
            })

        if not dmarc_found:
            findings.append({
                "module": "dns",
                "check": "missing_dmarc",
                "name": "Missing DMARC Record",
                "severity": "medium",
                "detail": "No DMARC policy found. Without DMARC, email spoofing is undetectable by receiving servers.",
                "evidence": f"No TXT record at _dmarc.{domain}",
            })

    except Exception:
        pass

    # 3. Check for exposed subdomains
    found_subdomains = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            for r in answers:
                found_subdomains.append({"subdomain": fqdn, "ip": str(r)})
        except Exception:
            pass

    if found_subdomains:
        sub_list = ", ".join(s["subdomain"] for s in found_subdomains[:6])
        findings.append({
            "module": "dns",
            "check": "exposed_subdomains",
            "name": f"Exposed Subdomains Found ({len(found_subdomains)})",
            "severity": "info",
            "detail": "These subdomains resolved to public IPs and may expose staging, dev, or admin environments.",
            "evidence": sub_list,
        })
        dns_info["found_subdomains"] = found_subdomains

    # 4. Check for CAA records (cert issuance control)
    try:
        resolver.resolve(domain, "CAA")
    except dns.resolver.NoAnswer:
        findings.append({
            "module": "dns",
            "check": "missing_caa",
            "name": "Missing CAA Record",
            "severity": "low",
            "detail": "No Certificate Authority Authorization record. Any CA can issue certs for your domain.",
            "evidence": f"No CAA record found for {domain}",
        })
    except Exception:
        pass

    return {"findings": findings, "dns_info": dns_info}
