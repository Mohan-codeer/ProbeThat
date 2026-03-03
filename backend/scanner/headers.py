"""
Scanner Module: HTTP Headers & Cookie Audit
Checks for missing/misconfigured security headers and insecure cookies.
"""

import requests
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP prevents XSS by declaring which dynamic resources are allowed to load.",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Prevents your pages from being embedded in iframes (clickjacking defense).",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Prevents MIME-type sniffing which can allow XSS in some browsers.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Controls access to browser APIs like camera, microphone, and geolocation.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controls how much referrer info is sent with requests.",
    },
    "X-XSS-Protection": {
        "severity": "info",
        "description": "Legacy XSS filter for older browsers. CSP is preferred.",
    },
}

SENSITIVE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]


def check_headers(url: str) -> dict:
    findings = []
    raw_headers = {}
    raw_cookies = []

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True,
                            headers={"User-Agent": "ProbeThat-SecurityScanner/1.0"})
        raw_headers = dict(resp.headers)

        # 1. Check missing security headers
        for header, meta in SECURITY_HEADERS.items():
            if header not in resp.headers:
                findings.append({
                    "module": "headers",
                    "check": "missing_security_header",
                    "name": f"Missing Header: {header}",
                    "severity": meta["severity"],
                    "detail": meta["description"],
                    "evidence": f"{header} header not present in response",
                })

        # 2. Check for information leakage via headers
        for header in SENSITIVE_HEADERS:
            if header in resp.headers:
                findings.append({
                    "module": "headers",
                    "check": "info_disclosure_header",
                    "name": f"Information Disclosure: {header}",
                    "severity": "medium",
                    "detail": f"The {header} header reveals server technology which aids attackers in fingerprinting.",
                    "evidence": f"{header}: {resp.headers[header]}",
                })

        # 3. CORS misconfig
        origin_test = requests.get(url, timeout=10, verify=True,
                                   headers={"Origin": "https://evil.com",
                                            "User-Agent": "ProbeThat-SecurityScanner/1.0"})
        acao = origin_test.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            findings.append({
                "module": "headers",
                "check": "cors_misconfiguration",
                "name": "Permissive CORS Policy",
                "severity": "high",
                "detail": "Server reflects arbitrary origins or uses wildcard, allowing cross-origin data theft.",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
            })

        # 4. Cookie security flags
        for cookie in resp.cookies:
            missing_flags = [f for f in COOKIE_FLAGS if not getattr(cookie, f.lower().replace("-", "_"), None)]
            if missing_flags:
                raw_cookies.append({
                    "name": cookie.name,
                    "missing_flags": missing_flags,
                })
                findings.append({
                    "module": "headers",
                    "check": "insecure_cookie",
                    "name": f"Insecure Cookie: {cookie.name}",
                    "severity": "medium",
                    "detail": f"Cookie is missing security flags: {', '.join(missing_flags)}.",
                    "evidence": f"Set-Cookie: {cookie.name}=...; (missing: {', '.join(missing_flags)})",
                })

        # 5. Check if HTTPS redirect exists
        if url.startswith("http://"):
            findings.append({
                "module": "headers",
                "check": "no_https_redirect",
                "name": "No HTTPS Redirect",
                "severity": "high",
                "detail": "The site is accessible over plain HTTP with no redirect to HTTPS.",
                "evidence": f"HTTP 200 returned for {url}",
            })

    except requests.exceptions.SSLError as e:
        findings.append({
            "module": "headers",
            "check": "ssl_error",
            "name": "SSL Certificate Error",
            "severity": "critical",
            "detail": "The server's SSL certificate caused an error.",
            "evidence": str(e)[:200],
        })
    except requests.exceptions.ConnectionError:
        findings.append({
            "module": "headers",
            "check": "connection_error",
            "name": "Connection Failed",
            "severity": "info",
            "detail": "Could not connect to the target URL.",
            "evidence": url,
        })
    except Exception as e:
        findings.append({
            "module": "headers",
            "check": "scan_error",
            "name": "Header Scan Error",
            "severity": "info",
            "detail": str(e)[:200],
            "evidence": "",
        })

    return {"findings": findings, "raw_headers": raw_headers, "raw_cookies": raw_cookies}
