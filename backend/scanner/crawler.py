"""
Scanner Module: Web Crawler
Checks for exposed sensitive files, directories, admin panels,
debug endpoints, and error message disclosure.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse


SENSITIVE_PATHS = [
    # Config & env files
    ("/.env", "critical", "Environment file exposed"),
    ("/.env.local", "critical", "Local environment file exposed"),
    ("/.env.production", "critical", "Production environment file exposed"),
    ("/config.json", "high", "Config file exposed"),
    ("/config.yaml", "high", "Config file exposed"),
    ("/config.yml", "high", "Config file exposed"),
    ("/secrets.json", "critical", "Secrets file exposed"),
    ("/app.config", "high", "Application config exposed"),
    ("/web.config", "high", "Web.config exposed"),
    ("/wp-config.php.bak", "critical", "WordPress config backup exposed"),

    # Version control
    ("/.git/HEAD", "critical", "Git repository exposed"),
    ("/.git/config", "critical", "Git configuration exposed"),
    ("/.svn/entries", "high", "SVN repository exposed"),
    ("/.hg/", "high", "Mercurial repository exposed"),

    # Admin panels
    ("/admin", "high", "Admin panel accessible"),
    ("/admin/login", "high", "Admin login page accessible"),
    ("/administrator", "high", "Administrator panel accessible"),
    ("/wp-admin", "medium", "WordPress admin panel accessible"),
    ("/phpmyadmin", "critical", "phpMyAdmin accessible"),
    ("/adminer.php", "critical", "Adminer database tool accessible"),
    ("/panel", "medium", "Control panel accessible"),
    ("/dashboard", "medium", "Dashboard accessible"),

    # Backup files
    ("/backup.zip", "critical", "Backup archive exposed"),
    ("/backup.sql", "critical", "Database backup exposed"),
    ("/backup.tar.gz", "critical", "Backup archive exposed"),
    ("/dump.sql", "critical", "SQL dump exposed"),
    ("/db.sql", "critical", "SQL database exposed"),

    # Debug / dev endpoints
    ("/debug", "high", "Debug endpoint accessible"),
    ("/console", "high", "Debug console accessible"),
    ("/phpinfo.php", "high", "PHP info page exposed"),
    ("/info.php", "high", "PHP info page exposed"),
    ("/test.php", "medium", "Test PHP file accessible"),
    ("/_debug_toolbar", "high", "Debug toolbar accessible"),
    ("/laravel-telescope", "high", "Laravel Telescope exposed"),

    # API & docs
    ("/swagger", "medium", "Swagger API docs accessible"),
    ("/swagger-ui.html", "medium", "Swagger UI accessible"),
    ("/api-docs", "medium", "API documentation accessible"),
    ("/graphql", "medium", "GraphQL endpoint accessible"),
    ("/graphiql", "medium", "GraphiQL interface accessible"),
    ("/api/v1", "info", "API endpoint discovered"),
    ("/api/v2", "info", "API endpoint discovered"),

    # Log files
    ("/logs/app.log", "high", "Application log exposed"),
    ("/error.log", "high", "Error log exposed"),
    ("/access.log", "high", "Access log exposed"),
    ("/.htaccess", "medium", "htaccess file accessible"),

    # Security files that should be configured
    ("/robots.txt", "info", "robots.txt found (review for path disclosure)"),
    ("/sitemap.xml", "info", "sitemap.xml found"),
    ("/security.txt", "info", "security.txt found"),
    ("/.well-known/security.txt", "info", "security.txt found"),
]

HEADERS = {"User-Agent": "ProbeThat-SecurityScanner/1.0"}


def probe_path(base_url: str, path: str, severity: str, description: str) -> dict | None:
    url = urljoin(base_url, path)
    try:
        resp = requests.get(url, timeout=6, allow_redirects=False,
                            verify=True, headers=HEADERS)

        # Interesting status codes
        if resp.status_code in (200, 403, 500):
            content = resp.text[:500].lower()

            # 403 on admin paths = still noteworthy
            if resp.status_code == 403 and "admin" not in path:
                return None

            # For .env, check if it looks real
            if ".env" in path and resp.status_code == 200:
                if "db_password" in content or "secret_key" in content or "api_key" in content:
                    severity = "critical"

            return {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "severity": severity,
                "description": description,
                "size": len(resp.content),
            }
    except Exception:
        pass
    return None


def crawl_site(url: str) -> dict:
    findings = []
    discovered_paths = []

    base = url.rstrip("/")
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(probe_path, base_url, path, sev, desc): (path, sev, desc)
            for path, sev, desc in SENSITIVE_PATHS
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered_paths.append(result)

    # Build findings from discovered paths
    for p in discovered_paths:
        severity = p["severity"]
        status = p["status"]

        # Don't alert on info paths unless we want to
        if severity == "info" and status != 200:
            continue

        evidence = f"HTTP {status} — {p['url']}"
        if p["size"]:
            evidence += f" ({p['size']} bytes)"

        # Check for graphql introspection
        if "graphql" in p["path"] and status == 200:
            try:
                resp = requests.post(p["url"], json={"query": "{__schema{types{name}}}"}, timeout=6, headers=HEADERS)
                if "data" in resp.text and "__schema" in resp.text:
                    findings.append({
                        "module": "crawler",
                        "check": "graphql_introspection",
                        "name": "GraphQL Introspection Enabled",
                        "severity": "medium",
                        "detail": "GraphQL introspection is enabled, exposing the full schema to attackers.",
                        "evidence": f"Introspection query returned schema at {p['url']}",
                    })
            except Exception:
                pass

        findings.append({
            "module": "crawler",
            "check": "sensitive_path",
            "name": p["description"],
            "severity": severity,
            "detail": f"Path {p['path']} returned HTTP {status}.",
            "evidence": evidence,
        })

    return {"findings": findings, "discovered_paths": discovered_paths}
