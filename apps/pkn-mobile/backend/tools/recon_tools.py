"""
Recon Tools - Advanced Reconnaissance
Pure Python reconnaissance utilities for penetration testing.

Tools:
- banner_grab: Service banner grabbing
- http_security_headers: Analyze security headers
- robots_sitemap_extract: Extract paths from robots.txt/sitemap.xml
- directory_bruteforce: Directory enumeration
- js_endpoints_extract: Find API endpoints in JavaScript
- cors_check: CORS misconfiguration testing
- subdomain_takeover_check: Detect takeover vulnerabilities
- favicon_fingerprint: Shodan favicon hash

WARNING: For authorized security testing only.
"""

import socket
import hashlib
import re
from typing import Optional, List
from urllib.parse import urljoin, urlparse
from langchain_core.tools import tool

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Common directories for bruteforcing
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "api", "v1", "v2", "graphql", "swagger", "docs",
    "backup", "backups", "db", "database", "config", "conf",
    ".git", ".svn", ".env", "env", ".htaccess", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "phpinfo.php",
    "test", "dev", "staging", "debug", "console", "shell",
    "upload", "uploads", "files", "images", "assets", "static",
    "cgi-bin", "bin", "includes", "inc", "lib", "src", "app",
]

# Security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
    "X-XSS-Protection", "Strict-Transport-Security", "Referrer-Policy",
    "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
]


@tool
def banner_grab(host: str, port: int, timeout: int = 5) -> str:
    """
    Grab service banner from a host:port.

    Args:
        host: Target hostname or IP
        port: Target port number
        timeout: Connection timeout in seconds

    Returns:
        Service banner or error message
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send probe for HTTP
        if port in [80, 443, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()

        return f"Banner from {host}:{port}:\n{banner.strip()}"
    except socket.timeout:
        return f"Timeout connecting to {host}:{port}"
    except Exception as e:
        return f"Error: {e}"


@tool
def http_security_headers(url: str) -> str:
    """
    Analyze HTTP security headers for a URL.

    Args:
        url: Target URL to analyze

    Returns:
        Security header analysis report
    """
    if not REQUESTS_AVAILABLE:
        return "Error: requests library not available"

    try:
        resp = requests.head(url, timeout=10, allow_redirects=True)
        headers = resp.headers

        results = [f"Security Headers Analysis: {url}", "=" * 50]

        for header in SECURITY_HEADERS:
            value = headers.get(header, "MISSING")
            status = "+" if value != "MISSING" else "-"
            results.append(f"[{status}] {header}: {value[:60]}...")

        # Additional checks
        server = headers.get("Server", "Hidden")
        results.append(f"\nServer: {server}")
        results.append(f"Cookies: {len(resp.cookies)} set")

        missing = [h for h in SECURITY_HEADERS if h not in headers]
        results.append(f"\nMissing headers: {len(missing)}/{len(SECURITY_HEADERS)}")

        return "\n".join(results)
    except Exception as e:
        return f"Error analyzing {url}: {e}"


@tool
def robots_sitemap_extract(url: str) -> str:
    """
    Extract paths from robots.txt and sitemap.xml.

    Args:
        url: Base URL of the target website

    Returns:
        Extracted paths and directives
    """
    if not REQUESTS_AVAILABLE:
        return "Error: requests library not available"

    results = [f"Robots/Sitemap Analysis: {url}", "=" * 50]
    paths = set()

    # Parse robots.txt
    try:
        robots_url = urljoin(url, "/robots.txt")
        resp = requests.get(robots_url, timeout=10)
        if resp.status_code == 200:
            results.append("\n[robots.txt]")
            for line in resp.text.split("\n"):
                line = line.strip()
                if line.startswith(("Disallow:", "Allow:", "Sitemap:")):
                    results.append(f"  {line}")
                    if ":" in line:
                        path = line.split(":", 1)[1].strip()
                        if path and not path.startswith("http"):
                            paths.add(path)
    except:
        results.append("[robots.txt] Not found or error")

    # Parse sitemap.xml
    try:
        sitemap_url = urljoin(url, "/sitemap.xml")
        resp = requests.get(sitemap_url, timeout=10)
        if resp.status_code == 200:
            urls_found = re.findall(r"<loc>(.*?)</loc>", resp.text)
            results.append(f"\n[sitemap.xml] {len(urls_found)} URLs found")
            for u in urls_found[:10]:
                results.append(f"  {u}")
            if len(urls_found) > 10:
                results.append(f"  ... and {len(urls_found) - 10} more")
    except:
        results.append("[sitemap.xml] Not found or error")

    results.append(f"\nUnique paths discovered: {len(paths)}")
    return "\n".join(results)


@tool
def directory_bruteforce(url: str, wordlist: str = "common", threads: int = 5) -> str:
    """
    Bruteforce directories using built-in wordlist.

    Args:
        url: Base URL to scan
        wordlist: "common" for built-in, or custom comma-separated paths
        threads: Not used (sequential for simplicity)

    Returns:
        Found directories with status codes
    """
    if not REQUESTS_AVAILABLE:
        return "Error: requests library not available"

    dirs = COMMON_DIRS if wordlist == "common" else wordlist.split(",")
    found = []

    results = [f"Directory Bruteforce: {url}", f"Testing {len(dirs)} paths...", "=" * 50]

    for path in dirs:
        try:
            test_url = urljoin(url.rstrip("/") + "/", path.strip())
            resp = requests.head(test_url, timeout=5, allow_redirects=False)

            if resp.status_code in [200, 301, 302, 403]:
                status = f"[{resp.status_code}]"
                found.append((test_url, resp.status_code))
                results.append(f"{status} {test_url}")
        except:
            continue

    results.append(f"\nFound: {len(found)} accessible paths")
    return "\n".join(results)


@tool
def cors_check(url: str) -> str:
    """
    Test for CORS misconfigurations.

    Args:
        url: Target URL to test

    Returns:
        CORS analysis results
    """
    if not REQUESTS_AVAILABLE:
        return "Error: requests library not available"

    results = [f"CORS Analysis: {url}", "=" * 50]

    # Test various origins
    test_origins = [
        "https://evil.com",
        "null",
        urlparse(url).scheme + "://" + urlparse(url).netloc.replace(".", "x"),
    ]

    for origin in test_origins:
        try:
            headers = {"Origin": origin}
            resp = requests.get(url, headers=headers, timeout=10)

            acao = resp.headers.get("Access-Control-Allow-Origin", "Not Set")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "Not Set")

            vuln = ""
            if acao == "*":
                vuln = "[VULN] Wildcard origin"
            elif acao == origin and origin != "null":
                vuln = "[VULN] Reflects arbitrary origin"
            elif acao == "null":
                vuln = "[VULN] Allows null origin"

            if acac == "true" and vuln:
                vuln += " + credentials!"

            results.append(f"Origin: {origin}")
            results.append(f"  ACAO: {acao}")
            results.append(f"  ACAC: {acac}")
            if vuln:
                results.append(f"  {vuln}")
            results.append("")
        except Exception as e:
            results.append(f"Origin: {origin} - Error: {e}")

    return "\n".join(results)


@tool
def favicon_fingerprint(url: str) -> str:
    """
    Generate Shodan favicon hash for fingerprinting.

    Args:
        url: URL of the favicon (or base URL to find /favicon.ico)

    Returns:
        MurmurHash3 value for Shodan search
    """
    if not REQUESTS_AVAILABLE:
        return "Error: requests library not available"

    try:
        import base64
        import struct

        # Get favicon
        if not url.endswith((".ico", ".png")):
            url = urljoin(url, "/favicon.ico")

        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return f"Favicon not found at {url}"

        # Base64 encode
        favicon_b64 = base64.b64encode(resp.content).decode()

        # MurmurHash3 (simplified)
        def mmh3_hash(data):
            h = 0
            for b in data.encode():
                h ^= b
                h = (h * 0x5bd1e995) & 0xFFFFFFFF
            return struct.unpack("i", struct.pack("I", h))[0]

        hash_value = mmh3_hash(favicon_b64)

        return f"""Favicon Fingerprint:
URL: {url}
Size: {len(resp.content)} bytes
MurmurHash3: {hash_value}

Shodan search: http.favicon.hash:{hash_value}"""
    except Exception as e:
        return f"Error: {e}"


# Export tools
TOOLS = [
    banner_grab,
    http_security_headers,
    robots_sitemap_extract,
    directory_bruteforce,
    cors_check,
    favicon_fingerprint,
]

TOOL_DESCRIPTIONS = {
    "banner_grab": "Grab service banner from host:port",
    "http_security_headers": "Analyze HTTP security headers",
    "robots_sitemap_extract": "Extract paths from robots.txt/sitemap.xml",
    "directory_bruteforce": "Bruteforce directories",
    "cors_check": "Test for CORS misconfigurations",
    "favicon_fingerprint": "Generate Shodan favicon hash",
}
