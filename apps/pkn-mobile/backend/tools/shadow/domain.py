#!/usr/bin/env python3
"""
Shadow OSINT - Domain Reconnaissance
DNS, SSL, subdomains, and web technology intelligence
"""

import socket
import ssl
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
import requests

from .sources import DATA_SOURCES


class DomainRecon:
    """Domain-focused OSINT reconnaissance."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ShadowOSINT/1.0)"
        })

    def full_recon(self, domain: str) -> Dict[str, Any]:
        """
        Complete domain reconnaissance.

        Combines all domain checks into one report.
        """
        domain = self._clean_domain(domain)

        return {
            "success": True,
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "dns": self.dns_records(domain),
            "ssl": self.ssl_info(domain),
            "subdomains": self.subdomain_enum(domain),
            "technologies": self.tech_detect(domain),
            "certificates": self.cert_transparency(domain),
        }

    def _clean_domain(self, domain: str) -> str:
        """Clean domain input."""
        domain = domain.lower().strip()
        domain = domain.replace("http://", "").replace("https://", "")
        domain = domain.split("/")[0]
        return domain

    def dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive DNS record lookup.

        Uses both local resolver and HackerTarget API.
        """
        domain = self._clean_domain(domain)
        results = {"domain": domain, "records": {}}

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        try:
            import dns.resolver

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    results["records"][rtype] = [str(r) for r in answers]
                except dns.resolver.NoAnswer:
                    results["records"][rtype] = []
                except dns.resolver.NXDOMAIN:
                    results["error"] = "Domain does not exist"
                    break
                except Exception:
                    results["records"][rtype] = []

        except ImportError:
            # Fallback to HackerTarget API
            try:
                resp = self.session.get(
                    DATA_SOURCES["hackertarget_dns"]["url"].format(domain=domain),
                    timeout=self.timeout
                )
                results["records"]["raw"] = resp.text
                results["source"] = "hackertarget"
            except Exception as e:
                results["error"] = str(e)

        return results

    def ssl_info(self, domain: str) -> Dict[str, Any]:
        """
        Get SSL/TLS certificate information.
        """
        domain = self._clean_domain(domain)

        try:
            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Parse subject
                    subject = {}
                    for item in cert.get("subject", []):
                        for key, value in item:
                            subject[key] = value

                    # Parse issuer
                    issuer = {}
                    for item in cert.get("issuer", []):
                        for key, value in item:
                            issuer[key] = value

                    # Parse SANs
                    sans = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        sans.append({"type": san_type, "value": san_value})

                    return {
                        "success": True,
                        "domain": domain,
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get("version"),
                        "serial": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "sans": sans,
                        "san_count": len(sans),
                    }

        except Exception as e:
            return {"success": False, "domain": domain, "error": str(e)}

    def subdomain_enum(self, domain: str, use_api: bool = True) -> Dict[str, Any]:
        """
        Subdomain enumeration.

        Uses:
        - Certificate transparency logs (crt.sh)
        - HackerTarget API
        - Common subdomain wordlist
        """
        domain = self._clean_domain(domain)
        subdomains = set()
        sources_used = []

        # Method 1: Certificate Transparency (crt.sh)
        if use_api:
            try:
                resp = self.session.get(
                    DATA_SOURCES["crtsh"]["url"].format(domain=domain),
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    certs = resp.json()
                    for cert in certs:
                        name = cert.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(domain) and "*" not in sub:
                                subdomains.add(sub)
                    sources_used.append("crt.sh")
            except Exception:
                pass

            # Method 2: HackerTarget
            try:
                resp = self.session.get(
                    DATA_SOURCES["hackertarget_subdomain"]["url"].format(domain=domain),
                    timeout=self.timeout
                )
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.split("\n"):
                        if "," in line:
                            sub = line.split(",")[0].strip()
                            if sub:
                                subdomains.add(sub)
                    sources_used.append("hackertarget")
            except Exception:
                pass

        # Method 3: Common subdomains check
        common = [
            "www", "mail", "ftp", "admin", "blog", "dev", "staging",
            "test", "api", "app", "m", "mobile", "cdn", "static",
            "assets", "img", "images", "portal", "vpn", "remote",
            "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail"
        ]

        for sub in common:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
            except socket.gaierror:
                pass

        sources_used.append("wordlist")

        return {
            "success": True,
            "domain": domain,
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains),
            "sources": sources_used,
        }

    def cert_transparency(self, domain: str, limit: int = 100) -> Dict[str, Any]:
        """
        Query Certificate Transparency logs via crt.sh
        """
        domain = self._clean_domain(domain)

        try:
            resp = self.session.get(
                DATA_SOURCES["crtsh"]["url"].format(domain=domain),
                timeout=self.timeout
            )

            if resp.status_code == 200:
                certs = resp.json()[:limit]

                # Process certificates
                processed = []
                for cert in certs:
                    processed.append({
                        "id": cert.get("id"),
                        "name": cert.get("name_value"),
                        "issuer": cert.get("issuer_name"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                    })

                return {
                    "success": True,
                    "domain": domain,
                    "certificates": processed,
                    "count": len(processed),
                }

            return {"success": False, "error": f"Status {resp.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def tech_detect(self, domain: str) -> Dict[str, Any]:
        """
        Detect web technologies used by domain.
        """
        domain = self._clean_domain(domain)
        url = f"https://{domain}"

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(resp.headers)
            content = resp.text.lower()

            tech = {
                "server": headers.get("Server", "Unknown"),
                "powered_by": headers.get("X-Powered-By"),
                "frameworks": [],
                "cms": None,
                "cdn": None,
                "analytics": [],
                "security": [],
            }

            # CMS Detection
            cms_signatures = {
                "wordpress": ["wp-content", "wp-includes", "wordpress"],
                "drupal": ["drupal", "/sites/default/"],
                "joomla": ["joomla", "/components/com_"],
                "shopify": ["shopify", "cdn.shopify.com"],
                "wix": ["wix.com", "wixstatic.com"],
                "squarespace": ["squarespace"],
            }

            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    tech["cms"] = cms
                    break

            # Framework Detection
            framework_signatures = {
                "react": ["react", "_next", "__next"],
                "vue": ["vue.js", "__vue__"],
                "angular": ["ng-", "angular"],
                "jquery": ["jquery"],
                "bootstrap": ["bootstrap"],
                "tailwind": ["tailwind"],
            }

            for framework, signatures in framework_signatures.items():
                if any(sig in content for sig in signatures):
                    tech["frameworks"].append(framework)

            # CDN Detection
            cdn_signatures = {
                "cloudflare": ["cloudflare", "cf-ray"],
                "akamai": ["akamai"],
                "fastly": ["fastly"],
                "cloudfront": ["cloudfront", "x-amz-cf-id"],
            }

            for cdn, signatures in cdn_signatures.items():
                if any(sig in str(headers).lower() or sig in content for sig in signatures):
                    tech["cdn"] = cdn
                    break

            # Analytics Detection
            if "google-analytics" in content or "gtag" in content:
                tech["analytics"].append("Google Analytics")
            if "facebook.net/en_US/fbevents" in content:
                tech["analytics"].append("Facebook Pixel")
            if "hotjar" in content:
                tech["analytics"].append("Hotjar")

            # Security Headers
            security_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
            ]

            for header in security_headers:
                if header in headers:
                    tech["security"].append({
                        "header": header,
                        "value": headers[header][:100]
                    })

            return {
                "success": True,
                "domain": domain,
                "url": str(resp.url),
                "status_code": resp.status_code,
                "technologies": tech,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        WHOIS lookup for domain registration info.
        """
        domain = self._clean_domain(domain)

        try:
            import whois

            w = whois.whois(domain)

            return {
                "success": True,
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "nameservers": w.name_servers if w.name_servers else [],
                "status": w.status,
                "emails": w.emails if w.emails else [],
                "country": w.country,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
