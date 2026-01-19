#!/usr/bin/env python3
"""
Shadow OSINT - Core Engine
Orchestrates all reconnaissance modules
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from .person import PersonRecon
from .domain import DomainRecon
from .network import NetworkRecon
from .dorks import DorkGenerator


class ShadowEngine:
    """
    Main Shadow OSINT orchestrator.

    Coordinates all reconnaissance modules and generates reports.
    """

    def __init__(self, timeout: int = 10, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers

        # Initialize modules
        self.person = PersonRecon(timeout=timeout, max_workers=max_workers)
        self.domain = DomainRecon(timeout=timeout)
        self.network = NetworkRecon(timeout=timeout)
        self.dorks = DorkGenerator()

        # Results storage
        self.results = {}

    def investigate_person(
        self,
        username: str = None,
        email: str = None,
        phone: str = None,
        quick: bool = False
    ) -> Dict[str, Any]:
        """
        Full person investigation.

        Args:
            username: Username to investigate
            email: Email address to investigate
            phone: Phone number to investigate
            quick: If True, use quick mode (fewer platforms)
        """
        results = {
            "type": "person",
            "timestamp": datetime.utcnow().isoformat(),
            "inputs": {
                "username": username,
                "email": email,
                "phone": phone,
            },
            "findings": {},
        }

        if username:
            results["findings"]["username"] = self.person.username_check(
                username, quick=quick
            )
            results["findings"]["social_graph"] = self.person.social_graph(username)

        if email:
            results["findings"]["email"] = self.person.email_recon(email)

            # If email has username part, also check that
            if "@" in email and not username:
                email_username = email.split("@")[0]
                results["findings"]["derived_username"] = self.person.username_check(
                    email_username, quick=True
                )

        if phone:
            results["findings"]["phone"] = self.person.phone_recon(phone)

        # Generate dorks
        if username:
            results["dorks"] = self.dorks.google_dorks(username, "username")
        elif email:
            results["dorks"] = self.dorks.google_dorks(email, "email")

        self.results["person"] = results
        return results

    def investigate_domain(
        self,
        domain: str,
        full: bool = True
    ) -> Dict[str, Any]:
        """
        Full domain investigation.

        Args:
            domain: Domain to investigate
            full: If True, run all checks
        """
        results = {
            "type": "domain",
            "timestamp": datetime.utcnow().isoformat(),
            "domain": domain,
            "findings": {},
        }

        if full:
            results["findings"] = self.domain.full_recon(domain)
        else:
            results["findings"]["dns"] = self.domain.dns_records(domain)
            results["findings"]["ssl"] = self.domain.ssl_info(domain)

        # Generate dorks
        results["dorks"] = {
            "google": self.dorks.google_dorks(domain, "domain"),
            "github": self.dorks.github_dorks(domain, "org"),
            "shodan": self.dorks.shodan_dorks(domain),
        }

        self.results["domain"] = results
        return results

    def investigate_ip(
        self,
        ip: str,
        full: bool = True
    ) -> Dict[str, Any]:
        """
        Full IP investigation.

        Args:
            ip: IP address to investigate
            full: If True, run all checks
        """
        results = {
            "type": "ip",
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "findings": {},
        }

        if full:
            results["findings"] = self.network.full_recon(ip)
        else:
            results["findings"]["geolocation"] = self.network.geolocate(ip)
            results["findings"]["reverse_dns"] = self.network.reverse_dns(ip)

        self.results["ip"] = results
        return results

    def investigate_company(
        self,
        company: str,
        domain: str = None
    ) -> Dict[str, Any]:
        """
        Company-focused investigation.

        Args:
            company: Company name
            domain: Company domain (optional)
        """
        results = {
            "type": "company",
            "timestamp": datetime.utcnow().isoformat(),
            "company": company,
            "domain": domain,
            "findings": {},
        }

        # Generate company dorks
        results["dorks"] = {
            "google": self.dorks.google_dorks(company, "company"),
            "github": self.dorks.github_dorks(company, "org"),
        }

        # If domain provided, also investigate it
        if domain:
            results["findings"]["domain"] = self.domain.full_recon(domain)
            results["dorks"]["domain"] = self.dorks.google_dorks(domain, "domain")

        self.results["company"] = results
        return results

    def quick_recon(self, target: str) -> Dict[str, Any]:
        """
        Auto-detect target type and run quick recon.

        Args:
            target: Can be username, email, domain, or IP
        """
        import re

        results = {
            "target": target,
            "detected_type": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Detect type
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            results["detected_type"] = "ip"
            results["findings"] = self.network.geolocate(target)
            results["findings"]["shodan"] = self.network.shodan_lookup(target)

        elif "@" in target:
            results["detected_type"] = "email"
            results["findings"] = self.person.email_recon(target)

        elif "." in target and not target.startswith("+"):
            results["detected_type"] = "domain"
            results["findings"] = {
                "dns": self.domain.dns_records(target),
                "ssl": self.domain.ssl_info(target),
            }

        elif target.startswith("+") or target.isdigit():
            results["detected_type"] = "phone"
            results["findings"] = self.person.phone_recon(target)

        else:
            results["detected_type"] = "username"
            results["findings"] = self.person.username_check(target, quick=True)

        return results

    def generate_dorks(
        self,
        target: str,
        platforms: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generate dorks for a target across all platforms.

        Args:
            target: Target (domain, company, username)
            platforms: List of platforms ("google", "github", "shodan")
        """
        if platforms is None:
            platforms = ["google", "github", "shodan"]

        results = {
            "target": target,
            "platforms": {},
        }

        if "google" in platforms:
            # Try different target types
            results["platforms"]["google"] = {
                "domain": self.dorks.google_dorks(target, "domain"),
                "company": self.dorks.google_dorks(target, "company"),
                "username": self.dorks.google_dorks(target, "username"),
            }

        if "github" in platforms:
            results["platforms"]["github"] = {
                "org": self.dorks.github_dorks(target, "org"),
                "user": self.dorks.github_dorks(target, "user"),
            }

        if "shodan" in platforms:
            results["platforms"]["shodan"] = self.dorks.shodan_dorks(target)

        return results

    def export_results(
        self,
        filepath: str = None,
        format: str = "json"
    ) -> str:
        """
        Export all results to file.

        Args:
            filepath: Output file path
            format: "json" or "txt"
        """
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"shadow_report_{timestamp}.{format}"

        if format == "json":
            with open(filepath, "w") as f:
                json.dump(self.results, f, indent=2, default=str)
        else:
            with open(filepath, "w") as f:
                f.write(self._format_txt_report())

        return filepath

    def _format_txt_report(self) -> str:
        """Format results as text report."""
        lines = [
            "=" * 60,
            "SHADOW OSINT REPORT",
            f"Generated: {datetime.utcnow().isoformat()}",
            "=" * 60,
            "",
        ]

        for category, data in self.results.items():
            lines.append(f"\n{'='*40}")
            lines.append(f"[{category.upper()}]")
            lines.append("=" * 40)
            lines.append(json.dumps(data, indent=2, default=str))

        return "\n".join(lines)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all findings."""
        summary = {
            "total_investigations": len(self.results),
            "categories": list(self.results.keys()),
            "highlights": [],
        }

        # Extract highlights
        if "person" in self.results:
            person = self.results["person"]
            if "username" in person.get("findings", {}):
                found_count = person["findings"]["username"].get("found_count", 0)
                summary["highlights"].append(
                    f"Found {found_count} profiles for username"
                )

        if "domain" in self.results:
            domain = self.results["domain"]
            findings = domain.get("findings", {})
            if "subdomains" in findings:
                sub_count = findings["subdomains"].get("count", 0)
                summary["highlights"].append(
                    f"Found {sub_count} subdomains"
                )

        if "ip" in self.results:
            ip = self.results["ip"]
            findings = ip.get("findings", {})
            if "shodan" in findings and findings["shodan"].get("has_vulns"):
                vuln_count = len(findings["shodan"].get("vulns", []))
                summary["highlights"].append(
                    f"IP has {vuln_count} known vulnerabilities"
                )

        return summary
