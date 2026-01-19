#!/usr/bin/env python3
"""
Shadow OSINT - Person Reconnaissance
Username, email, phone, and social media intelligence
"""

import re
import socket
import hashlib
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from .sources import USERNAME_PLATFORMS, DATA_SOURCES, get_platforms_by_category


class PersonRecon:
    """Person-focused OSINT reconnaissance."""

    def __init__(self, timeout: int = 5, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def username_check(
        self,
        username: str,
        categories: List[str] = None,
        quick: bool = False
    ) -> Dict[str, Any]:
        """
        Check username across platforms.

        Args:
            username: Username to search
            categories: Filter by categories (dev, social, gaming, etc.)
            quick: If True, only check top 20 platforms
        """
        # Select platforms
        if categories:
            platforms = {}
            for cat in categories:
                platforms.update(get_platforms_by_category(cat))
        else:
            platforms = USERNAME_PLATFORMS

        # Quick mode - top platforms only
        if quick:
            top_platforms = [
                "github", "twitter", "instagram", "linkedin", "reddit",
                "youtube", "tiktok", "facebook", "twitch", "discord",
                "steam", "spotify", "medium", "hackthebox", "telegram",
                "stackoverflow", "pinterest", "tumblr", "snapchat", "keybase"
            ]
            platforms = {k: v for k, v in platforms.items() if k in top_platforms}

        found = {}
        not_found = []
        errors = []

        def check_platform(name: str, data: dict) -> tuple:
            url = data["url"].format(username)
            try:
                resp = self.session.head(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                if resp.status_code == 200:
                    return (name, url, "found")
                return (name, url, "not_found")
            except Exception as e:
                return (name, url, f"error:{str(e)[:30]}")

        # Parallel checking
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(check_platform, name, data): name
                for name, data in platforms.items()
            }

            for future in as_completed(futures):
                name, url, status = future.result()
                if status == "found":
                    found[name] = {
                        "url": url,
                        "category": platforms[name].get("category", "unknown")
                    }
                elif status == "not_found":
                    not_found.append(name)
                else:
                    errors.append({"platform": name, "error": status})

        return {
            "success": True,
            "username": username,
            "found": found,
            "found_count": len(found),
            "not_found_count": len(not_found),
            "errors_count": len(errors),
            "total_checked": len(platforms),
            "categories_checked": categories or ["all"],
        }

    def email_recon(self, email: str) -> Dict[str, Any]:
        """
        Comprehensive email reconnaissance.

        Checks:
        - Format validation
        - MX records
        - Disposable email detection
        - Breach databases (k-anonymity)
        - Gravatar
        """
        results = {
            "success": True,
            "email": email,
            "checks": {}
        }

        # Format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        results["checks"]["format"] = {
            "valid": bool(re.match(email_regex, email))
        }

        if not results["checks"]["format"]["valid"]:
            results["success"] = False
            results["error"] = "Invalid email format"
            return results

        domain = email.split("@")[1]
        local_part = email.split("@")[0]

        # MX records
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, "MX")
            results["checks"]["mx"] = {
                "has_mx": True,
                "records": [str(r.exchange) for r in mx_records]
            }
        except Exception:
            results["checks"]["mx"] = {"has_mx": False, "records": []}

        # Disposable email check
        disposable_domains = [
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "10minutemail.com", "mailinator.com", "temp-mail.org",
            "fakeinbox.com", "trashmail.com", "yopmail.com"
        ]
        results["checks"]["disposable"] = {
            "is_disposable": domain.lower() in disposable_domains
        }

        # Gravatar check
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        try:
            resp = self.session.head(gravatar_url, timeout=5)
            results["checks"]["gravatar"] = {
                "exists": resp.status_code == 200,
                "url": f"https://www.gravatar.com/{email_hash}" if resp.status_code == 200 else None
            }
        except Exception:
            results["checks"]["gravatar"] = {"exists": False, "url": None}

        # Have I Been Pwned (k-anonymity - no API key needed)
        try:
            sha1_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            resp = self.session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )

            if resp.status_code == 200:
                breaches = 0
                for line in resp.text.split("\n"):
                    if line.startswith(suffix):
                        breaches = int(line.split(":")[1])
                        break

                results["checks"]["breaches"] = {
                    "found_in_breaches": breaches > 0,
                    "breach_count": breaches
                }
            else:
                results["checks"]["breaches"] = {"error": "API unavailable"}
        except Exception as e:
            results["checks"]["breaches"] = {"error": str(e)}

        # Generate related usernames to check
        results["derived_usernames"] = [
            local_part,
            local_part.replace(".", ""),
            local_part.replace(".", "_"),
            f"{local_part}{domain.split('.')[0]}",
        ]

        return results

    def phone_recon(self, phone: str) -> Dict[str, Any]:
        """
        Phone number reconnaissance.

        Uses phonenumbers library for:
        - Validation
        - Country/carrier detection
        - Number type classification
        """
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone, phonenumberutil

            # Parse number
            parsed = phonenumbers.parse(phone, None)

            # Get number type
            number_type = phonenumberutil.number_type(parsed)
            type_names = {
                0: "FIXED_LINE",
                1: "MOBILE",
                2: "FIXED_LINE_OR_MOBILE",
                3: "TOLL_FREE",
                4: "PREMIUM_RATE",
                5: "SHARED_COST",
                6: "VOIP",
                7: "PERSONAL_NUMBER",
                8: "PAGER",
                9: "UAN",
                10: "VOICEMAIL",
                27: "UNKNOWN",
            }

            return {
                "success": True,
                "phone": phone,
                "valid": phonenumbers.is_valid_number(parsed),
                "possible": phonenumbers.is_possible_number(parsed),
                "country_code": parsed.country_code,
                "national_number": str(parsed.national_number),
                "country": geocoder.description_for_number(parsed, "en"),
                "carrier": carrier.name_for_number(parsed, "en"),
                "timezones": list(timezone.time_zones_for_number(parsed)),
                "type": type_names.get(number_type, "UNKNOWN"),
                "formatted": {
                    "international": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    ),
                    "national": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                    ),
                    "e164": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164
                    ),
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def social_graph(self, username: str) -> Dict[str, Any]:
        """
        Build social graph from found profiles.

        Attempts to find connections between platforms.
        """
        # First check all platforms
        found = self.username_check(username, quick=True)

        graph = {
            "username": username,
            "profiles": found.get("found", {}),
            "profile_count": found.get("found_count", 0),
            "categories": {},
            "connections": [],
        }

        # Group by category
        for platform, data in graph["profiles"].items():
            cat = data.get("category", "unknown")
            if cat not in graph["categories"]:
                graph["categories"][cat] = []
            graph["categories"][cat].append(platform)

        # Suggest potential connections
        if "github" in graph["profiles"] and "linkedin" in graph["profiles"]:
            graph["connections"].append({
                "type": "professional",
                "platforms": ["github", "linkedin"],
                "confidence": "high"
            })

        if "twitter" in graph["profiles"] and "instagram" in graph["profiles"]:
            graph["connections"].append({
                "type": "social",
                "platforms": ["twitter", "instagram"],
                "confidence": "high"
            })

        return graph
