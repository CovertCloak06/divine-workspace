#!/usr/bin/env python3
"""
Shadow OSINT - People Search
Search by name, age, location - generate dorks and username variations
"""

import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import quote


class PeopleSearch:
    """Name-based person search and correlation."""

    def __init__(self):
        # Common username patterns
        self.username_patterns = [
            "{first}{last}",           # johnsmith
            "{first}.{last}",          # john.smith
            "{first}_{last}",          # john_smith
            "{first}-{last}",          # john-smith
            "{f}{last}",               # jsmith
            "{first}{l}",              # johns
            "{last}{first}",           # smithjohn
            "{last}.{first}",          # smith.john
            "{last}_{first}",          # smith_john
            "{first}{last}{yy}",       # johnsmith90
            "{first}.{last}{yy}",      # john.smith90
            "{f}{last}{yy}",           # jsmith90
            "{first}{yy}",             # john90
            "{last}{yy}",              # smith90
            "{first}{yyyy}",           # john1990
            "{first}_{yy}",            # john_90
            "{first}{last}{birth_yy}", # johnsmith90 (birth year)
        ]

        # Common email domains
        self.email_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "icloud.com", "protonmail.com", "aol.com", "mail.com",
            "live.com", "msn.com", "ymail.com", "proton.me"
        ]

    def search_person(
        self,
        name: str,
        age: int = None,
        city: str = None,
        state: str = None,
        country: str = "US"
    ) -> Dict[str, Any]:
        """
        Search for a person by name with optional age and location.

        Args:
            name: Full name (e.g., "John Smith")
            age: Approximate age (generates birth year range ±3 years)
            city: City name
            state: State/province
            country: Country code (default US)
        """
        # Parse name
        name_parts = self._parse_name(name)
        first = name_parts["first"]
        last = name_parts["last"]
        middle = name_parts.get("middle", "")

        # Calculate birth year range from age
        birth_years = []
        if age:
            current_year = datetime.now().year
            base_year = current_year - age
            birth_years = list(range(base_year - 3, base_year + 4))

        # Build location string
        location = self._build_location(city, state, country)

        results = {
            "name": name,
            "parsed": name_parts,
            "age": age,
            "birth_year_range": birth_years,
            "location": location,
            "usernames": self._generate_usernames(first, last, birth_years),
            "emails": self._generate_emails(first, last, birth_years),
            "dorks": {
                "google": self._google_dorks(name, location, age),
                "social": self._social_dorks(name, location),
                "professional": self._professional_dorks(name, location),
                "records": self._records_dorks(name, location, birth_years),
            },
            "direct_links": self._direct_search_links(name, location),
        }

        return results

    def _parse_name(self, name: str) -> Dict[str, str]:
        """Parse full name into components."""
        parts = name.strip().split()

        if len(parts) == 1:
            return {"first": parts[0].lower(), "last": "", "full": name}
        elif len(parts) == 2:
            return {
                "first": parts[0].lower(),
                "last": parts[1].lower(),
                "full": name
            }
        else:
            return {
                "first": parts[0].lower(),
                "middle": " ".join(parts[1:-1]).lower(),
                "last": parts[-1].lower(),
                "full": name
            }

    def _build_location(
        self,
        city: str = None,
        state: str = None,
        country: str = "US"
    ) -> Dict[str, Any]:
        """Build location dict and search strings."""
        loc = {
            "city": city,
            "state": state,
            "country": country,
            "strings": []
        }

        if city and state:
            loc["strings"].append(f"{city}, {state}")
            loc["strings"].append(f"{city} {state}")
        if city:
            loc["strings"].append(city)
        if state:
            loc["strings"].append(state)

        return loc

    def _generate_usernames(
        self,
        first: str,
        last: str,
        birth_years: List[int]
    ) -> List[str]:
        """Generate possible username variations."""
        usernames = set()

        if not first:
            return []

        f = first[0] if first else ""
        l = last[0] if last else ""

        for pattern in self.username_patterns:
            try:
                # Base patterns (no year)
                if "{yy}" not in pattern and "{yyyy}" not in pattern and "{birth_yy}" not in pattern:
                    username = pattern.format(
                        first=first, last=last, f=f, l=l
                    )
                    if username and len(username) > 2:
                        usernames.add(username)

                # Year-based patterns
                elif birth_years:
                    for year in birth_years:
                        yy = str(year)[-2:]
                        yyyy = str(year)
                        try:
                            username = pattern.format(
                                first=first, last=last, f=f, l=l,
                                yy=yy, yyyy=yyyy, birth_yy=yy
                            )
                            if username and len(username) > 2:
                                usernames.add(username)
                        except KeyError:
                            pass
            except KeyError:
                pass

        # Add number suffixes (1, 2, 123, etc.)
        base_names = [f"{first}{last}", f"{f}{last}", f"{first}"]
        for base in base_names:
            if base:
                usernames.add(f"{base}1")
                usernames.add(f"{base}123")
                usernames.add(f"{base}007")
                usernames.add(f"{base}99")

        return sorted(list(usernames))[:50]  # Limit to top 50

    def _generate_emails(
        self,
        first: str,
        last: str,
        birth_years: List[int]
    ) -> List[str]:
        """Generate possible email addresses."""
        emails = []

        if not first:
            return []

        f = first[0]
        l = last[0] if last else ""

        # Email patterns
        patterns = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{f}{last}",
            f"{first}{l}",
            f"{last}{first}",
            f"{first}",
        ]

        # Add year variants
        if birth_years:
            year = birth_years[len(birth_years)//2]  # Middle year
            yy = str(year)[-2:]
            patterns.extend([
                f"{first}{last}{yy}",
                f"{first}.{last}{yy}",
                f"{f}{last}{yy}",
            ])

        # Generate for common domains
        for pattern in patterns:
            if pattern and last:  # Only full patterns for emails
                for domain in self.email_domains[:5]:  # Top 5 domains
                    emails.append(f"{pattern}@{domain}")

        return emails[:30]  # Limit to 30

    def _google_dorks(
        self,
        name: str,
        location: Dict,
        age: int = None
    ) -> List[Dict[str, str]]:
        """Generate Google search dorks."""
        dorks = []
        loc_str = location["strings"][0] if location["strings"] else ""

        # Basic name search
        dorks.append({
            "description": "Basic name search",
            "query": f'"{name}"',
            "url": f'https://www.google.com/search?q="{quote(name)}"'
        })

        # Name + location
        if loc_str:
            dorks.append({
                "description": "Name + location",
                "query": f'"{name}" "{loc_str}"',
                "url": f'https://www.google.com/search?q="{quote(name)}"+"{quote(loc_str)}"'
            })

        # Name + age indicator
        if age:
            birth_year = datetime.now().year - age
            dorks.append({
                "description": "Name + birth year",
                "query": f'"{name}" "{birth_year}" OR "born {birth_year}"',
                "url": f'https://www.google.com/search?q="{quote(name)}"+"{birth_year}"'
            })

        # Name + common info requests
        dorks.append({
            "description": "Name + contact info",
            "query": f'"{name}" (phone OR email OR address OR contact)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+(phone+OR+email+OR+address)'
        })

        # Name + social profiles
        dorks.append({
            "description": "Name + social media",
            "query": f'"{name}" (site:facebook.com OR site:linkedin.com OR site:twitter.com)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+(site:facebook.com+OR+site:linkedin.com)'
        })

        # Name + records
        dorks.append({
            "description": "Name + public records",
            "query": f'"{name}" (arrest OR court OR warrant OR mugshot)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+(arrest+OR+court+OR+records)'
        })

        return dorks

    def _social_dorks(self, name: str, location: Dict) -> List[Dict[str, str]]:
        """Generate social media search dorks."""
        dorks = []
        loc_str = location["strings"][0] if location["strings"] else ""

        platforms = [
            ("Facebook", "facebook.com"),
            ("Instagram", "instagram.com"),
            ("Twitter/X", "twitter.com"),
            ("TikTok", "tiktok.com"),
            ("LinkedIn", "linkedin.com"),
            ("Reddit", "reddit.com"),
        ]

        for platform, domain in platforms:
            query = f'site:{domain} "{name}"'
            if loc_str:
                query += f' "{loc_str}"'

            dorks.append({
                "description": f"{platform} search",
                "query": query,
                "url": f'https://www.google.com/search?q={quote(query)}'
            })

        return dorks

    def _professional_dorks(self, name: str, location: Dict) -> List[Dict[str, str]]:
        """Generate professional/employment search dorks."""
        dorks = []
        loc_str = location["strings"][0] if location["strings"] else ""

        # LinkedIn
        query = f'site:linkedin.com/in "{name}"'
        if loc_str:
            query += f' "{loc_str}"'
        dorks.append({
            "description": "LinkedIn profiles",
            "query": query,
            "url": f'https://www.google.com/search?q={quote(query)}'
        })

        # Company associations
        dorks.append({
            "description": "Employment mentions",
            "query": f'"{name}" (employee OR "works at" OR "working at" OR staff)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+(employee+OR+"works+at")'
        })

        # Professional licenses
        dorks.append({
            "description": "Professional licenses",
            "query": f'"{name}" (license OR licensed OR certification OR certified)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+(license+OR+certified)'
        })

        return dorks

    def _records_dorks(
        self,
        name: str,
        location: Dict,
        birth_years: List[int]
    ) -> List[Dict[str, str]]:
        """Generate public records search dorks."""
        dorks = []
        state = location.get("state", "")

        # Voter records
        if state:
            dorks.append({
                "description": f"Voter records ({state})",
                "query": f'"{name}" voter registration {state}',
                "url": f'https://www.google.com/search?q="{quote(name)}"+voter+{quote(state)}'
            })

        # Property records
        dorks.append({
            "description": "Property records",
            "query": f'"{name}" (property OR deed OR parcel OR homeowner)',
            "url": f'https://www.google.com/search?q="{quote(name)}"+property+records'
        })

        # Court records
        dorks.append({
            "description": "Court records",
            "query": f'"{name}" (court OR case OR plaintiff OR defendant) filetype:pdf',
            "url": f'https://www.google.com/search?q="{quote(name)}"+court+filetype:pdf'
        })

        # Obituaries (for relatives)
        dorks.append({
            "description": "Obituaries (find relatives)",
            "query": f'"{name}" (obituary OR "survived by" OR "preceded by")',
            "url": f'https://www.google.com/search?q="{quote(name)}"+obituary'
        })

        return dorks

    def _direct_search_links(self, name: str, location: Dict) -> List[Dict[str, str]]:
        """Generate direct links to people search engines."""
        encoded_name = quote(name)
        city = location.get("city", "")
        state = location.get("state", "")

        links = [
            {
                "site": "TruePeopleSearch",
                "url": f"https://www.truepeoplesearch.com/results?name={encoded_name}&citystatezip={quote(f'{city} {state}')}" if city else f"https://www.truepeoplesearch.com/results?name={encoded_name}",
                "note": "Free, US only"
            },
            {
                "site": "FastPeopleSearch",
                "url": f"https://www.fastpeoplesearch.com/name/{encoded_name.replace(' ', '-')}",
                "note": "Free, US only"
            },
            {
                "site": "That's Them",
                "url": f"https://thatsthem.com/name/{encoded_name.replace(' ', '-')}",
                "note": "Free, limited results"
            },
            {
                "site": "Whitepages",
                "url": f"https://www.whitepages.com/name/{encoded_name.replace(' ', '-')}/{quote(f'{city}-{state}')}" if city else f"https://www.whitepages.com/name/{encoded_name.replace(' ', '-')}",
                "note": "Free basic, paid details"
            },
            {
                "site": "Spokeo",
                "url": f"https://www.spokeo.com/{encoded_name.replace(' ', '-')}",
                "note": "Paid, comprehensive"
            },
            {
                "site": "Pipl",
                "url": f"https://pipl.com/search/?q={encoded_name}",
                "note": "Paid, global"
            },
            {
                "site": "FamilyTreeNow",
                "url": f"https://www.familytreenow.com/search/genealogy/results?first={quote(name.split()[0])}&last={quote(name.split()[-1])}",
                "note": "Free, US, includes relatives"
            },
            {
                "site": "Radaris",
                "url": f"https://radaris.com/p/{encoded_name.replace(' ', '-')}/",
                "note": "Free basic, US"
            },
        ]

        return links

    def correlate_findings(
        self,
        name: str,
        found_usernames: List[str] = None,
        found_emails: List[str] = None,
        found_phone: str = None
    ) -> Dict[str, Any]:
        """
        Take initial findings and generate more search vectors.

        Useful after finding a username - derive more searches.
        """
        results = {
            "original_name": name,
            "derived_searches": []
        }

        if found_usernames:
            for username in found_usernames:
                results["derived_searches"].append({
                    "type": "username",
                    "value": username,
                    "searches": [
                        f'"{username}" site:github.com',
                        f'"{username}" site:reddit.com',
                        f'"{username}" email',
                        f'"{username}" real name',
                    ]
                })

        if found_emails:
            for email in found_emails:
                domain = email.split("@")[1] if "@" in email else ""
                results["derived_searches"].append({
                    "type": "email",
                    "value": email,
                    "searches": [
                        f'"{email}"',
                        f'"{email}" site:linkedin.com',
                        f'"{email}" password OR leak OR breach',
                    ]
                })

        if found_phone:
            results["derived_searches"].append({
                "type": "phone",
                "value": found_phone,
                "searches": [
                    f'"{found_phone}"',
                    f'"{found_phone}" name',
                    f'"{found_phone}" address',
                ]
            })

        return results
