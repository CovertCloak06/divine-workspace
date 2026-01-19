#!/usr/bin/env python3
"""
Shadow OSINT - Person Profiler
Builds profiles with probability ratings from available information
Supports immediate profile generation or incremental building over time
"""

import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict


@dataclass
class ProfileField:
    """A single piece of profile information with confidence."""
    value: Any
    confidence: float  # 0.0 to 1.0
    source: str  # Where this info came from
    verified: bool = False
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProfileLink:
    """A confirmed or suspected online account."""
    platform: str
    url: str
    username: str
    confidence: float
    verified: bool = False
    last_checked: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class PersonProfile:
    """
    A person profile that builds over time with confidence ratings.
    """

    def __init__(self, profile_id: str = None):
        self.profile_id = profile_id or self._generate_id()
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at

        # Core identity fields
        self.names: List[ProfileField] = []
        self.ages: List[ProfileField] = []
        self.locations: List[ProfileField] = []
        self.emails: List[ProfileField] = []
        self.phones: List[ProfileField] = []
        self.usernames: List[ProfileField] = []

        # Online presence
        self.accounts: List[ProfileLink] = []

        # Additional intel
        self.employers: List[ProfileField] = []
        self.education: List[ProfileField] = []
        self.associates: List[ProfileField] = []  # Related people
        self.notes: List[str] = []

        # Metadata
        self.search_history: List[Dict] = []
        self.overall_confidence: float = 0.0

    def _generate_id(self) -> str:
        """Generate unique profile ID."""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]

    def add_name(
        self,
        name: str,
        confidence: float = 0.5,
        source: str = "user_input",
        verified: bool = False
    ):
        """Add a name with confidence score."""
        # Check for duplicates
        for existing in self.names:
            if existing.value.lower() == name.lower():
                # Update if higher confidence
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.source = source
                    existing.verified = verified or existing.verified
                return

        self.names.append(ProfileField(
            value=name,
            confidence=confidence,
            source=source,
            verified=verified
        ))
        self._recalculate_confidence()

    def add_age(
        self,
        age: int,
        confidence: float = 0.5,
        source: str = "user_input"
    ):
        """Add age estimate with confidence."""
        self.ages.append(ProfileField(
            value=age,
            confidence=confidence,
            source=source
        ))
        self._recalculate_confidence()

    def add_location(
        self,
        city: str = None,
        state: str = None,
        country: str = "US",
        confidence: float = 0.5,
        source: str = "user_input"
    ):
        """Add location with confidence."""
        location = {
            "city": city,
            "state": state,
            "country": country
        }
        self.locations.append(ProfileField(
            value=location,
            confidence=confidence,
            source=source
        ))
        self._recalculate_confidence()

    def add_email(
        self,
        email: str,
        confidence: float = 0.5,
        source: str = "generated",
        verified: bool = False
    ):
        """Add email with confidence."""
        for existing in self.emails:
            if existing.value.lower() == email.lower():
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.verified = verified or existing.verified
                return

        self.emails.append(ProfileField(
            value=email,
            confidence=confidence,
            source=source,
            verified=verified
        ))
        self._recalculate_confidence()

    def add_phone(
        self,
        phone: str,
        confidence: float = 0.5,
        source: str = "user_input",
        verified: bool = False
    ):
        """Add phone with confidence."""
        self.phones.append(ProfileField(
            value=phone,
            confidence=confidence,
            source=source,
            verified=verified
        ))
        self._recalculate_confidence()

    def add_username(
        self,
        username: str,
        confidence: float = 0.3,
        source: str = "generated"
    ):
        """Add possible username."""
        for existing in self.usernames:
            if existing.value.lower() == username.lower():
                if confidence > existing.confidence:
                    existing.confidence = confidence
                return

        self.usernames.append(ProfileField(
            value=username,
            confidence=confidence,
            source=source
        ))

    def add_account(
        self,
        platform: str,
        url: str,
        username: str,
        confidence: float = 0.7,
        verified: bool = False
    ):
        """Add confirmed/suspected online account."""
        for existing in self.accounts:
            if existing.url == url:
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.verified = verified or existing.verified
                return

        self.accounts.append(ProfileLink(
            platform=platform,
            url=url,
            username=username,
            confidence=confidence,
            verified=verified
        ))

        # Boost username confidence if account found
        self.add_username(username, confidence=confidence, source=f"found_on_{platform}")
        self._recalculate_confidence()

    def add_employer(
        self,
        employer: str,
        confidence: float = 0.5,
        source: str = "user_input"
    ):
        """Add employer with confidence."""
        self.employers.append(ProfileField(
            value=employer,
            confidence=confidence,
            source=source
        ))
        self._recalculate_confidence()

    def add_note(self, note: str):
        """Add investigator note."""
        self.notes.append(f"[{datetime.utcnow().isoformat()}] {note}")

    def log_search(self, search_type: str, query: str, results_count: int):
        """Log a search performed on this profile."""
        self.search_history.append({
            "type": search_type,
            "query": query,
            "results": results_count,
            "timestamp": datetime.utcnow().isoformat()
        })

    def _recalculate_confidence(self):
        """Recalculate overall profile confidence."""
        scores = []

        # Weight different fields
        if self.names:
            scores.append(max(n.confidence for n in self.names) * 1.5)
        if self.ages:
            scores.append(max(a.confidence for a in self.ages) * 0.5)
        if self.locations:
            scores.append(max(l.confidence for l in self.locations) * 1.0)
        if self.emails:
            verified = [e for e in self.emails if e.verified]
            if verified:
                scores.append(1.0 * 1.5)  # Verified email is strong
            else:
                scores.append(max(e.confidence for e in self.emails) * 1.0)
        if self.phones:
            scores.append(max(p.confidence for p in self.phones) * 1.2)
        if self.accounts:
            verified = [a for a in self.accounts if a.verified]
            if verified:
                scores.append(len(verified) * 0.2)  # Each verified account adds
            scores.append(max(a.confidence for a in self.accounts) * 1.0)

        if scores:
            self.overall_confidence = min(sum(scores) / len(scores), 1.0)
        else:
            self.overall_confidence = 0.0

        self.updated_at = datetime.utcnow().isoformat()

    def get_best_name(self) -> Optional[str]:
        """Get highest confidence name."""
        if not self.names:
            return None
        return max(self.names, key=lambda x: x.confidence).value

    def get_probable_age(self) -> Optional[int]:
        """Get most probable age."""
        if not self.ages:
            return None
        return max(self.ages, key=lambda x: x.confidence).value

    def get_best_location(self) -> Optional[Dict]:
        """Get highest confidence location."""
        if not self.locations:
            return None
        return max(self.locations, key=lambda x: x.confidence).value

    def get_verified_accounts(self) -> List[ProfileLink]:
        """Get all verified accounts."""
        return [a for a in self.accounts if a.verified]

    def get_high_confidence_data(self, threshold: float = 0.7) -> Dict:
        """Get all data above confidence threshold."""
        return {
            "names": [n.to_dict() for n in self.names if n.confidence >= threshold],
            "emails": [e.to_dict() for e in self.emails if e.confidence >= threshold],
            "phones": [p.to_dict() for p in self.phones if p.confidence >= threshold],
            "accounts": [a.to_dict() for a in self.accounts if a.confidence >= threshold],
            "locations": [l.to_dict() for l in self.locations if l.confidence >= threshold],
        }

    def to_dict(self) -> Dict:
        """Export profile as dictionary."""
        return {
            "profile_id": self.profile_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "overall_confidence": round(self.overall_confidence, 2),
            "summary": {
                "best_name": self.get_best_name(),
                "probable_age": self.get_probable_age(),
                "best_location": self.get_best_location(),
                "verified_accounts": len(self.get_verified_accounts()),
                "total_accounts": len(self.accounts),
            },
            "identity": {
                "names": [n.to_dict() for n in self.names],
                "ages": [a.to_dict() for a in self.ages],
                "locations": [l.to_dict() for l in self.locations],
            },
            "contact": {
                "emails": [e.to_dict() for e in self.emails],
                "phones": [p.to_dict() for p in self.phones],
            },
            "online_presence": {
                "usernames": [u.to_dict() for u in sorted(
                    self.usernames, key=lambda x: x.confidence, reverse=True
                )[:20]],  # Top 20
                "accounts": [a.to_dict() for a in sorted(
                    self.accounts, key=lambda x: x.confidence, reverse=True
                )],
            },
            "additional": {
                "employers": [e.to_dict() for e in self.employers],
                "education": [e.to_dict() for e in self.education],
                "associates": [a.to_dict() for a in self.associates],
            },
            "metadata": {
                "notes": self.notes,
                "search_history": self.search_history[-10:],  # Last 10
            }
        }

    def to_json(self, indent: int = 2) -> str:
        """Export profile as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class Profiler:
    """
    Main profiler class - builds and manages profiles.
    """

    def __init__(self, storage_dir: str = None):
        self.storage_dir = Path(storage_dir) if storage_dir else Path.home() / ".shadow_profiles"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.active_profiles: Dict[str, PersonProfile] = {}

    def create_profile(
        self,
        name: str = None,
        age: int = None,
        city: str = None,
        state: str = None,
        email: str = None,
        phone: str = None,
        usernames: List[str] = None
    ) -> PersonProfile:
        """
        Create a new profile with initial information.
        Returns profile with generated usernames, emails, and confidence scores.
        """
        profile = PersonProfile()

        # Add provided info with high confidence (user input)
        if name:
            profile.add_name(name, confidence=0.9, source="user_input")

            # Generate usernames from name
            from .people import PeopleSearch
            people = PeopleSearch()
            parts = name.strip().split()
            first = parts[0].lower() if parts else ""
            last = parts[-1].lower() if len(parts) > 1 else ""

            birth_years = []
            if age:
                current_year = datetime.now().year
                base_year = current_year - age
                birth_years = list(range(base_year - 3, base_year + 4))

            generated_usernames = people._generate_usernames(first, last, birth_years)
            for username in generated_usernames[:30]:
                profile.add_username(username, confidence=0.3, source="generated_from_name")

            # Generate possible emails
            generated_emails = people._generate_emails(first, last, birth_years)
            for email_addr in generated_emails[:20]:
                profile.add_email(email_addr, confidence=0.2, source="generated_from_name")

        if age:
            profile.add_age(age, confidence=0.8, source="user_input")

        if city or state:
            profile.add_location(city=city, state=state, confidence=0.8, source="user_input")

        if email:
            profile.add_email(email, confidence=0.9, source="user_input", verified=False)

        if phone:
            profile.add_phone(phone, confidence=0.9, source="user_input")

        if usernames:
            for username in usernames:
                profile.add_username(username, confidence=0.7, source="user_input")

        self.active_profiles[profile.profile_id] = profile
        return profile

    def enrich_with_username_hunt(
        self,
        profile: PersonProfile,
        username: str
    ) -> PersonProfile:
        """
        Enrich profile by hunting for a username across platforms.
        Updates profile with found accounts.
        """
        from .person import PersonRecon
        person = PersonRecon()

        results = person.username_check(username, quick=False)
        found = results.get("found", {})

        profile.log_search("username_hunt", username, len(found))

        for platform, data in found.items():
            profile.add_account(
                platform=platform,
                url=data.get("url", ""),
                username=username,
                confidence=0.85,  # Found = high confidence
                verified=True
            )

        return profile

    def enrich_with_email_check(
        self,
        profile: PersonProfile,
        email: str
    ) -> PersonProfile:
        """
        Enrich profile by checking an email address.
        """
        from .person import PersonRecon
        person = PersonRecon()

        results = person.email_recon(email)

        profile.log_search("email_recon", email, 1 if results.get("success") else 0)

        # Update email confidence based on findings
        checks = results.get("checks", {})

        if checks.get("mx", {}).get("has_mx"):
            # Valid MX = higher confidence
            for e in profile.emails:
                if e.value.lower() == email.lower():
                    e.confidence = min(e.confidence + 0.2, 0.9)

        if checks.get("gravatar", {}).get("exists"):
            profile.add_account(
                platform="Gravatar",
                url=checks["gravatar"].get("url", ""),
                username=email.split("@")[0],
                confidence=0.9,
                verified=True
            )

        if checks.get("breaches", {}).get("found_in_breaches"):
            profile.add_note(f"Email {email} found in {checks['breaches'].get('breach_count', 0)} breaches")

        return profile

    def save_profile(self, profile: PersonProfile) -> str:
        """Save profile to disk."""
        filepath = self.storage_dir / f"{profile.profile_id}.json"
        with open(filepath, "w") as f:
            f.write(profile.to_json())
        return str(filepath)

    def load_profile(self, profile_id: str) -> Optional[PersonProfile]:
        """Load profile from disk."""
        filepath = self.storage_dir / f"{profile_id}.json"
        if not filepath.exists():
            return None

        with open(filepath) as f:
            data = json.load(f)

        # Reconstruct profile
        profile = PersonProfile(profile_id=data["profile_id"])
        profile.created_at = data["created_at"]
        profile.updated_at = data["updated_at"]

        # This is simplified - full reconstruction would need more work
        # For now, return basic profile info
        return profile

    def list_profiles(self) -> List[Dict]:
        """List all saved profiles."""
        profiles = []
        for filepath in self.storage_dir.glob("*.json"):
            try:
                with open(filepath) as f:
                    data = json.load(f)
                profiles.append({
                    "profile_id": data.get("profile_id"),
                    "best_name": data.get("summary", {}).get("best_name"),
                    "overall_confidence": data.get("overall_confidence"),
                    "updated_at": data.get("updated_at"),
                })
            except Exception:
                pass
        return profiles

    def get_profile_summary(self, profile: PersonProfile) -> Dict:
        """Get a condensed summary of a profile."""
        return {
            "profile_id": profile.profile_id,
            "confidence": f"{profile.overall_confidence * 100:.0f}%",
            "name": profile.get_best_name(),
            "age": profile.get_probable_age(),
            "location": profile.get_best_location(),
            "emails": len(profile.emails),
            "verified_emails": len([e for e in profile.emails if e.verified]),
            "accounts_found": len(profile.accounts),
            "verified_accounts": len(profile.get_verified_accounts()),
            "possible_usernames": len(profile.usernames),
        }
