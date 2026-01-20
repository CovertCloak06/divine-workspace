"""
Recon Profiles - Storage and export for Identity Recon results
Persists profiles to JSON and supports multiple export formats
"""

import os
import json
import uuid
from datetime import datetime


def _get_profiles_dir():
    """Get the profiles directory, creating if needed"""
    try:
        from android.storage import app_storage_path
        base = app_storage_path()
    except ImportError:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    profiles_dir = os.path.join(base, 'recon_profiles')
    os.makedirs(profiles_dir, exist_ok=True)
    return profiles_dir


class ReconProfile:
    """Represents a single recon profile/investigation"""

    def __init__(self, profile_id=None):
        self.id = profile_id or str(uuid.uuid4())[:8]
        self.created = datetime.now().isoformat()
        self.updated = self.created
        self.input_value = ''
        self.input_type = ''
        self.input_details = {}
        self.scan_profile = 'standard'
        self.status = 'pending'  # pending, running, complete, error
        self.tools_completed = 0
        self.tools_total = 0
        self.results = {}  # tool_id -> result data
        self.summary = {}
        self.notes = ''

    def to_dict(self) -> dict:
        """Convert profile to dictionary"""
        return {
            'id': self.id,
            'created': self.created,
            'updated': self.updated,
            'input_value': self.input_value,
            'input_type': self.input_type,
            'input_details': self.input_details,
            'scan_profile': self.scan_profile,
            'status': self.status,
            'tools_completed': self.tools_completed,
            'tools_total': self.tools_total,
            'results': self.results,
            'summary': self.summary,
            'notes': self.notes
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ReconProfile':
        """Create profile from dictionary"""
        profile = cls(profile_id=data.get('id'))
        profile.created = data.get('created', profile.created)
        profile.updated = data.get('updated', profile.updated)
        profile.input_value = data.get('input_value', '')
        profile.input_type = data.get('input_type', '')
        profile.input_details = data.get('input_details', {})
        profile.scan_profile = data.get('scan_profile', 'standard')
        profile.status = data.get('status', 'pending')
        profile.tools_completed = data.get('tools_completed', 0)
        profile.tools_total = data.get('tools_total', 0)
        profile.results = data.get('results', {})
        profile.summary = data.get('summary', {})
        profile.notes = data.get('notes', '')
        return profile

    def add_result(self, tool_id: str, output: str, status: str = 'complete'):
        """Add a tool result to the profile"""
        self.results[tool_id] = {
            'status': status,
            'output': output,
            'timestamp': datetime.now().isoformat()
        }
        self.tools_completed += 1
        self.updated = datetime.now().isoformat()

    def export_json(self) -> str:
        """Export profile as JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    def export_text(self) -> str:
        """Export profile as readable text report"""
        lines = [
            "=" * 60,
            f"IDENTITY RECON REPORT",
            f"ID: {self.id}",
            f"Generated: {self.created}",
            "=" * 60,
            "",
            f"TARGET: {self.input_value}",
            f"TYPE: {self.input_type.upper()}",
            f"SCAN: {self.scan_profile}",
            "",
            "-" * 60,
            "RESULTS",
            "-" * 60,
        ]

        for tool_id, result in self.results.items():
            lines.append(f"\n[{tool_id.upper()}]")
            lines.append(f"Status: {result.get('status', 'unknown')}")
            lines.append(f"Time: {result.get('timestamp', 'N/A')}")
            lines.append("Output:")
            lines.append(result.get('output', 'No output'))
            lines.append("")

        if self.notes:
            lines.extend([
                "-" * 60,
                "NOTES",
                "-" * 60,
                self.notes
            ])

        lines.extend([
            "",
            "=" * 60,
            "END OF REPORT",
            "=" * 60
        ])

        return "\n".join(lines)


class ProfilesManager:
    """Manage saved recon profiles"""

    INDEX_FILE = 'profiles_index.json'

    def __init__(self):
        self._index = []
        self._load_index()

    def _load_index(self):
        """Load profiles index from disk"""
        try:
            path = os.path.join(_get_profiles_dir(), self.INDEX_FILE)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    self._index = json.load(f)
        except Exception:
            self._index = []

    def _save_index(self):
        """Save profiles index to disk"""
        try:
            path = os.path.join(_get_profiles_dir(), self.INDEX_FILE)
            with open(path, 'w') as f:
                json.dump(self._index, f, indent=2)
        except Exception:
            pass

    def save_profile(self, profile: ReconProfile):
        """Save a profile to disk"""
        try:
            # Save profile file
            filename = f"profile_{profile.id}.json"
            path = os.path.join(_get_profiles_dir(), filename)
            with open(path, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)

            # Update index
            entry = {
                'id': profile.id,
                'input_value': profile.input_value,
                'input_type': profile.input_type,
                'created': profile.created,
                'status': profile.status
            }

            # Remove existing entry if present
            self._index = [e for e in self._index if e['id'] != profile.id]
            self._index.insert(0, entry)

            # Keep only last 50 profiles
            self._index = self._index[:50]
            self._save_index()

            return True
        except Exception:
            return False

    def load_profile(self, profile_id: str) -> ReconProfile:
        """Load a profile from disk"""
        try:
            filename = f"profile_{profile_id}.json"
            path = os.path.join(_get_profiles_dir(), filename)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                    return ReconProfile.from_dict(data)
        except Exception:
            pass
        return None

    def delete_profile(self, profile_id: str) -> bool:
        """Delete a profile"""
        try:
            filename = f"profile_{profile_id}.json"
            path = os.path.join(_get_profiles_dir(), filename)
            if os.path.exists(path):
                os.remove(path)
            self._index = [e for e in self._index if e['id'] != profile_id]
            self._save_index()
            return True
        except Exception:
            return False

    def get_all(self) -> list:
        """Get all profile summaries"""
        return list(self._index)

    def get_recent(self, limit: int = 5) -> list:
        """Get recent profile summaries"""
        return self._index[:limit]


# Singleton instance
_profiles_manager = None


def get_profiles_manager() -> ProfilesManager:
    """Get the profiles manager singleton"""
    global _profiles_manager
    if _profiles_manager is None:
        _profiles_manager = ProfilesManager()
    return _profiles_manager
