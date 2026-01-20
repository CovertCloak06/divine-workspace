"""
Persistence Layer - Favorites, recents, settings storage
Uses JSON file storage for Android compatibility
"""

import os
import json
from datetime import datetime


def _get_data_dir():
    """Get the data directory, creating if needed"""
    # Try Android storage first
    try:
        from android.storage import app_storage_path
        base = app_storage_path()
    except ImportError:
        # Fallback for desktop
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    data_dir = os.path.join(base, 'data')
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def _get_file_path(filename):
    """Get full path for a data file"""
    return os.path.join(_get_data_dir(), filename)


class FavoritesManager:
    """Manage tool favorites"""

    FILENAME = 'favorites.json'

    def __init__(self):
        self._favorites = set()
        self._load()

    def _load(self):
        """Load favorites from disk"""
        try:
            path = _get_file_path(self.FILENAME)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                    self._favorites = set(data.get('favorites', []))
        except Exception:
            self._favorites = set()

    def _save(self):
        """Save favorites to disk"""
        try:
            path = _get_file_path(self.FILENAME)
            with open(path, 'w') as f:
                json.dump({'favorites': list(self._favorites)}, f)
        except Exception:
            pass

    def add(self, tool_id):
        """Add a tool to favorites"""
        self._favorites.add(tool_id)
        self._save()

    def remove(self, tool_id):
        """Remove a tool from favorites"""
        self._favorites.discard(tool_id)
        self._save()

    def toggle(self, tool_id):
        """Toggle favorite status, returns new state"""
        if tool_id in self._favorites:
            self.remove(tool_id)
            return False
        else:
            self.add(tool_id)
            return True

    def is_favorite(self, tool_id):
        """Check if a tool is favorited"""
        return tool_id in self._favorites

    def get_all(self):
        """Get all favorite tool IDs"""
        return list(self._favorites)


class RecentsManager:
    """Manage recently used tools"""

    FILENAME = 'recents.json'
    MAX_RECENTS = 10

    def __init__(self):
        self._recents = []  # List of {tool_id, timestamp}
        self._load()

    def _load(self):
        """Load recents from disk"""
        try:
            path = _get_file_path(self.FILENAME)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                    self._recents = data.get('recents', [])
        except Exception:
            self._recents = []

    def _save(self):
        """Save recents to disk"""
        try:
            path = _get_file_path(self.FILENAME)
            with open(path, 'w') as f:
                json.dump({'recents': self._recents}, f)
        except Exception:
            pass

    def add(self, tool_id):
        """Add a tool to recents (moves to front if exists)"""
        # Remove if exists
        self._recents = [r for r in self._recents if r['tool_id'] != tool_id]
        # Add to front
        self._recents.insert(0, {
            'tool_id': tool_id,
            'timestamp': datetime.now().isoformat()
        })
        # Trim to max
        self._recents = self._recents[:self.MAX_RECENTS]
        self._save()

    def get_all(self):
        """Get all recent tool IDs in order"""
        return [r['tool_id'] for r in self._recents]

    def clear(self):
        """Clear all recents"""
        self._recents = []
        self._save()


class SettingsManager:
    """Manage app settings"""

    FILENAME = 'settings.json'

    DEFAULTS = {
        'theme': 'cyberpunk',
        'show_descriptions': True,
        'confirm_before_run': False,
        'save_output_history': True,
        'output_font_size': 12,
    }

    def __init__(self):
        self._settings = dict(self.DEFAULTS)
        self._load()

    def _load(self):
        """Load settings from disk"""
        try:
            path = _get_file_path(self.FILENAME)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                    self._settings.update(data)
        except Exception:
            pass

    def _save(self):
        """Save settings to disk"""
        try:
            path = _get_file_path(self.FILENAME)
            with open(path, 'w') as f:
                json.dump(self._settings, f, indent=2)
        except Exception:
            pass

    def get(self, key, default=None):
        """Get a setting value"""
        return self._settings.get(key, default or self.DEFAULTS.get(key))

    def set(self, key, value):
        """Set a setting value"""
        self._settings[key] = value
        self._save()

    def get_all(self):
        """Get all settings"""
        return dict(self._settings)

    def reset(self):
        """Reset to defaults"""
        self._settings = dict(self.DEFAULTS)
        self._save()


class PresetsManager:
    """Manage tool presets/templates"""

    FILENAME = 'presets.json'

    def __init__(self):
        self._presets = {}  # tool_id -> list of presets
        self._load()

    def _load(self):
        """Load presets from disk"""
        try:
            path = _get_file_path(self.FILENAME)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    self._presets = json.load(f)
        except Exception:
            self._presets = {}

    def _save(self):
        """Save presets to disk"""
        try:
            path = _get_file_path(self.FILENAME)
            with open(path, 'w') as f:
                json.dump(self._presets, f, indent=2)
        except Exception:
            pass

    def get_for_tool(self, tool_id):
        """Get presets for a specific tool"""
        return self._presets.get(tool_id, [])

    def add_preset(self, tool_id, name, values):
        """Add a custom preset for a tool"""
        if tool_id not in self._presets:
            self._presets[tool_id] = []
        self._presets[tool_id].append({
            'name': name,
            'values': values,
            'custom': True
        })
        self._save()

    def remove_preset(self, tool_id, preset_name):
        """Remove a custom preset"""
        if tool_id in self._presets:
            self._presets[tool_id] = [
                p for p in self._presets[tool_id]
                if not (p.get('custom') and p['name'] == preset_name)
            ]
            self._save()


# Singleton instances for app-wide access
_favorites = None
_recents = None
_settings = None
_presets = None


def get_favorites():
    """Get the favorites manager singleton"""
    global _favorites
    if _favorites is None:
        _favorites = FavoritesManager()
    return _favorites


def get_recents():
    """Get the recents manager singleton"""
    global _recents
    if _recents is None:
        _recents = RecentsManager()
    return _recents


def get_settings():
    """Get the settings manager singleton"""
    global _settings
    if _settings is None:
        _settings = SettingsManager()
    return _settings


def get_presets():
    """Get the presets manager singleton"""
    global _presets
    if _presets is None:
        _presets = PresetsManager()
    return _presets
