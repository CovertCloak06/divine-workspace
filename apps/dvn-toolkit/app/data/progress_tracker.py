"""
Progress Tracker - Tracks user progress through learning paths
Persists completion status for paths and lessons
"""

import os
import json
from datetime import datetime


def _get_data_dir():
    """Get the data directory, creating if needed"""
    try:
        from android.storage import app_storage_path
        base = app_storage_path()
    except ImportError:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    data_dir = os.path.join(base, 'data')
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


class ProgressTracker:
    """Track learning progress across paths and lessons"""

    FILENAME = 'learning_progress.json'

    def __init__(self):
        self._progress = {
            'paths': {},  # path_id -> {started, completed, current_lesson}
            'lessons': {},  # lesson_id -> {completed, completed_at, notes}
            'stats': {
                'total_lessons_completed': 0,
                'total_time_spent': 0,
                'current_streak': 0,
                'last_activity': None
            }
        }
        self._load()

    def _load(self):
        """Load progress from disk"""
        try:
            path = os.path.join(_get_data_dir(), self.FILENAME)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                    self._progress.update(data)
        except Exception:
            pass

    def _save(self):
        """Save progress to disk"""
        try:
            path = os.path.join(_get_data_dir(), self.FILENAME)
            with open(path, 'w') as f:
                json.dump(self._progress, f, indent=2)
        except Exception:
            pass

    def start_path(self, path_id: str):
        """Mark a path as started"""
        if path_id not in self._progress['paths']:
            self._progress['paths'][path_id] = {
                'started': datetime.now().isoformat(),
                'completed': None,
                'current_lesson': 0
            }
            self._save()

    def complete_lesson(self, path_id: str, lesson_id: str, lesson_index: int):
        """Mark a lesson as completed"""
        # Mark lesson complete
        self._progress['lessons'][lesson_id] = {
            'completed': True,
            'completed_at': datetime.now().isoformat(),
            'path_id': path_id
        }

        # Update path progress
        if path_id in self._progress['paths']:
            path_progress = self._progress['paths'][path_id]
            if lesson_index >= path_progress.get('current_lesson', 0):
                path_progress['current_lesson'] = lesson_index + 1

        # Update stats
        self._progress['stats']['total_lessons_completed'] += 1
        self._progress['stats']['last_activity'] = datetime.now().isoformat()

        self._save()

    def complete_path(self, path_id: str):
        """Mark a path as fully completed"""
        if path_id in self._progress['paths']:
            self._progress['paths'][path_id]['completed'] = datetime.now().isoformat()
            self._save()

    def is_lesson_complete(self, lesson_id: str) -> bool:
        """Check if a lesson is completed"""
        return self._progress['lessons'].get(lesson_id, {}).get('completed', False)

    def is_path_started(self, path_id: str) -> bool:
        """Check if a path has been started"""
        return path_id in self._progress['paths']

    def is_path_complete(self, path_id: str) -> bool:
        """Check if a path is fully completed"""
        path_data = self._progress['paths'].get(path_id, {})
        return path_data.get('completed') is not None

    def get_path_progress(self, path_id: str, total_lessons: int) -> dict:
        """Get progress info for a path"""
        path_data = self._progress['paths'].get(path_id, {})
        current = path_data.get('current_lesson', 0)

        return {
            'started': path_data.get('started'),
            'completed': path_data.get('completed'),
            'current_lesson': current,
            'total_lessons': total_lessons,
            'percentage': int((current / total_lessons) * 100) if total_lessons > 0 else 0
        }

    def get_current_lesson_index(self, path_id: str) -> int:
        """Get the current lesson index for a path"""
        return self._progress['paths'].get(path_id, {}).get('current_lesson', 0)

    def get_stats(self) -> dict:
        """Get overall learning stats"""
        return dict(self._progress['stats'])

    def get_completed_paths_count(self) -> int:
        """Get count of completed paths"""
        return sum(
            1 for p in self._progress['paths'].values()
            if p.get('completed')
        )

    def get_completed_lessons_count(self) -> int:
        """Get total completed lessons"""
        return self._progress['stats']['total_lessons_completed']

    def reset_path(self, path_id: str):
        """Reset progress for a specific path"""
        if path_id in self._progress['paths']:
            # Find and remove associated lessons
            lessons_to_remove = [
                lid for lid, data in self._progress['lessons'].items()
                if data.get('path_id') == path_id
            ]
            for lid in lessons_to_remove:
                del self._progress['lessons'][lid]
                self._progress['stats']['total_lessons_completed'] -= 1

            del self._progress['paths'][path_id]
            self._save()

    def reset_all(self):
        """Reset all progress"""
        self._progress = {
            'paths': {},
            'lessons': {},
            'stats': {
                'total_lessons_completed': 0,
                'total_time_spent': 0,
                'current_streak': 0,
                'last_activity': None
            }
        }
        self._save()


# Singleton instance
_progress_tracker = None


def get_progress_tracker() -> ProgressTracker:
    """Get the progress tracker singleton"""
    global _progress_tracker
    if _progress_tracker is None:
        _progress_tracker = ProgressTracker()
    return _progress_tracker
