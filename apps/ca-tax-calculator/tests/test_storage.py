"""Tests for storage module."""

import sys
import os
import tempfile
import stat
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Override DATA_DIR before importing storage
import storage
_tmpdir = tempfile.mkdtemp()
storage.DATA_DIR = Path(_tmpdir) / ".ca-tax-calc"
storage.DRAFT_FILE = storage.DATA_DIR / "draft.json"
storage.PROFILES_DIR = storage.DATA_DIR / "profiles"
storage.RESULTS_DIR = storage.DATA_DIR / "results"

from storage import (
    save_draft, load_draft, clear_draft, format_draft_summary,
    save_profile, load_profile, list_profiles, delete_profile,
    save_result, list_results,
    _ensure_dirs,
)


def test_dirs_created_with_permissions():
    _ensure_dirs()
    assert storage.DATA_DIR.exists()
    assert storage.PROFILES_DIR.exists()
    assert storage.RESULTS_DIR.exists()
    # Check owner-only permissions
    mode = storage.DATA_DIR.stat().st_mode
    assert mode & stat.S_IRWXU == stat.S_IRWXU  # owner has full access
    assert mode & stat.S_IRWXG == 0  # no group access
    assert mode & stat.S_IRWXO == 0  # no other access


def test_save_and_load_draft():
    fields = {"filing_status": "single", "gross_income": 85000}
    save_draft(fields)
    draft = load_draft()
    assert draft is not None
    assert draft["fields"]["gross_income"] == 85000
    assert draft["completed_count"] == 2


def test_clear_draft():
    save_draft({"filing_status": "single"})
    assert load_draft() is not None
    clear_draft()
    assert load_draft() is None


def test_format_draft_summary():
    fields = {"filing_status": "single", "gross_income": 85000, "hourly_rate": 25}
    save_draft(fields)
    draft = load_draft()
    summary = format_draft_summary(draft)
    assert "Single" in summary
    assert "85,000" in summary
    assert "$25" in summary


def test_save_and_load_profile():
    save_profile("test_profile", {"filing_status": "single", "hourly_rate": 30})
    data = load_profile("test_profile")
    assert data is not None
    assert data["hourly_rate"] == 30


def test_list_profiles():
    save_profile("profile_a", {"filing_status": "single"})
    save_profile("profile_b", {"filing_status": "married"})
    profiles = list_profiles()
    assert "profile_a" in profiles
    assert "profile_b" in profiles


def test_delete_profile():
    save_profile("to_delete", {"filing_status": "single"})
    assert delete_profile("to_delete") is True
    assert load_profile("to_delete") is None
    assert delete_profile("nonexistent") is False


def test_load_missing_profile():
    assert load_profile("does_not_exist") is None


def test_save_and_list_results():
    result = {"summary": {"gross_income": 85000, "take_home": 63000}}
    inputs = {"gross_income": 85000}
    save_result(result, inputs)
    results = list_results()
    assert len(results) >= 1
    assert results[0]["inputs"]["gross_income"] == 85000


def test_file_permissions():
    """Saved files should be owner-readable only (600)."""
    save_draft({"test": True})
    mode = storage.DRAFT_FILE.stat().st_mode
    assert mode & stat.S_IRUSR  # owner can read
    assert mode & stat.S_IWUSR  # owner can write
    assert not (mode & stat.S_IRGRP)  # no group read
    assert not (mode & stat.S_IROTH)  # no other read


# Cleanup
import shutil
import atexit
atexit.register(lambda: shutil.rmtree(_tmpdir, ignore_errors=True))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
