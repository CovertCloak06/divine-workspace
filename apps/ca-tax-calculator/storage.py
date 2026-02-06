"""Local storage for CA Tax Calculator - drafts, profiles, and data security.

All data stored in ~/.ca-tax-calc/ (never in the repo).
Sensitive financial data stays on the user's machine only.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path


DATA_DIR = Path.home() / ".ca-tax-calc"
DRAFT_FILE = DATA_DIR / "draft.json"
PROFILES_DIR = DATA_DIR / "profiles"
RESULTS_DIR = DATA_DIR / "results"


def _ensure_dirs():
    """Create data directories with restricted permissions (owner-only)."""
    for d in [DATA_DIR, PROFILES_DIR, RESULTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        # Owner read/write/execute only - no group or other access
        os.chmod(d, stat.S_IRWXU)


def _safe_write(path: Path, data: dict):
    """Write JSON with restricted file permissions."""
    _ensure_dirs()
    path.write_text(json.dumps(data, indent=2, default=str))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600: owner read/write only


def _safe_read(path: Path) -> dict | None:
    """Read JSON file, return None if missing or corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# --- Draft System (auto-save/resume) ---

# Fields in order of the interactive form
DRAFT_FIELDS = [
    "filing_status", "gross_income", "is_self_employed",
    "hourly_rate", "regular_hours", "overtime_hours", "double_time_hours",
    "health_premium", "employer_health_contribution",
    "medical_expenses", "mortgage_interest", "state_local_taxes",
    "charitable_donations",
]


def save_draft(fields: dict):
    """Save current progress to draft file."""
    draft = {
        "timestamp": datetime.now().isoformat(),
        "fields": fields,
        "completed_count": sum(1 for k in DRAFT_FIELDS if k in fields and fields[k]),
        "total_fields": len(DRAFT_FIELDS),
    }
    _safe_write(DRAFT_FILE, draft)


def load_draft() -> dict | None:
    """Load saved draft. Returns None if no draft exists."""
    return _safe_read(DRAFT_FILE)


def clear_draft():
    """Remove the draft file after successful calculation."""
    if DRAFT_FILE.exists():
        DRAFT_FILE.unlink()


def format_draft_summary(draft: dict) -> str:
    """Human-readable summary of a saved draft."""
    fields = draft["fields"]
    ts = draft["timestamp"][:16].replace("T", " ")
    count = draft["completed_count"]
    total = draft["total_fields"]

    parts = [f"Saved {ts}"]
    if "filing_status" in fields:
        parts.append(f"Filing: {fields['filing_status'].title()}")
    if fields.get("gross_income"):
        parts.append(f"Income: ${fields['gross_income']:,.0f}")
    if fields.get("hourly_rate"):
        parts.append(f"OT: ${fields['hourly_rate']}/hr")

    summary = " | ".join(parts)
    return f"{summary}\n    ({count} of {total} fields completed)"


# --- Profile System (reusable stable fields) ---

def save_profile(name: str, fields: dict):
    """Save a named profile with stable fields."""
    profile = {
        "name": name,
        "created": datetime.now().isoformat(),
        "fields": fields,
    }
    _safe_write(PROFILES_DIR / f"{name}.json", profile)


def load_profile(name: str) -> dict | None:
    """Load a named profile."""
    data = _safe_read(PROFILES_DIR / f"{name}.json")
    return data["fields"] if data else None


def list_profiles() -> list[str]:
    """List available profile names."""
    _ensure_dirs()
    return [p.stem for p in PROFILES_DIR.glob("*.json")]


def delete_profile(name: str) -> bool:
    """Delete a profile by name."""
    path = PROFILES_DIR / f"{name}.json"
    if path.exists():
        path.unlink()
        return True
    return False


# --- Results History ---

def save_result(result: dict, inputs: dict):
    """Save a completed calculation with timestamp."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "inputs": inputs,
        "result": result,
    }
    filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    _safe_write(RESULTS_DIR / filename, entry)


def list_results() -> list[dict]:
    """List saved results (most recent first)."""
    _ensure_dirs()
    results = []
    for p in sorted(RESULTS_DIR.glob("*.json"), reverse=True):
        data = _safe_read(p)
        if data:
            results.append({"file": p.name, **data})
    return results
