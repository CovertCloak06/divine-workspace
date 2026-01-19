"""
Scratchpad Tools - Agent Handoff Storage
Temporary storage for passing data between agents during workflows.

Tools:
- scratchpad_write: Save findings for next agent
- scratchpad_read: Read entries (empty key lists all)
- scratchpad_clear: Clear all scratchpad entries
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from langchain_core.tools import tool


SCRATCHPAD_FILE = Path.home() / ".pkn_scratchpad.json"


def _load_scratchpad() -> Dict[str, Any]:
    """Load scratchpad or return empty dict"""
    if not SCRATCHPAD_FILE.exists():
        return {"entries": {}, "workflow": None}
    try:
        return json.loads(SCRATCHPAD_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"entries": {}, "workflow": None}


def _save_scratchpad(data: Dict[str, Any]) -> None:
    """Save scratchpad to disk"""
    SCRATCHPAD_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCRATCHPAD_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@tool
def scratchpad_write(key: str, content: str) -> str:
    """
    Save findings for handoff to next agent in workflow.

    Use this to pass important information between agents during
    multi-agent workflows. Data persists until explicitly cleared.

    Args:
        key: Identifier for this entry (e.g., "analysis", "findings", "plan")
        content: Information to save for the next agent

    Returns:
        Confirmation message

    Examples:
        scratchpad_write("bug_analysis", "Root cause: null pointer in auth.py line 42")
        scratchpad_write("test_results", "3 tests failing: test_login, test_signup, test_reset")
    """
    try:
        data = _load_scratchpad()
        data["entries"][key] = {
            "content": content,
            "timestamp": datetime.now().isoformat(),
        }
        _save_scratchpad(data)
        return f"Saved to scratchpad: '{key}' ({len(content)} chars)"
    except Exception as e:
        return f"Error writing to scratchpad: {e}"


@tool
def scratchpad_read(key: str = "") -> str:
    """
    Read scratchpad entries. Empty key lists all entries.

    Use this at the start of a workflow step to see what
    previous agents have discovered or documented.

    Args:
        key: Specific entry to read, or empty string to list all

    Returns:
        Entry content or list of all entries

    Examples:
        scratchpad_read("bug_analysis")  # Get specific entry
        scratchpad_read()                 # List all entries
    """
    try:
        data = _load_scratchpad()
        entries = data.get("entries", {})

        if not entries:
            return "Scratchpad is empty"

        if key:
            if key in entries:
                entry = entries[key]
                return f"[{key}] ({entry['timestamp']})\n{entry['content']}"
            else:
                available = ", ".join(entries.keys())
                return f"Key '{key}' not found. Available: {available}"
        else:
            # List all entries
            result = ["Scratchpad entries:"]
            for k, v in entries.items():
                preview = v["content"][:100] + "..." if len(v["content"]) > 100 else v["content"]
                result.append(f"  - {k}: {preview}")

            workflow = data.get("workflow")
            if workflow:
                result.append(f"\nActive workflow: {workflow['name']} (step {workflow.get('step', 0) + 1})")

            return "\n".join(result)
    except Exception as e:
        return f"Error reading scratchpad: {e}"


@tool
def scratchpad_clear() -> str:
    """
    Clear all scratchpad entries.

    Use this when starting a new workflow or when handoff
    data is no longer needed. Clears both entries and
    active workflow state.

    Returns:
        Confirmation message

    Examples:
        scratchpad_clear()  # Clear everything for fresh start
    """
    try:
        count = 0
        if SCRATCHPAD_FILE.exists():
            data = _load_scratchpad()
            count = len(data.get("entries", {}))

        _save_scratchpad({"entries": {}, "workflow": None})
        return f"Scratchpad cleared ({count} entries removed)"
    except Exception as e:
        return f"Error clearing scratchpad: {e}"


# Export tools for registration
TOOLS = [scratchpad_write, scratchpad_read, scratchpad_clear]

TOOL_DESCRIPTIONS = {
    "scratchpad_write": "Save findings for handoff to next agent",
    "scratchpad_read": "Read scratchpad entries (empty key lists all)",
    "scratchpad_clear": "Clear all scratchpad entries",
}
