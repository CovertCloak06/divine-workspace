"""
Memory Tools - Context & Learning
Persistent memory and context management for agents.

Tools:
- save_context: Store information for later
- recall_context: Retrieve saved information
- save_snippet: Save reusable code snippets
- search_memory: Search through saved memories
- list_memories: Show all saved contexts
- clear_memory: Clear specific or all memories
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from langchain_core.tools import tool


PROJECT_ROOT = Path("/home/gh0st/pkn")
GLOBAL_MEMORY = Path.home() / ".parakleon_memory.json"
PROJECT_MEMORY = PROJECT_ROOT / "pkn_memory.json"
CODE_SNIPPETS = PROJECT_ROOT / "code_snippets.json"


def _load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file or return empty dict"""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except:
        return {}


def _save_json(path: Path, data: Dict[str, Any]) -> None:
    """Save data to JSON file"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


@tool
def save_context(
    key: str,
    value: str,
    scope: str = "project",
    tags: Optional[List[str]] = None
) -> str:
    """
    Save information for later retrieval (persistent memory).

    Args:
        key: Unique identifier for this context
        value: Information to save
        scope: "global" (all projects) or "project" (this project only)
        tags: Optional list of tags for categorization

    Returns:
        Confirmation message

    Examples:
        save_context("api_pattern", "Use Flask-CORS for cross-origin requests")
        save_context("database_choice", "Using SQLite for simplicity", tags=["database"])

    Use this to remember:
        - Architectural decisions
        - API patterns
        - Configuration choices
        - User preferences
        - Important findings
    """
    try:
        memory_path = GLOBAL_MEMORY if scope == "global" else PROJECT_MEMORY
        data = _load_json(memory_path)

        # Store with metadata
        data[key] = {
            'value': value,
            'timestamp': datetime.now().isoformat(),
            'tags': tags or []
        }

        _save_json(memory_path, data)

        return f"✅ Saved to {scope} memory: '{key}'"

    except Exception as e:
        return f"Error saving context: {e}"


@tool
def recall_context(key: str, scope: str = "project") -> str:
    """
    Retrieve previously saved information.

    Args:
        key: Identifier to recall
        scope: "global" or "project"

    Returns:
        Saved value or error message

    Examples:
        recall_context("api_pattern")
        recall_context("user_preferences", scope="global")
    """
    try:
        memory_path = GLOBAL_MEMORY if scope == "global" else PROJECT_MEMORY
        data = _load_json(memory_path)

        if key not in data:
            return f"No memory found for key: {key}"

        entry = data[key]
        timestamp = entry.get('timestamp', 'unknown')
        value = entry.get('value', '')
        tags = entry.get('tags', [])

        result = f"Memory '{key}' (saved: {timestamp}):\n{value}"
        if tags:
            result += f"\nTags: {', '.join(tags)}"

        return result

    except Exception as e:
        return f"Error recalling context: {e}"


@tool
def save_snippet(
    name: str,
    code: str,
    language: str,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> str:
    """
    Save a reusable code snippet.

    Args:
        name: Snippet name (unique identifier)
        code: The code to save
        language: Programming language (python, javascript, bash, etc.)
        description: What this snippet does
        tags: Optional categorization tags

    Returns:
        Confirmation message

    Examples:
        save_snippet(
            "flask_cors",
            "from flask_cors import CORS\\nCORS(app)",
            "python",
            description="Enable CORS in Flask",
            tags=["flask", "cors"]
        )

    Use this for:
        - Frequently used patterns
        - Template code
        - Configuration snippets
        - Utility functions
    """
    try:
        snippets = _load_json(CODE_SNIPPETS)

        snippets[name] = {
            'code': code,
            'language': language,
            'description': description or '',
            'tags': tags or [],
            'timestamp': datetime.now().isoformat()
        }

        _save_json(CODE_SNIPPETS, snippets)

        return f"✅ Saved code snippet: '{name}' ({language})"

    except Exception as e:
        return f"Error saving snippet: {e}"


@tool
def search_memory(query: str, scope: str = "project") -> str:
    """
    Search through saved memories for a query.

    Searches in key names, values, and tags.

    Args:
        query: What to search for
        scope: "global", "project", or "snippets"

    Returns:
        Matching memories

    Examples:
        search_memory("api")
        search_memory("flask", scope="snippets")
    """
    try:
        if scope == "snippets":
            data = _load_json(CODE_SNIPPETS)
        elif scope == "global":
            data = _load_json(GLOBAL_MEMORY)
        else:
            data = _load_json(PROJECT_MEMORY)

        query_lower = query.lower()
        matches = []

        for key, entry in data.items():
            # Search in key
            if query_lower in key.lower():
                matches.append((key, entry))
                continue

            # Search in value/code
            value = entry.get('value') or entry.get('code') or ''
            if query_lower in value.lower():
                matches.append((key, entry))
                continue

            # Search in tags
            tags = entry.get('tags', [])
            if any(query_lower in tag.lower() for tag in tags):
                matches.append((key, entry))

        if not matches:
            return f"No memories found matching: {query}"

        # Format results
        results = [f"Found {len(matches)} match(es) for '{query}':\n"]
        for key, entry in matches[:10]:  # Limit to 10 results
            timestamp = entry.get('timestamp', 'unknown')
            preview = (entry.get('value') or entry.get('code') or '')[:100]
            results.append(f"\n• {key} ({timestamp})")
            results.append(f"  {preview}...")

        return '\n'.join(results)

    except Exception as e:
        return f"Error searching memory: {e}"


@tool
def list_memories(scope: str = "project") -> str:
    """
    List all saved contexts/snippets.

    Args:
        scope: "global", "project", or "snippets"

    Returns:
        List of all stored memories

    Examples:
        list_memories()
        list_memories(scope="snippets")
    """
    try:
        if scope == "snippets":
            data = _load_json(CODE_SNIPPETS)
            title = "Code Snippets"
        elif scope == "global":
            data = _load_json(GLOBAL_MEMORY)
            title = "Global Memory"
        else:
            data = _load_json(PROJECT_MEMORY)
            title = "Project Memory"

        if not data:
            return f"No {title.lower()} saved"

        results = [f"{title} ({len(data)} items):\n"]
        for key, entry in data.items():
            timestamp = entry.get('timestamp', 'unknown')
            tags = entry.get('tags', [])
            tags_str = f" [{', '.join(tags)}]" if tags else ""
            results.append(f"  • {key} ({timestamp}){tags_str}")

        return '\n'.join(results)

    except Exception as e:
        return f"Error listing memories: {e}"


@tool
def clear_memory(key: Optional[str] = None, scope: str = "project") -> str:
    """
    Clear specific memory or all memories.

    Args:
        key: Specific key to clear (or None to clear all)
        scope: "global", "project", or "snippets"

    Returns:
        Confirmation message

    Examples:
        clear_memory("old_key")  # Clear specific
        clear_memory()  # Clear all project memories
        clear_memory(scope="snippets")  # Clear all snippets

    WARNING: This is permanent! Use carefully.
    """
    try:
        if scope == "snippets":
            memory_path = CODE_SNIPPETS
        elif scope == "global":
            memory_path = GLOBAL_MEMORY
        else:
            memory_path = PROJECT_MEMORY

        if key:
            # Clear specific key
            data = _load_json(memory_path)
            if key in data:
                del data[key]
                _save_json(memory_path, data)
                return f"✅ Cleared memory: '{key}'"
            else:
                return f"Key not found: '{key}'"
        else:
            # Clear all
            _save_json(memory_path, {})
            return f"✅ Cleared all {scope} memories"

    except Exception as e:
        return f"Error clearing memory: {e}"


@tool
def get_snippet(name: str) -> str:
    """
    Retrieve a saved code snippet.

    Args:
        name: Snippet name

    Returns:
        Code snippet with metadata

    Examples:
        get_snippet("flask_cors")
    """
    try:
        snippets = _load_json(CODE_SNIPPETS)

        if name not in snippets:
            return f"Snippet not found: {name}"

        snippet = snippets[name]
        code = snippet.get('code', '')
        lang = snippet.get('language', 'unknown')
        desc = snippet.get('description', '')
        tags = snippet.get('tags', [])

        result = f"Snippet: {name} ({lang})"
        if desc:
            result += f"\nDescription: {desc}"
        if tags:
            result += f"\nTags: {', '.join(tags)}"
        result += f"\n\nCode:\n{code}"

        return result

    except Exception as e:
        return f"Error retrieving snippet: {e}"


# Export tools
TOOLS = [
    save_context,
    recall_context,
    save_snippet,
    get_snippet,
    search_memory,
    list_memories,
    clear_memory
]

TOOL_DESCRIPTIONS = {
    'save_context': 'Save information for later (persistent memory)',
    'recall_context': 'Retrieve saved information',
    'save_snippet': 'Save reusable code snippets',
    'get_snippet': 'Retrieve saved code snippet',
    'search_memory': 'Search through saved memories',
    'list_memories': 'List all saved contexts/snippets',
    'clear_memory': 'Clear specific or all memories',
}
