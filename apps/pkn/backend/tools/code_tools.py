"""
Code Tools - Surgical Code Operations
Inspired by Claude Code's Edit, Write, and Read tools.

Tools:
- read_file: Read files with optional line ranges
- edit_file: Replace exact strings in files (surgical editing)
- write_file: Create or overwrite files
- append_file: Append content to files
"""

from pathlib import Path
from typing import Optional, Dict, Any
from langchain_core.tools import tool


PROJECT_ROOT = Path("/home/gh0st/pkn")


def _validate_path(path: str, must_exist: bool = False) -> tuple[bool, str, Path]:
    """
    Validate file path is within project root.
    Returns: (success, message, resolved_path)
    """
    try:
        p = Path(path)
        p = p if p.is_absolute() else PROJECT_ROOT / p
        p = p.resolve()
        root = PROJECT_ROOT.resolve()

        if not str(p).startswith(str(root)):
            return False, f"Refused: Path outside project root: {p}", p

        if must_exist and not p.exists():
            return False, f"File not found: {p}", p

        return True, "OK", p
    except Exception as e:
        return False, f"Path validation error: {e}", Path()


@tool
def read_file(
    file_path: str,
    offset: Optional[int] = None,
    limit: Optional[int] = None
) -> str:
    """
    Read a file from the local filesystem with optional line ranges.

    Args:
        file_path: Path to the file (absolute or relative to ~/pkn)
        offset: Optional line number to start reading from (1-indexed)
        limit: Optional number of lines to read

    Returns:
        File contents with line numbers (cat -n format)

    Examples:
        read_file("app.js") - Read entire file
        read_file("app.js", offset=100, limit=50) - Read lines 100-150
    """
    valid, msg, path = _validate_path(file_path, must_exist=True)
    if not valid:
        return msg

    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        # Apply offset and limit
        start = (offset - 1) if offset else 0
        end = start + limit if limit else len(lines)

        # Slice lines
        selected_lines = lines[start:end]

        # Format with line numbers (cat -n style)
        result = []
        for i, line in enumerate(selected_lines, start=start + 1):
            # Remove trailing newline, format with line number
            result.append(f"{i:6d}→{line.rstrip()}")

        output = '\n'.join(result)

        # Add context info
        if offset or limit:
            total = len(lines)
            showing = f"Showing lines {start + 1}-{min(end, total)} of {total}"
            output = f"{showing}\n\n{output}"

        return output

    except Exception as e:
        return f"Error reading {path}: {e}"


@tool
def edit_file(
    file_path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False
) -> str:
    """
    Perform exact string replacement in a file (surgical editing).

    CRITICAL: The old_string MUST match EXACTLY as it appears in the file.
    Use read_file first to see the exact content including indentation.

    Args:
        file_path: Path to the file to edit
        old_string: Exact string to replace (must be unique unless replace_all=True)
        new_string: String to replace it with
        replace_all: If True, replace all occurrences. If False, must be unique.

    Returns:
        Success message or error

    Examples:
        # Fix a bug:
        edit_file("app.js",
                  old_string="if (x = 5)",
                  new_string="if (x === 5)")

        # Rename variable everywhere:
        edit_file("app.js",
                  old_string="oldVarName",
                  new_string="newVarName",
                  replace_all=True)
    """
    valid, msg, path = _validate_path(file_path, must_exist=True)
    if not valid:
        return msg

    try:
        # Read original content
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check if old_string exists
        if old_string not in content:
            return f"Error: old_string not found in {path}"

        # Check uniqueness if not replace_all
        if not replace_all:
            count = content.count(old_string)
            if count > 1:
                return (f"Error: old_string appears {count} times in {path}. "
                       f"Provide more context or use replace_all=True")

        # Create backup
        backup_path = Path(str(path) + '.bak')
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Perform replacement
        if replace_all:
            new_content = content.replace(old_string, new_string)
            count = content.count(old_string)
        else:
            new_content = content.replace(old_string, new_string, 1)
            count = 1

        # Write new content
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        return (f"✅ Successfully edited {path}\n"
               f"   Replaced {count} occurrence(s)\n"
               f"   Backup: {backup_path}")

    except Exception as e:
        return f"Error editing {path}: {e}"


@tool
def write_file(file_path: str, content: str) -> str:
    """
    Write content to a file, creating or overwriting it.

    IMPORTANT: This will overwrite existing files! Use edit_file for modifications.

    Args:
        file_path: Path to the file (will be created if doesn't exist)
        content: Content to write

    Returns:
        Success message or error

    Examples:
        write_file("new_script.py", "#!/usr/bin/env python3\\nprint('Hello')")
    """
    valid, msg, path = _validate_path(file_path, must_exist=False)
    if not valid:
        return msg

    try:
        # Create backup if file exists
        if path.exists():
            backup_path = Path(str(path) + '.bak')
            with open(path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)
            backup_msg = f"\n   Backup: {backup_path}"
        else:
            backup_msg = ""

        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

        lines = content.count('\n') + 1
        size = len(content)

        return (f"✅ Successfully wrote {path}\n"
               f"   Size: {size} bytes, {lines} lines{backup_msg}")

    except Exception as e:
        return f"Error writing {path}: {e}"


@tool
def append_file(file_path: str, content: str) -> str:
    """
    Append content to a file (add to end).

    Args:
        file_path: Path to the file
        content: Content to append

    Returns:
        Success message or error
    """
    valid, msg, path = _validate_path(file_path, must_exist=True)
    if not valid:
        return msg

    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(content)

        return f"✅ Appended {len(content)} bytes to {path}"

    except Exception as e:
        return f"Error appending to {path}: {e}"


# Export tools for agent use
TOOLS = [read_file, edit_file, write_file, append_file]

# Tool descriptions for LLM
TOOL_DESCRIPTIONS = {
    'read_file': 'Read files with optional line ranges (like cat -n)',
    'edit_file': 'Surgical string replacement in files (exact match required)',
    'write_file': 'Create or overwrite files (use edit_file for changes)',
    'append_file': 'Add content to end of existing file',
}
