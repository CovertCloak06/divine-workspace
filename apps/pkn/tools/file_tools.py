"""
File Tools - File Search and Discovery
Inspired by Claude Code's Glob and Grep tools.

Tools:
- glob: Find files by pattern
- grep: Search file contents with regex
- find_definition: Find function/class definitions
- tree: Directory tree view
- file_info: Get file statistics
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict
from langchain_core.tools import tool


PROJECT_ROOT = Path("/home/gh0st/pkn")


@tool
def glob(pattern: str, path: Optional[str] = None) -> str:
    """
    Find files matching a glob pattern.

    Supports patterns like:
    - *.py - All Python files in path
    - **/*.js - All JS files recursively
    - src/**/*.tsx - All TSX files in src/

    Args:
        pattern: Glob pattern (e.g., "**/*.py", "*.txt")
        path: Directory to search in (default: project root)

    Returns:
        List of matching file paths, sorted by modification time

    Examples:
        glob("**/*.py") - All Python files
        glob("*.md", path="docs") - Markdown files in docs/
    """
    try:
        search_path = Path(path) if path else PROJECT_ROOT
        if not search_path.is_absolute():
            search_path = PROJECT_ROOT / search_path

        # Use Path.glob for pattern matching
        matches = list(search_path.glob(pattern))

        # Sort by modification time (newest first)
        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        if not matches:
            return f"No files found matching pattern: {pattern}"

        # Format output
        result = [f"Found {len(matches)} file(s) matching '{pattern}':\n"]
        for p in matches:
            rel_path = p.relative_to(PROJECT_ROOT) if p.is_relative_to(PROJECT_ROOT) else p
            result.append(f"  {rel_path}")

        return '\n'.join(result)

    except Exception as e:
        return f"Error in glob: {e}"


@tool
def grep(
    pattern: str,
    path: Optional[str] = None,
    output_mode: str = "files_with_matches",
    context_lines: int = 0,
    case_insensitive: bool = False
) -> str:
    """
    Search file contents using regex (powered by ripgrep/grep).

    Args:
        pattern: Regex pattern to search for
        path: File or directory to search (default: project root)
        output_mode: Output format:
            - "files_with_matches": Just list files containing pattern
            - "content": Show matching lines with context
            - "count": Show match counts per file
        context_lines: Number of lines before/after match (content mode only)
        case_insensitive: Case-insensitive search

    Returns:
        Search results

    Examples:
        grep("TODO") - Find files with TODO
        grep("def.*main", output_mode="content") - Show function definitions
        grep("error", context_lines=3, output_mode="content") - With context
    """
    try:
        search_path = Path(path) if path else PROJECT_ROOT
        if not search_path.is_absolute():
            search_path = PROJECT_ROOT / search_path

        # Build grep command
        cmd = ['grep', '-r']

        if case_insensitive:
            cmd.append('-i')

        if output_mode == "files_with_matches":
            cmd.append('-l')  # Files with matches
        elif output_mode == "count":
            cmd.append('-c')  # Count matches
        elif output_mode == "content":
            cmd.append('-n')  # Line numbers
            if context_lines:
                cmd.extend(['-C', str(context_lines)])  # Context

        cmd.extend([pattern, str(search_path)])

        # Run grep
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout.strip()

        if not output:
            return f"No matches found for pattern: {pattern}"

        # Format output
        if output_mode == "files_with_matches":
            files = output.split('\n')
            return f"Found {len(files)} file(s) with matches:\n" + '\n'.join(f"  {f}" for f in files)
        else:
            return output

    except subprocess.TimeoutExpired:
        return "Error: Search timed out (30s limit)"
    except Exception as e:
        return f"Error in grep: {e}"


@tool
def find_definition(name: str, path: Optional[str] = None) -> str:
    """
    Find function or class definitions by name.

    Searches for patterns like:
    - def function_name
    - class ClassName
    - function function_name
    - const functionName

    Args:
        name: Function or class name to find
        path: Directory to search (default: project root)

    Returns:
        Files and line numbers where definition is found

    Examples:
        find_definition("sendMessage")
        find_definition("UserManager")
    """
    try:
        search_path = Path(path) if path else PROJECT_ROOT
        if not search_path.is_absolute():
            search_path = PROJECT_ROOT / search_path

        # Build regex for common definition patterns
        patterns = [
            f"def {name}",  # Python
            f"class {name}",  # Python/JS
            f"function {name}",  # JS
            f"const {name}\\s*=",  # JS const
            f"let {name}\\s*=",  # JS let
            f"var {name}\\s*=",  # JS var
        ]

        results = []
        for pattern in patterns:
            cmd = ['grep', '-rn', pattern, str(search_path)]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.stdout:
                    results.append(result.stdout.strip())
            except:
                continue

        if not results:
            return f"No definition found for: {name}"

        output = '\n'.join(results)
        return f"Definition(s) of '{name}':\n{output}"

    except Exception as e:
        return f"Error finding definition: {e}"


@tool
def tree(path: Optional[str] = None, depth: int = 2) -> str:
    """
    Show directory tree structure.

    Args:
        path: Directory to show (default: project root)
        depth: Maximum depth to show (default: 2)

    Returns:
        Tree structure

    Examples:
        tree() - Show project root (2 levels)
        tree(path="tools", depth=1) - Show tools/ directory
    """
    try:
        search_path = Path(path) if path else PROJECT_ROOT
        if not search_path.is_absolute():
            search_path = PROJECT_ROOT / search_path

        # Use 'tree' command if available, else manual
        try:
            result = subprocess.run(
                ['tree', '-L', str(depth), str(search_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            pass  # tree command not available, use manual method

        # Manual tree building
        def build_tree(path: Path, prefix: str = "", depth_left: int = depth):
            if depth_left <= 0:
                return []

            lines = []
            try:
                items = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name))
                for i, item in enumerate(items):
                    is_last = i == len(items) - 1
                    current_prefix = "└── " if is_last else "├── "
                    lines.append(prefix + current_prefix + item.name)

                    if item.is_dir() and depth_left > 1:
                        extension = "    " if is_last else "│   "
                        lines.extend(build_tree(item, prefix + extension, depth_left - 1))
            except PermissionError:
                pass

            return lines

        tree_lines = [str(search_path)] + build_tree(search_path)
        return '\n'.join(tree_lines)

    except Exception as e:
        return f"Error building tree: {e}"


@tool
def file_info(file_path: str) -> str:
    """
    Get detailed file information.

    Args:
        file_path: Path to file

    Returns:
        File statistics (size, modified time, permissions, etc.)

    Examples:
        file_info("app.js")
    """
    try:
        path = Path(file_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path

        if not path.exists():
            return f"File not found: {path}"

        stats = path.stat()

        # Format size
        size = stats.st_size
        if size < 1024:
            size_str = f"{size} bytes"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"

        # Format modified time
        from datetime import datetime
        mtime = datetime.fromtimestamp(stats.st_mtime)

        # Count lines if text file
        lines = "N/A"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = sum(1 for _ in f)
        except:
            pass

        info = f"""File: {path}
Type: {'Directory' if path.is_dir() else 'File'}
Size: {size_str}
Lines: {lines}
Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}
Permissions: {oct(stats.st_mode)[-3:]}
"""
        return info.strip()

    except Exception as e:
        return f"Error getting file info: {e}"


# Export tools
TOOLS = [glob, grep, find_definition, tree, file_info]

TOOL_DESCRIPTIONS = {
    'glob': 'Find files by pattern (e.g., **/*.py)',
    'grep': 'Search file contents with regex',
    'find_definition': 'Find function/class definitions by name',
    'tree': 'Show directory tree structure',
    'file_info': 'Get detailed file statistics',
}
