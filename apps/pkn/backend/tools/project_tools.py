"""
Project Tools - Project Management
Basic project management tools for mobile development.

Tools:
- project_status: Git status and recent commits
- project_health: Check project health (structure, files)
- project_test: Run tests if pytest available
- project_structure: Show directory tree
"""

import subprocess
import os
from pathlib import Path
from typing import Optional
from langchain_core.tools import tool


def _run_cmd(args: list, cwd: Optional[Path] = None, timeout: int = 60) -> tuple:
    """Run command and return (success, output)"""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or Path.cwd(),
        )
        output = result.stdout.strip() or result.stderr.strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {args[0]}"
    except Exception as e:
        return False, f"Error: {e}"


@tool
def project_status() -> str:
    """
    Show git status and recent commits.

    Combines git status and recent log for quick overview.

    Returns:
        Project status summary

    Examples:
        project_status()  # Quick overview
    """
    try:
        result = ["Project Status", "=" * 40]

        # Git status
        success, status = _run_cmd(["git", "status", "--short", "--branch"])
        if success:
            result.append("\nGit Status:")
            result.append(status if status else "  Working tree clean")
        else:
            result.append("\nGit: Not a repository or git not available")

        # Recent commits
        success, log = _run_cmd(["git", "log", "-5", "--oneline"])
        if success and log:
            result.append("\nRecent Commits:")
            for line in log.split("\n"):
                result.append(f"  {line}")

        return "\n".join(result)

    except Exception as e:
        return f"Error getting project status: {e}"


@tool
def project_health() -> str:
    """
    Check project health and structure.

    Checks:
    - Directory structure
    - Key files exist
    - File counts by type
    - Large files warning

    Returns:
        Health check report

    Examples:
        project_health()  # Full health check
    """
    try:
        result = ["Project Health Check", "=" * 40]
        cwd = Path.cwd()

        # Check key files
        key_files = [
            "README.md", "requirements.txt", "package.json",
            "setup.py", "pyproject.toml", ".gitignore",
            "CLAUDE.md", "Makefile", "justfile"
        ]

        found_files = []
        for f in key_files:
            if (cwd / f).exists():
                found_files.append(f)

        result.append(f"\nKey files found: {len(found_files)}/{len(key_files)}")
        for f in found_files:
            result.append(f"  ✓ {f}")

        # Count files by type
        file_counts = {}
        total_files = 0
        large_files = []

        for root, dirs, files in os.walk(cwd):
            # Skip hidden and common ignore dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in [
                'node_modules', '__pycache__', '.venv', 'venv', '.git', 'dist', 'build'
            ]]

            for f in files:
                total_files += 1
                ext = Path(f).suffix.lower() or "(no ext)"
                file_counts[ext] = file_counts.get(ext, 0) + 1

                # Check file size
                filepath = Path(root) / f
                try:
                    size = filepath.stat().st_size
                    if size > 500_000:  # > 500KB
                        large_files.append((str(filepath.relative_to(cwd)), size))
                except:
                    pass

        result.append(f"\nTotal files: {total_files}")
        result.append("\nFiles by type:")
        for ext, count in sorted(file_counts.items(), key=lambda x: -x[1])[:10]:
            result.append(f"  {ext}: {count}")

        if large_files:
            result.append(f"\nLarge files (>500KB): {len(large_files)}")
            for path, size in large_files[:5]:
                result.append(f"  {path}: {size // 1024}KB")

        # Directory depth
        max_depth = 0
        for root, dirs, files in os.walk(cwd):
            depth = str(root).count(os.sep) - str(cwd).count(os.sep)
            max_depth = max(max_depth, depth)
            if depth > 8:
                dirs.clear()  # Stop going deeper

        result.append(f"\nMax directory depth: {max_depth}")

        return "\n".join(result)

    except Exception as e:
        return f"Error checking project health: {e}"


@tool
def project_test(path: Optional[str] = None) -> str:
    """
    Run tests if pytest is available.

    Args:
        path: Optional path to specific test file or directory

    Returns:
        Test results or error message

    Examples:
        project_test()                    # Run all tests
        project_test("tests/test_auth.py") # Run specific test
    """
    try:
        # Check if pytest is available
        success, _ = _run_cmd(["python3", "-m", "pytest", "--version"])
        if not success:
            return "pytest not available. Install with: pip install pytest"

        args = ["python3", "-m", "pytest", "-v", "--tb=short"]
        if path:
            args.append(path)

        success, output = _run_cmd(args, timeout=120)

        if not output:
            return "No test output (no tests found?)"

        # Truncate if too long
        if len(output) > 3000:
            lines = output.split("\n")
            # Keep first 20 and last 30 lines
            output = "\n".join(lines[:20]) + "\n\n... (truncated) ...\n\n" + "\n".join(lines[-30:])

        return f"Test Results:\n{output}"

    except Exception as e:
        return f"Error running tests: {e}"


@tool
def project_structure(max_depth: int = 3) -> str:
    """
    Show project directory structure.

    Args:
        max_depth: Maximum depth to show (default 3)

    Returns:
        Directory tree

    Examples:
        project_structure()        # Default depth
        project_structure(max_depth=2)  # Shallow view
    """
    try:
        cwd = Path.cwd()
        result = [f"{cwd.name}/"]

        def _tree(path: Path, prefix: str, depth: int):
            if depth > max_depth:
                return

            # Skip hidden and common ignore dirs
            ignore = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.cache'}

            try:
                entries = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            except PermissionError:
                return

            # Filter entries
            entries = [e for e in entries if e.name not in ignore and not e.name.startswith('.')]

            for i, entry in enumerate(entries):
                is_last = i == len(entries) - 1
                connector = "└── " if is_last else "├── "
                new_prefix = prefix + ("    " if is_last else "│   ")

                if entry.is_dir():
                    result.append(f"{prefix}{connector}{entry.name}/")
                    _tree(entry, new_prefix, depth + 1)
                else:
                    result.append(f"{prefix}{connector}{entry.name}")

        _tree(cwd, "", 1)

        if len(result) > 100:
            result = result[:100]
            result.append("... (truncated)")

        return "\n".join(result)

    except Exception as e:
        return f"Error showing structure: {e}"


# Export tools for registration
TOOLS = [project_status, project_health, project_test, project_structure]

TOOL_DESCRIPTIONS = {
    "project_status": "Git status and recent commits",
    "project_health": "Check project health (files, structure)",
    "project_test": "Run tests if pytest available",
    "project_structure": "Show directory tree",
}
