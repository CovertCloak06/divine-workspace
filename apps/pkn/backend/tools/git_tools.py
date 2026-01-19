"""
Git Tools - Version Control
Git operations for version control on mobile.

Tools:
- git_diff: Show changes (staged or unstaged)
- git_log: Show recent commits
- git_branches: List branches
- git_status: Show working tree status
"""

import subprocess
from pathlib import Path
from typing import Optional
from langchain_core.tools import tool


def _run_git(args: list, cwd: Optional[Path] = None) -> tuple:
    """Run git command and return (success, output)"""
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd or Path.cwd(),
        )
        output = result.stdout.strip() or result.stderr.strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Git command timed out"
    except FileNotFoundError:
        return False, "Git not installed"
    except Exception as e:
        return False, f"Error: {e}"


@tool
def git_diff(staged: bool = False, path: Optional[str] = None) -> str:
    """
    Show git diff (changes in working directory).

    Args:
        staged: If True, show only staged changes (--cached)
        path: Optional path to specific file or directory

    Returns:
        Git diff output or message if no changes

    Examples:
        git_diff()                    # All unstaged changes
        git_diff(staged=True)         # Only staged changes
        git_diff(path="src/app.py")   # Changes to specific file
    """
    try:
        args = ["diff"]
        if staged:
            args.append("--cached")
        if path:
            args.extend(["--", path])

        success, output = _run_git(args)

        if not success:
            return f"Git error: {output}"

        if not output:
            if staged:
                return "No staged changes"
            else:
                return "No unstaged changes (working tree clean)"

        # Truncate if too long
        if len(output) > 5000:
            output = output[:5000] + f"\n\n... (truncated, {len(output)} total chars)"

        return output

    except Exception as e:
        return f"Error running git diff: {e}"


@tool
def git_log(count: int = 10, oneline: bool = True) -> str:
    """
    Show recent git commits.

    Args:
        count: Number of commits to show (default 10)
        oneline: If True, compact one-line format (default True)

    Returns:
        Git log output

    Examples:
        git_log()              # Last 10 commits, compact
        git_log(count=5)       # Last 5 commits
        git_log(oneline=False) # Full commit details
    """
    try:
        args = ["log", f"-{count}"]
        if oneline:
            args.append("--oneline")
        else:
            args.append("--pretty=format:%h %ad | %s [%an]")
            args.append("--date=short")

        success, output = _run_git(args)

        if not success:
            if "not a git repository" in output.lower():
                return "Not in a git repository"
            return f"Git error: {output}"

        if not output:
            return "No commits yet"

        return f"Recent commits ({count}):\n{output}"

    except Exception as e:
        return f"Error running git log: {e}"


@tool
def git_branches(all_branches: bool = False) -> str:
    """
    List git branches.

    Args:
        all_branches: If True, include remote branches (-a)

    Returns:
        List of branches with current branch marked

    Examples:
        git_branches()                # Local branches only
        git_branches(all_branches=True)  # Include remotes
    """
    try:
        args = ["branch"]
        if all_branches:
            args.append("-a")

        success, output = _run_git(args)

        if not success:
            if "not a git repository" in output.lower():
                return "Not in a git repository"
            return f"Git error: {output}"

        if not output:
            return "No branches found"

        return f"Branches:\n{output}"

    except Exception as e:
        return f"Error listing branches: {e}"


@tool
def git_status() -> str:
    """
    Show git working tree status.

    Returns summary of:
    - Current branch
    - Staged changes
    - Unstaged changes
    - Untracked files

    Returns:
        Git status output

    Examples:
        git_status()  # See current state
    """
    try:
        args = ["status", "--short", "--branch"]
        success, output = _run_git(args)

        if not success:
            if "not a git repository" in output.lower():
                return "Not in a git repository"
            return f"Git error: {output}"

        if not output:
            return "On branch (unknown)\nNothing to commit, working tree clean"

        return f"Git status:\n{output}"

    except Exception as e:
        return f"Error running git status: {e}"


# Export tools for registration
TOOLS = [git_diff, git_log, git_branches, git_status]

TOOL_DESCRIPTIONS = {
    "git_diff": "Show git diff (staged or unstaged changes)",
    "git_log": "Show recent commits",
    "git_branches": "List git branches",
    "git_status": "Show working tree status",
}
