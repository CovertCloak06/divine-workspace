#!/usr/bin/env python3
"""
Master script to run all PKN code analysis checks.
Catches common bugs before they cause issues in production.

Usage:
    python3 run_all_checks.py [project_dir]

Default project_dir: /home/gh0st/pkn
"""

import sys
import subprocess
from pathlib import Path


def run_check(script_name, project_dir):
    """Run a single analysis script | Returns True if passed | ref:CLAUDE.md (Code Documentation Standard)"""
    script_path = Path(__file__).parent / script_name

    print("\n" + "=" * 70)
    print(f"🔍 Running: {script_name}")
    print("=" * 70)

    try:
        result = subprocess.run(
            ["python3", str(script_path), project_dir],
            capture_output=False,  # Show output directly
            text=True,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running {script_name}: {e}")
        return False


def main():
    """Run all analysis checks on PKN codebase | ref:analyze_*.py"""
    project_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/gh0st/pkn"

    print("=" * 70)
    print("🛠️  PKN CODE ANALYSIS")
    print("=" * 70)
    print(f"📁 Project: {project_dir}\n")

    checks = [
        ("analyze_duplicate_functions.py", "Duplicate function definitions"),
        ("analyze_scope_mismatches.py", "Variable scope mismatches"),
        ("analyze_missing_selectors.py", "Missing CSS/HTML selectors"),
    ]

    results = {}
    for script, description in checks:
        success = run_check(script, project_dir)
        results[description] = success

    # Summary
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)

    all_passed = True
    for description, passed in results.items():
        icon = "✅" if passed else "❌"
        print(f"{icon} {description}")
        if not passed:
            all_passed = False

    print("=" * 70)

    if all_passed:
        print("🎉 All checks passed! Code is clean.\n")
        return 0
    else:
        print("⚠️  Some checks failed. Review issues above.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
