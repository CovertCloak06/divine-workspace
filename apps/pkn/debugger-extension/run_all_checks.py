#!/usr/bin/env python3
"""
PKN Code Quality Master Runner
Runs all analysis checks and provides a unified report.

Usage:
    python run_all_checks.py [path]

Checks run:
    1. Duplicate Functions - Same function defined in multiple files
    2. Scope Mismatches - Variables used inconsistently with window.*
    3. Missing Selectors - JS references to non-existent CSS classes/IDs
"""

import os
import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, Tuple

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'


def print_header(text: str):
    """Print a styled header."""
    width = 70
    print(f"\n{CYAN}{BOLD}{'='*width}{RESET}")
    print(f"{CYAN}{BOLD}{text.center(width)}{RESET}")
    print(f"{CYAN}{BOLD}{'='*width}{RESET}\n")


def print_section(text: str):
    """Print a section header."""
    print(f"\n{YELLOW}{BOLD}▶ {text}{RESET}")
    print(f"{YELLOW}{'-'*50}{RESET}")


def run_check(name: str, script_path: Path, target_path: Path) -> Tuple[bool, str, float]:
    """
    Run a check script and return results.

    Returns:
        (passed: bool, output: str, duration: float)
    """
    start = time.time()

    try:
        result = subprocess.run(
            [sys.executable, str(script_path), str(target_path)],
            capture_output=True,
            text=True,
            timeout=60
        )

        duration = time.time() - start
        output = result.stdout + result.stderr
        passed = result.returncode == 0

        return passed, output, duration

    except subprocess.TimeoutExpired:
        return False, f"{RED}Check timed out after 60 seconds{RESET}", 60.0
    except Exception as e:
        return False, f"{RED}Error running check: {e}{RESET}", 0.0


def main():
    # Determine paths
    script_dir = Path(__file__).parent

    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        target = script_dir.parent  # Default to pkn app root

    if not target.exists():
        print(f"{RED}Error: Target path does not exist: {target}{RESET}")
        sys.exit(1)

    print_header("PKN Code Quality Analyzer")

    print(f"Target: {target}")
    print(f"Script dir: {script_dir}")

    # Define checks to run
    checks = [
        ("Duplicate Functions", script_dir / "analyze_duplicate_functions.py"),
        ("Scope Mismatches", script_dir / "analyze_scope_mismatches.py"),
        ("Missing Selectors", script_dir / "analyze_missing_selectors.py"),
    ]

    # Run all checks
    results = {}
    total_start = time.time()

    for name, script_path in checks:
        print_section(name)

        if not script_path.exists():
            print(f"{RED}Script not found: {script_path}{RESET}")
            results[name] = (False, "Script not found", 0.0)
            continue

        passed, output, duration = run_check(name, script_path, target)
        results[name] = (passed, output, duration)

        # Print output
        print(output)
        print(f"\n{f'Duration: {duration:.2f}s':>50}")

    total_duration = time.time() - total_start

    # Summary
    print_header("Summary")

    passed_count = sum(1 for v in results.values() if v[0])
    failed_count = len(results) - passed_count

    for name, (passed, _, duration) in results.items():
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  {icon} {name} ({duration:.2f}s)")

    print(f"\n{'-'*50}")
    print(f"  Total checks: {len(results)}")
    print(f"  {GREEN}Passed: {passed_count}{RESET}")
    print(f"  {RED}Failed: {failed_count}{RESET}")
    print(f"  Duration: {total_duration:.2f}s")

    if failed_count > 0:
        print(f"\n{RED}{BOLD}✗ Code quality checks FAILED{RESET}")
        print(f"\n{YELLOW}Fix the issues above before committing!{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}✓ All code quality checks PASSED{RESET}")
        sys.exit(0)


if __name__ == '__main__':
    main()
