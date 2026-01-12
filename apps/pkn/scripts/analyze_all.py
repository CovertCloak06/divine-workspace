#!/usr/bin/env python3
"""
PKN Master Analysis Tool
Runs all code quality checks in one command
"""

import os
import sys
import subprocess
from pathlib import Path

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}{text.center(70)}{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")

def print_section(text):
    print(f"\n{YELLOW}▶ {text}{RESET}")

def run_check(name, script_path, args):
    """Run a check script and return success status"""
    print_section(f"Running: {name}")

    try:
        result = subprocess.run(
            [sys.executable, script_path] + args,
            capture_output=True,
            text=True
        )

        # Print output
        print(result.stdout)
        if result.stderr:
            print(result.stderr)

        if result.returncode == 0:
            print(f"{GREEN}✓ {name} PASSED{RESET}")
            return True
        else:
            print(f"{RED}✗ {name} FAILED{RESET}")
            return False

    except FileNotFoundError:
        print(f"{RED}✗ Script not found: {script_path}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}✗ Error running {name}: {e}{RESET}")
        return False

def main():
    print_header("PKN Master Code Analysis")

    # Get paths
    script_dir = Path(__file__).parent
    pkn_root = script_dir.parent
    debugger_ext = pkn_root / "debugger-extension"  # Now inside pkn app

    print(f"PKN Root: {pkn_root}")
    print(f"Debugger Extension: {debugger_ext}")

    # Track results
    results = {}

    # 1. Plugin Validation
    plugin_checker = script_dir / "check_plugins.py"
    if plugin_checker.exists():
        results['Plugins'] = run_check("Plugin Validation", str(plugin_checker), [])

    # 2. Code Analysis (from debugger extension)
    if debugger_ext.exists():
        print_section("Running Code Analysis Checks")

        checks = [
            ("Duplicate Functions", "analyze_duplicate_functions.py"),
            ("Scope Mismatches", "analyze_scope_mismatches.py"),
            ("Missing Selectors", "analyze_missing_selectors.py"),
        ]

        for name, script in checks:
            script_path = debugger_ext / script
            if script_path.exists():
                results[name] = run_check(name, str(script_path), [str(pkn_root)])
            else:
                print(f"{YELLOW}⚠ Skipping {name} - script not found{RESET}")

    # Summary
    print_header("Analysis Summary")

    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    for check, status in results.items():
        icon = f"{GREEN}✓{RESET}" if status else f"{RED}✗{RESET}"
        print(f"  {icon} {check}")

    print(f"\n{CYAN}Total Checks: {total}{RESET}")
    print(f"{GREEN}Passed: {passed}{RESET}")
    print(f"{RED}Failed: {failed}{RESET}")

    if failed > 0:
        print(f"\n{YELLOW}💡 Fix the issues above before committing!{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}🎉 All checks passed! Your code is clean!{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
