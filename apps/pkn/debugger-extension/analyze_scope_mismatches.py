#!/usr/bin/env python3
"""
Scope Mismatch Analyzer
Finds variables that are used inconsistently with window.* prefix.

Example bug this catches:
  - openMenuElement used locally in one place
  - window.openMenuElement used elsewhere
  - They're actually different variables, causing bugs
"""

import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


def analyze_file(file_path: Path) -> Tuple[Set[str], Set[str], Dict[str, List[int]]]:
    """
    Analyze a JS file for scope usage patterns.

    Returns:
        - local_vars: Variables used without window. prefix
        - window_vars: Variables used with window. prefix
        - locations: Dict mapping var names to line numbers
    """
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        return set(), set(), {}

    lines = content.split('\n')

    local_vars = set()
    window_vars = set()
    locations = defaultdict(list)

    # Pattern for window.varName usage (assignment or read)
    window_pattern = r'window\.([a-zA-Z_$][a-zA-Z0-9_$]*)'

    # Pattern for variable declarations
    decl_pattern = r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'

    # Pattern for assignments (varName = something, but not inside window.)
    assign_pattern = r'^(?!.*window\.).*\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*='

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        # Find window.* usages
        for match in re.finditer(window_pattern, line):
            var_name = match.group(1)
            window_vars.add(var_name)
            locations[f'window.{var_name}'].append(line_num)

        # Find local declarations
        for match in re.finditer(decl_pattern, line):
            var_name = match.group(1)
            local_vars.add(var_name)
            locations[var_name].append(line_num)

    return local_vars, window_vars, locations


def find_mismatches(root_path: Path) -> Dict[str, Dict]:
    """Find variables used both with and without window. prefix."""

    all_local = defaultdict(lambda: defaultdict(list))  # var -> file -> lines
    all_window = defaultdict(lambda: defaultdict(list))  # var -> file -> lines

    # Directories and patterns to skip
    skip_patterns = [
        'node_modules', '.venv', 'vendor', 'llama.cpp',
        '/archive/', '/android/', '/www/',  # Capacitor build outputs
        '.backup', '.bak', '.old', '.disabled',  # Backup files
        'old-code', 'old_code',  # Legacy code directories
    ]

    for file_path in root_path.rglob('*.js'):
        # Skip excluded directories and patterns
        if any(skip in str(file_path) for skip in skip_patterns):
            continue

        local_vars, window_vars, locations = analyze_file(file_path)
        rel_path = str(file_path.relative_to(root_path))

        for var in local_vars:
            all_local[var][rel_path] = locations.get(var, [])

        for var in window_vars:
            all_window[var][rel_path] = locations.get(f'window.{var}', [])

    # Find vars that appear in both sets
    mismatches = {}

    all_var_names = set(all_local.keys()) | set(all_window.keys())

    for var_name in all_var_names:
        local_files = set(all_local[var_name].keys())
        window_files = set(all_window[var_name].keys())

        # Check if same var used both ways (either in same file or across files)
        if local_files and window_files:
            mismatches[var_name] = {
                'local': dict(all_local[var_name]),
                'window': dict(all_window[var_name]),
                'same_file': bool(local_files & window_files)
            }

    return mismatches


def main():
    if len(sys.argv) < 2:
        root = Path('/home/gh0st/dvn/divine-workspace/apps/pkn/frontend')
    else:
        root = Path(sys.argv[1])

    if not root.exists():
        print(f"{RED}Error: Path does not exist: {root}{RESET}")
        sys.exit(1)

    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}{'Scope Mismatch Analyzer'.center(70)}{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\nScanning: {root}\n")

    mismatches = find_mismatches(root)

    if not mismatches:
        print(f"{GREEN}✓ No scope mismatches found{RESET}")
        sys.exit(0)

    # Filter to show only significant mismatches (skip common globals like 'init', 'app')
    common_globals = {'init', 'app', 'config', 'utils', 'API', 'eventBus', 'console', 'document', 'fetch'}
    significant = {k: v for k, v in mismatches.items() if k not in common_globals}

    if not significant:
        print(f"{GREEN}✓ No significant scope mismatches (only common globals){RESET}")
        sys.exit(0)

    print(f"{RED}Found {len(significant)} scope mismatch(es):{RESET}\n")

    for var_name, info in sorted(significant.items()):
        severity = "HIGH" if info['same_file'] else "MEDIUM"
        color = RED if info['same_file'] else YELLOW

        print(f"{color}► {var_name} [{severity}]{RESET}")

        if info['local']:
            print(f"  Used as local variable:")
            for file_path, line_nums in info['local'].items():
                print(f"    {file_path}:{','.join(str(ln) for ln in line_nums[:3])}")

        if info['window']:
            print(f"  Used as window.{var_name}:")
            for file_path, line_nums in info['window'].items():
                print(f"    {file_path}:{','.join(str(ln) for ln in line_nums[:3])}")
        print()

    high_severity = sum(1 for v in significant.values() if v['same_file'])

    print(f"{RED}✗ {len(significant)} scope mismatch(es) found{RESET}")
    print(f"  {RED}{high_severity} HIGH{RESET} (same file - likely bugs)")
    print(f"  {YELLOW}{len(significant) - high_severity} MEDIUM{RESET} (cross-file - review needed)")

    print(f"\n{YELLOW}Fix: Use consistent naming - either always local or always window.*{RESET}")
    print(f"{YELLOW}If intentional, document why with a comment.{RESET}")

    sys.exit(1 if high_severity > 0 else 0)


if __name__ == '__main__':
    main()
