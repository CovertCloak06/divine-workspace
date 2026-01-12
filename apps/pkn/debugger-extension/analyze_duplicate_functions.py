#!/usr/bin/env python3
"""
Duplicate Function Analyzer
Finds functions/methods defined in multiple files - a common source of bugs.

Example bug this catches:
  - openProjectMenu() defined in both app.js and projects.js
  - One shadows the other, causing unexpected behavior
"""

import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

# Colors for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


def extract_js_functions(file_path: Path) -> List[Tuple[str, int]]:
    """Extract function names and line numbers from a JS file."""
    functions = []

    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"{YELLOW}Warning: Could not read {file_path}: {e}{RESET}")
        return []

    patterns = [
        # function declarations: function name(
        r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
        # arrow functions assigned to const/let/var: const name = (
        r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>',
        # arrow functions assigned to const/let/var (no parens): const name = arg =>
        r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?[a-zA-Z_$][a-zA-Z0-9_$]*\s*=>',
        # method definitions in objects/classes: name( or name: function(
        r'^\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*\{',
        # window.name = function
        r'window\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?function',
        # export function name(
        r'export\s+(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
    ]

    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern in patterns:
            matches = re.findall(pattern, line)
            for match in matches:
                # Skip common non-function matches
                if match in ('if', 'for', 'while', 'switch', 'catch', 'with'):
                    continue
                functions.append((match, line_num))

    return functions


def extract_py_functions(file_path: Path) -> List[Tuple[str, int]]:
    """Extract function/method names and line numbers from a Python file."""
    functions = []

    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"{YELLOW}Warning: Could not read {file_path}: {e}{RESET}")
        return []

    pattern = r'^\s*(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('

    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        matches = re.findall(pattern, line)
        for match in matches:
            # Skip dunder methods - they're supposed to be duplicated
            if match.startswith('__') and match.endswith('__'):
                continue
            functions.append((match, line_num))

    return functions


def find_duplicates(root_path: Path, extensions: List[str]) -> Dict[str, List[Tuple[Path, int]]]:
    """Find all duplicate function definitions across files."""
    function_locations = defaultdict(list)

    # Directories and patterns to skip (build artifacts, backups, submodules)
    skip_patterns = [
        'node_modules', '.venv', 'vendor', '__pycache__', 'llama.cpp',
        '/archive/', '/android/', '/www/',  # Capacitor build outputs
        '.backup', '.bak', '.old', '.disabled',  # Backup files
        'old-code', 'old_code',  # Legacy code directories
        'apps/pkn/plugins/',  # Duplicate of frontend/js/plugins/ - exclude to avoid false positives
    ]

    for ext in extensions:
        for file_path in root_path.rglob(f'*{ext}'):
            # Skip excluded directories and patterns
            if any(skip in str(file_path) for skip in skip_patterns):
                continue

            if ext in ['.js', '.mjs', '.ts']:
                functions = extract_js_functions(file_path)
            elif ext == '.py':
                functions = extract_py_functions(file_path)
            else:
                continue

            for func_name, line_num in functions:
                function_locations[func_name].append((file_path, line_num))

    # Filter to only duplicates (defined in 2+ files)
    duplicates = {
        name: locations
        for name, locations in function_locations.items()
        if len(set(loc[0] for loc in locations)) > 1  # Different files
    }

    return duplicates


def main():
    if len(sys.argv) < 2:
        root = Path('/home/gh0st/dvn/divine-workspace/apps/pkn')
    else:
        root = Path(sys.argv[1])

    if not root.exists():
        print(f"{RED}Error: Path does not exist: {root}{RESET}")
        sys.exit(1)

    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}{'Duplicate Function Analyzer'.center(70)}{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\nScanning: {root}\n")

    # Find duplicates in JS and Python files
    duplicates = find_duplicates(root, ['.js', '.mjs', '.py'])

    if not duplicates:
        print(f"{GREEN}✓ No duplicate functions found across files{RESET}")
        sys.exit(0)

    # Report duplicates
    print(f"{RED}Found {len(duplicates)} duplicate function(s):{RESET}\n")

    for func_name, locations in sorted(duplicates.items()):
        print(f"{YELLOW}► {func_name}(){RESET}")

        # Group by file
        by_file = defaultdict(list)
        for file_path, line_num in locations:
            by_file[file_path].append(line_num)

        for file_path, line_nums in by_file.items():
            rel_path = file_path.relative_to(root) if file_path.is_relative_to(root) else file_path
            lines_str = ', '.join(str(ln) for ln in line_nums)
            print(f"    {rel_path}:{lines_str}")
        print()

    print(f"{RED}✗ {len(duplicates)} duplicate function(s) found{RESET}")
    print(f"\n{YELLOW}Fix: Ensure each function is defined in only one file.{RESET}")
    print(f"{YELLOW}If intentional, use different names or proper module exports.{RESET}")

    sys.exit(1)


if __name__ == '__main__':
    main()
