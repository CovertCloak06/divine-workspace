#!/usr/bin/env python3
"""
File Size Checker - Enforce 200-line maximum
Ensures all source files stay under 200 lines for maintainability
"""

import sys
from pathlib import Path

MAX_LINES = 200

# Paths to ignore (build artifacts, dependencies, etc.)
IGNORED_PATHS = [
    'node_modules',
    'dist',
    'build',
    '.venv',
    'venv',
    '__pycache__',
    '.git',
    'llama.cpp',
    'data',
    'android',
    '.buildozer',
    'lessons',
    'css',  # CSS files can be longer (visual styling)
]

# File extensions to check
SOURCE_EXTENSIONS = ['.py', '.js', '.ts', '.jsx', '.tsx']


def should_check_file(filepath):
    """Determine if file should be checked for size limit."""
    path = Path(filepath)

    # Skip if in ignored paths
    if any(ignore in filepath for ignore in IGNORED_PATHS):
        return False

    # Only check source files
    if path.suffix not in SOURCE_EXTENSIONS:
        return False

    # Skip test files (they can be longer)
    if 'test' in path.stem or path.stem.startswith('test_'):
        return False

    # Skip config files
    if path.name in ['vite.config.js', 'vitest.config.js', 'jest.config.js']:
        return False

    return True


def check_file_size(filepath):
    """Check if file exceeds 200 lines."""
    if not should_check_file(filepath):
        return True

    try:
        path = Path(filepath)
        if not path.exists():
            return True

        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Count non-empty lines (excluding pure whitespace and comments)
        non_empty_lines = [
            line for line in lines
            if line.strip() and not line.strip().startswith('#')
        ]

        line_count = len(lines)
        actual_count = len(non_empty_lines)

        if line_count > MAX_LINES:
            print(f"❌ {filepath}: {line_count} lines (max {MAX_LINES})")
            print(f"   └─ {actual_count} non-empty lines")
            print(f"   └─ Split into smaller modules")
            return False

        return True

    except Exception as e:
        print(f"⚠️  Error checking {filepath}: {e}")
        return True  # Don't fail on errors


def main():
    """Check all provided files."""
    files = sys.argv[1:]

    if not files:
        print("Usage: check_file_size.py <file1> <file2> ...")
        sys.exit(0)

    failed = []
    checked = 0

    for filepath in files:
        if should_check_file(filepath):
            checked += 1
            if not check_file_size(filepath):
                failed.append(filepath)

    if failed:
        print(f"\n{'='*60}")
        print(f"❌ {len(failed)} file(s) exceed 200-line limit")
        print(f"{'='*60}")
        print("\nOptions to fix:")
        print("1. Split into smaller modules (recommended)")
        print("2. Extract functions to separate files")
        print("3. Move to packages/ if shared code")
        print("4. Add to IGNORED_PATHS if intentional (rare)")
        sys.exit(1)
    else:
        if checked > 0:
            print(f"✅ All {checked} file(s) under 200 lines")
        sys.exit(0)


if __name__ == '__main__':
    main()
