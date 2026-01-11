#!/usr/bin/env python3
"""
Smart Test Runner - Run tests for changed files
Finds and runs relevant tests for modified source files
"""

import sys
import subprocess
from pathlib import Path


def find_test_for_file(filepath):
    """Find corresponding test file for a source file."""
    path = Path(filepath)

    # Skip if already a test file
    if 'test' in path.stem or path.stem.startswith('test_'):
        return path

    # Python: src/foo.py → tests/unit/test_foo.py
    if path.suffix == '.py':
        # Try multiple test locations
        test_locations = [
            path.parent.parent / 'tests' / 'unit' / f"test_{path.stem}.py",
            path.parent / 'tests' / 'unit' / f"test_{path.stem}.py",
            path.parent / f"test_{path.stem}.py",
        ]
        for test_path in test_locations:
            if test_path.exists():
                return test_path

    # JavaScript/TypeScript: src/foo.js → tests/unit/foo.test.js
    if path.suffix in ['.js', '.ts', '.jsx', '.tsx']:
        test_locations = [
            path.parent.parent / 'tests' / 'unit' / f"{path.stem}.test.js",
            path.parent / 'tests' / 'unit' / f"{path.stem}.test.js",
            path.parent / f"{path.stem}.test.js",
            path.with_suffix('.test' + path.suffix),
        ]
        for test_path in test_locations:
            if test_path.exists():
                return test_path

    return None


def run_python_tests(test_files):
    """Run Python tests with pytest."""
    if not test_files:
        return True

    try:
        result = subprocess.run(
            ['pytest', '-v'] + [str(f) for f in test_files],
            capture_output=False
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️  pytest not found, skipping Python tests")
        return True


def run_js_tests(test_files):
    """Run JavaScript tests with vitest."""
    if not test_files:
        return True

    try:
        result = subprocess.run(
            ['pnpm', 'vitest', 'run'] + [str(f) for f in test_files],
            capture_output=False
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️  vitest not found, skipping JavaScript tests")
        return True


def main():
    """Main entry point."""
    files = sys.argv[1:]

    if not files:
        print("No files to test")
        sys.exit(0)

    python_tests = []
    js_tests = []

    print(f"🔍 Finding tests for {len(files)} changed file(s)...")

    for filepath in files:
        test_file = find_test_for_file(filepath)
        if test_file:
            if test_file.suffix == '.py':
                python_tests.append(test_file)
            else:
                js_tests.append(test_file)

    if not python_tests and not js_tests:
        print("✅ No tests found for changed files (OK)")
        sys.exit(0)

    print(f"\n🧪 Running {len(python_tests)} Python test(s)")
    print(f"🧪 Running {len(js_tests)} JavaScript test(s)")
    print()

    all_passed = True

    if python_tests:
        if not run_python_tests(python_tests):
            all_passed = False

    if js_tests:
        if not run_js_tests(js_tests):
            all_passed = False

    if all_passed:
        print("\n✅ All tests passed")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
