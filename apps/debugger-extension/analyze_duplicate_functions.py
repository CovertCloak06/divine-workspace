#!/usr/bin/env python3
"""
Detect duplicate function definitions across JavaScript files.
Catches issues like having openProjectMenu in both app.js and projects.js.
"""

import re
from pathlib import Path
from collections import defaultdict

def find_duplicate_functions(project_dir):
    """Find functions defined in multiple files | ref:CLAUDE.md (Code Documentation Standard)"""
    functions = defaultdict(list)  # Map function name to list of (file, line) tuples

    # Patterns to match function definitions | Handles regular functions, arrow functions, exports
    patterns = [
        r'^\s*function\s+(\w+)\s*\(',  # function name()
        r'^\s*const\s+(\w+)\s*=\s*(?:async\s*)?\(',  # const name = (
        r'^\s*(?:export\s+)?function\s+(\w+)\s*\(',  # export function name()
        r'^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(',  # export const name = (
        r'^\s*(\w+)\s*:\s*(?:async\s*)?function\s*\(',  # name: function()
        r'^\s*async\s+function\s+(\w+)\s*\(',  # async function name()
    ]

    project_path = Path(project_dir)

    # Search all JS files in main directory and js/ subdirectory | ref:pkn.html, app.js, js/*.js
    js_files = list(project_path.glob('*.js')) + list(project_path.glob('js/*.js'))

    for js_file in js_files:
        if 'node_modules' in str(js_file) or '.min.js' in str(js_file):  # Skip minified and dependencies
            continue

        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in patterns:
                        match = re.search(pattern, line)
                        if match:
                            func_name = match.group(1)
                            # Skip common names that are expected to appear multiple times
                            if func_name not in ['init', 'render', 'show', 'hide', 'toggle', 'setup']:
                                functions[func_name].append((str(js_file.relative_to(project_path)), line_num))
                                break  # Only match first pattern per line
        except Exception as e:
            print(f"⚠️  Error reading {js_file}: {e}")

    # Report duplicates | Function appears in 2+ files
    duplicates = {name: locations for name, locations in functions.items() if len(locations) > 1}

    if duplicates:
        print("❌ DUPLICATE FUNCTIONS FOUND:")
        print("=" * 60)
        for func_name, locations in sorted(duplicates.items()):
            print(f"\n🔴 Function: {func_name}")
            for file_path, line_num in locations:
                print(f"   - {file_path}:{line_num}")
        print("\n⚠️  These functions may cause bugs if one is updated and the other isn't.")
        print("   Consider: Remove unused version or rename to avoid conflicts.\n")
        return False
    else:
        print("✅ No duplicate functions found")
        return True

if __name__ == '__main__':
    import sys
    project_dir = sys.argv[1] if len(sys.argv) > 1 else '/home/gh0st/pkn'
    success = find_duplicate_functions(project_dir)
    sys.exit(0 if success else 1)
