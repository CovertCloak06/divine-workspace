#!/usr/bin/env python3
"""
Verify function usage before removing duplicates.
Helps ensure you're removing the UNUSED version, not the active one.

Usage:
    python3 verify_before_fix.py <function_name> [project_dir]

Example:
    python3 verify_before_fix.py closeHistoryMenu /home/gh0st/pkn
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

def find_function_calls(function_name, project_dir):
    """Find all calls to a function | Shows which files use it | ref:CLAUDE.md (Code Documentation Standard)"""

    project_path = Path(project_dir)

    # Find where function is defined | Multiple definitions = duplicates
    definitions = []  # List of (file, line_num, context)

    # Find where function is called | Shows which version is actually used
    calls = []  # List of (file, line_num, context)

    # Find where function is imported | Shows module dependencies
    imports = []  # List of (file, line_num, context)

    # Search all JS files
    js_files = list(project_path.glob('*.js')) + list(project_path.glob('js/*.js'))

    for js_file in js_files:
        if 'node_modules' in str(js_file) or '.min.js' in str(js_file):
            continue

        file_rel = str(js_file.relative_to(project_path))

        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

                for line_num, line in enumerate(lines, 1):
                    # Check for function definition | function foo(), const foo = (), export function foo()
                    def_patterns = [
                        rf'^\s*function\s+{function_name}\s*\(',
                        rf'^\s*const\s+{function_name}\s*=\s*(?:async\s*)?\(',
                        rf'^\s*(?:export\s+)?function\s+{function_name}\s*\(',
                        rf'^\s*(?:export\s+)?const\s+{function_name}\s*=\s*(?:async\s*)?\(',
                    ]

                    for pattern in def_patterns:
                        if re.search(pattern, line):
                            definitions.append((file_rel, line_num, line.strip()))
                            break

                    # Check for function calls | foo(), window.foo(), obj.foo()
                    call_pattern = rf'{function_name}\s*\('
                    if re.search(call_pattern, line) and not any(re.search(p, line) for p in def_patterns):
                        # Exclude definition lines
                        calls.append((file_rel, line_num, line.strip()))

                    # Check for imports | import { foo } from './bar'
                    import_pattern = rf'import\s+.*{function_name}.*from'
                    if re.search(import_pattern, line):
                        imports.append((file_rel, line_num, line.strip()))

        except Exception as e:
            print(f"⚠️  Error reading {js_file}: {e}")

    # Print results
    print("=" * 70)
    print(f"🔍 Function Analysis: {function_name}")
    print("=" * 70)

    if definitions:
        print(f"\n📍 DEFINITIONS ({len(definitions)}):")
        for file_path, line_num, context in definitions:
            print(f"   {file_path}:{line_num}")
            print(f"      {context}")
    else:
        print("\n❌ No definitions found")

    if imports:
        print(f"\n📦 IMPORTS ({len(imports)}):")
        for file_path, line_num, context in imports:
            print(f"   {file_path}:{line_num}")
            print(f"      {context}")

    if calls:
        print(f"\n📞 FUNCTION CALLS ({len(calls)}):")
        # Group by file
        calls_by_file = defaultdict(list)
        for file_path, line_num, context in calls:
            calls_by_file[file_path].append((line_num, context))

        for file_path in sorted(calls_by_file.keys()):
            print(f"\n   {file_path}:")
            for line_num, context in calls_by_file[file_path]:
                print(f"      Line {line_num}: {context}")
    else:
        print("\n⚠️  No calls found - function may be unused!")

    # Analysis
    print("\n" + "=" * 70)
    print("📊 ANALYSIS:")
    print("=" * 70)

    if len(definitions) > 1:
        print(f"⚠️  {len(definitions)} definitions found - DUPLICATE FUNCTION")
        print("   Action: Determine which version is used, remove the other")
    elif len(definitions) == 1:
        print("✅ Single definition found")

    if len(calls) == 0 and len(imports) == 0:
        print("⚠️  No calls or imports found - POSSIBLY DEAD CODE")
        print("   Action: Safe to remove if truly unused")
    else:
        print(f"✅ Function is used ({len(calls)} calls, {len(imports)} imports)")

    if len(imports) > 0:
        print("📦 Function is imported by modules - likely the active version")

    print("\n" + "=" * 70)
    print("💡 RECOMMENDATION:")
    print("=" * 70)

    if len(definitions) > 1:
        if len(imports) > 0:
            print("✅ SAFE TO FIX:")
            print("   - Keep the version that's imported (likely in js/ module)")
            print("   - Remove the version that's NOT imported (likely in app.js)")
        else:
            print("⚠️  REQUIRES INVESTIGATION:")
            print("   - Both versions are in global scope (neither imported)")
            print("   - Check which file loads first in HTML")
            print("   - Test in browser to see which actually runs")
    elif len(definitions) == 1 and len(calls) == 0:
        print("⚠️  POSSIBLY DEAD CODE:")
        print("   - Function defined but never called")
        print("   - Safe to remove if confirmed unused")
    else:
        print("✅ NO ACTION NEEDED - Single definition, in use")

    print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 verify_before_fix.py <function_name> [project_dir]")
        print("\nExample:")
        print("  python3 verify_before_fix.py closeHistoryMenu /home/gh0st/pkn")
        sys.exit(1)

    function_name = sys.argv[1]
    project_dir = sys.argv[2] if len(sys.argv) > 2 else '/home/gh0st/pkn'

    find_function_calls(function_name, project_dir)
