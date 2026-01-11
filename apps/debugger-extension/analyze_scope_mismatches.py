#!/usr/bin/env python3
"""
Detect variable scope mismatches (local vs window.variable).
Catches issues like openMenuElement vs window.openMenuElement.
"""

import re
from pathlib import Path
from collections import defaultdict


def find_scope_mismatches(project_dir):
    """Find variables used as both local and window.variable | ref:CLAUDE.md (Code Documentation Standard)"""

    # Track variable usage patterns | Map var_name -> {files using local, files using window.var}
    local_usage = defaultdict(set)  # var_name -> set of files
    window_usage = defaultdict(set)  # var_name -> set of files

    project_path = Path(project_dir)
    js_files = list(project_path.glob("*.js")) + list(project_path.glob("js/*.js"))

    for js_file in js_files:
        if "node_modules" in str(js_file) or ".min.js" in str(js_file):
            continue

        file_rel = str(js_file.relative_to(project_path))

        try:
            with open(js_file, "r", encoding="utf-8") as f:
                content = f.read()

                # Find all window.variableName patterns | Matches window.foo, window['foo'], etc
                window_vars = re.findall(r"window\.(\w+)", content)
                for var_name in window_vars:
                    window_usage[var_name].add(file_rel)

                # Find local variable assignments/declarations | let, const, var
                # Patterns: let foo =, const foo =, var foo =, foo = (assignment)
                local_patterns = [
                    r"(?:let|const|var)\s+(\w+)\s*=",  # Declaration with assignment
                    r"^\s*(\w+)\s*=(?!=)",  # Assignment at line start (not ==)
                ]

                for line in content.split("\n"):
                    for pattern in local_patterns:
                        matches = re.findall(pattern, line)
                        for var_name in matches:
                            # Only track if this variable is also used as window.variable elsewhere
                            if var_name in window_usage or len(window_vars) > 0:
                                local_usage[var_name].add(file_rel)

        except Exception as e:
            print(f"⚠️  Error reading {js_file}: {e}")

    # Find mismatches | Variable used as both local and window.variable
    mismatches = {}
    for var_name in set(local_usage.keys()) | set(window_usage.keys()):
        local_files = local_usage.get(var_name, set())
        window_files = window_usage.get(var_name, set())

        # Mismatch if used differently in different files OR both ways in same file
        if local_files and window_files:
            mismatches[var_name] = {"local": local_files, "window": window_files}

    if mismatches:
        print("❌ SCOPE MISMATCHES FOUND:")
        print("=" * 60)
        for var_name, usage in sorted(mismatches.items()):
            print(f"\n🔴 Variable: {var_name}")
            if usage["local"]:
                print(f"   Used as LOCAL in:")
                for file_path in sorted(usage["local"]):
                    print(f"      - {file_path}")
            if usage["window"]:
                print(f"   Used as WINDOW.{var_name} in:")
                for file_path in sorted(usage["window"]):
                    print(f"      - {file_path}")

        print("\n⚠️  Scope mismatches can cause bugs where code doesn't see changes.")
        print(
            "   Consider: Use consistent scope (all window.var or all local with proper passing).\n"
        )
        return False
    else:
        print("✅ No scope mismatches found")
        return True


if __name__ == "__main__":
    import sys

    project_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/gh0st/pkn"
    success = find_scope_mismatches(project_dir)
    sys.exit(0 if success else 1)
