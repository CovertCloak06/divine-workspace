#!/usr/bin/env python3
"""
JavaScript Error Checker for PKN
Finds common issues: import/export mismatches, typos, missing files, etc.
"""

import re
import os
from pathlib import Path
from collections import defaultdict

PKN_DIR = Path("/home/gh0st/pkn")
JS_DIR = PKN_DIR / "js"


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_ok(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")


def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.END}")


def print_warn(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")


def print_header(msg):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 70}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{msg}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 70}{Colors.END}\n")


def extract_exports(file_path):
    """Extract all exported functions/variables from a JS file"""
    exports = []
    try:
        with open(file_path) as f:
            content = f.read()

        # Match: export function name() or export const name =
        patterns = [
            r"export\s+function\s+(\w+)",
            r"export\s+const\s+(\w+)",
            r"export\s+let\s+(\w+)",
            r"export\s+var\s+(\w+)",
            r"export\s+default\s+(\w+)",
            r"export\s+{\s*([^}]+)\s*}",  # export { a, b, c }
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if "{" in pattern:  # Handle export { a, b, c }
                    exports.extend([name.strip() for name in match.split(",")])
                else:
                    exports.append(match)

        # Also check for: export default ClassName
        default_match = re.search(r"export\s+default\s+(\w+)", content)
        if default_match:
            exports.append("default")

    except Exception as e:
        print_error(f"Error reading {file_path}: {e}")

    return list(set(exports))  # Remove duplicates


def extract_imports(file_path):
    """Extract all imports from a JS file"""
    imports = {}  # {from_file: [imported_names]}
    try:
        with open(file_path) as f:
            content = f.read()

        # Match: import { a, b } from './file.js'
        # Or: import name from './file.js'
        import_pattern = r'import\s+(?:{([^}]+)}|(\w+))\s+from\s+[\'"]([^\'"]+)[\'"]'

        for match in re.finditer(import_pattern, content):
            named_imports = match.group(1)
            default_import = match.group(2)
            from_file = match.group(3)

            if from_file not in imports:
                imports[from_file] = []

            if named_imports:
                names = [name.strip() for name in named_imports.split(",")]
                imports[from_file].extend(names)

            if default_import:
                imports[from_file].append(default_import)

    except Exception as e:
        print_error(f"Error reading {file_path}: {e}")

    return imports


def resolve_import_path(from_file, import_path):
    """Resolve relative import path to absolute path"""
    if import_path.startswith("./"):
        base_dir = from_file.parent
        resolved = (base_dir / import_path[2:]).resolve()
        return resolved
    elif import_path.startswith("../"):
        base_dir = from_file.parent
        resolved = (base_dir / import_path).resolve()
        return resolved
    else:
        # Absolute or node_modules
        return None


def check_import_export_mismatches():
    """Check for import/export mismatches across all JS files"""
    print_header("IMPORT/EXPORT MISMATCH CHECK")

    js_files = list(JS_DIR.glob("*.js"))
    plugin_files = list((PKN_DIR / "plugins").rglob("plugin.js"))
    all_files = js_files + plugin_files

    # Build export map
    export_map = {}
    for file in all_files:
        exports = extract_exports(file)
        export_map[file] = exports

    errors = []
    warnings = []

    for file in all_files:
        imports = extract_imports(file)

        for import_from, imported_names in imports.items():
            # Resolve the imported file path
            imported_file = resolve_import_path(file, import_from)

            if not imported_file:
                continue  # External dependency

            if not imported_file.exists():
                errors.append(
                    f"{file.name}: imports from non-existent file '{import_from}'"
                )
                continue

            # Check if the imported names exist in the exported file
            if imported_file in export_map:
                available_exports = export_map[imported_file]

                for name in imported_names:
                    if name not in available_exports and name != "default":
                        errors.append(
                            f"{file.name}:{import_from} - "
                            f"imports '{name}' but {imported_file.name} only exports: {', '.join(available_exports)}"
                        )

    if errors:
        for error in errors:
            print_error(error)
    else:
        print_ok("No import/export mismatches found")

    return len(errors)


def check_missing_files():
    """Check for missing imported files"""
    print_header("MISSING FILE CHECK")

    js_files = list(JS_DIR.glob("*.js"))
    errors = []

    for file in js_files:
        imports = extract_imports(file)

        for import_from in imports.keys():
            imported_file = resolve_import_path(file, import_from)

            if imported_file and not imported_file.exists():
                errors.append(
                    f"{file.name}: imports missing file '{import_from}' (resolved to {imported_file})"
                )

    if errors:
        for error in errors:
            print_error(error)
    else:
        print_ok("All imported files exist")

    return len(errors)


def check_undefined_globals():
    """Check for common undefined global references"""
    print_header("UNDEFINED GLOBALS CHECK")

    js_files = list(JS_DIR.glob("*.js"))
    app_js = PKN_DIR / "app.js"
    if app_js.exists():
        js_files.append(app_js)

    # Common globals that should be defined
    expected_globals = {
        "pluginManager": "js/main.js",
        "eventBus": "js/main.js",
        "openPluginsManager": "js/main.js",
        "showToast": "js/utils.js or js/main.js",
    }

    # Check main.js exports these to window
    main_js = JS_DIR / "main.js"
    if main_js.exists():
        with open(main_js) as f:
            main_content = f.read()

        for global_name, expected_file in expected_globals.items():
            if f"window.{global_name}" not in main_content:
                print_warn(f"{global_name} not exported to window in {expected_file}")
            else:
                print_ok(f"{global_name} exported to window")

    return 0


def check_json_import_assertions():
    """Check for JSON import assertions (not supported in older browsers)"""
    print_header("JSON IMPORT ASSERTIONS CHECK")

    js_files = list(JS_DIR.glob("*.js"))
    errors = []

    for file in js_files:
        with open(file) as f:
            content = f.read()

        # Look for assert { type: 'json' }
        if "assert { type: 'json' }" in content or 'assert {type:"json"}' in content:
            errors.append(
                f"{file.name} uses JSON import assertions (not supported in older browsers)"
            )

    if errors:
        for error in errors:
            print_error(error)
    else:
        print_ok("No JSON import assertions found")

    return len(errors)


def check_common_typos():
    """Check for common typos in variable names"""
    print_header("COMMON TYPO CHECK")

    common_mistakes = {
        "saveProjectsFromStorage": "saveProjectsToStorage",
        "loadProjectsToStorage": "loadProjectsFromStorage",
        "pluginManger": "pluginManager",  # common typo
        "mangager": "manager",
    }

    js_files = list(JS_DIR.glob("*.js"))
    errors = []

    for file in js_files:
        with open(file) as f:
            content = f.read()

        for typo, correct in common_mistakes.items():
            if typo in content:
                errors.append(f"{file.name} contains '{typo}' - should be '{correct}'?")

    if errors:
        for error in errors:
            print_warn(error)
    else:
        print_ok("No common typos found")

    return len(errors)


def check_duplicate_function_definitions():
    """Check for duplicate function definitions"""
    print_header("DUPLICATE FUNCTION CHECK")

    js_files = [PKN_DIR / "app.js"] + list(JS_DIR.glob("*.js"))

    all_functions = defaultdict(list)

    for file in js_files:
        if not file.exists():
            continue

        with open(file) as f:
            content = f.read()

        # Find function definitions
        function_pattern = r"(?:function|const|let|var)\s+(\w+)\s*(?:=|"
        functions = re.findall(r"function\s+(\w+)\s*\(", content)

        for func in functions:
            all_functions[func].append(file.name)

    duplicates = {k: v for k, v in all_functions.items() if len(v) > 1}

    if duplicates:
        for func, files in duplicates.items():
            if func not in ["init", "render", "update"]:  # Common names
                print_warn(
                    f"Function '{func}' defined in multiple files: {', '.join(files)}"
                )
    else:
        print_ok("No problematic duplicate functions found")

    return 0


def main():
    print(f"{Colors.BOLD}PKN JavaScript Error Checker{Colors.END}\n")

    total_errors = 0

    # Run all checks
    total_errors += check_import_export_mismatches()
    total_errors += check_missing_files()
    total_errors += check_undefined_globals()
    total_errors += check_json_import_assertions()
    total_errors += check_common_typos()
    total_errors += check_duplicate_function_definitions()

    # Summary
    print_header("SUMMARY")
    if total_errors == 0:
        print_ok(f"All checks passed! No critical errors found.")
    else:
        print_error(f"Found {total_errors} critical error(s) that need fixing")

    return total_errors


if __name__ == "__main__":
    exit(main())
