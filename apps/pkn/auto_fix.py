#!/usr/bin/env python3
"""
Auto-Fix Script for PKN
Automatically fixes common JavaScript issues
"""

import re
from pathlib import Path

PKN_DIR = Path(__file__).parent
JS_DIR = PKN_DIR / "js"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_ok(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_fix(msg):
    print(f"{Colors.CYAN}🔧 {msg}{Colors.END}")

def print_warn(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")

def fix_common_typos():
    """Fix common typos in import statements"""
    print(f"\n{Colors.BOLD}Fixing common typos...{Colors.END}\n")

    typo_map = {
        'saveProjectsFromStorage': 'saveProjectsToStorage',
        'loadProjectsToStorage': 'loadProjectsFromStorage',
        'SmartContextDetectorPlugin': 'ContextDetectorPlugin',
    }

    js_files = list(JS_DIR.glob("*.js"))
    fixed_count = 0

    for file in js_files:
        content = file.read_text()
        original = content

        for typo, correct in typo_map.items():
            if typo in content:
                content = content.replace(typo, correct)
                print_fix(f"{file.name}: {typo} → {correct}")
                fixed_count += 1

        if content != original:
            file.write_text(content)

    if fixed_count == 0:
        print_ok("No typos found")
    else:
        print_ok(f"Fixed {fixed_count} typo(s)")

    return fixed_count

def add_missing_exports():
    """Add missing exports to window object"""
    print(f"\n{Colors.BOLD}Checking window exports...{Colors.END}\n")

    main_js = JS_DIR / "main.js"
    if not main_js.exists():
        print_warn("main.js not found")
        return 0

    content = main_js.read_text()

    required_exports = [
        ('pluginManager', 'plugin-manager.js'),
        ('eventBus', 'event-bus.js'),
        ('openPluginsManager', 'plugins-ui.js'),
        ('closePluginsManager', 'plugins-ui.js'),
    ]

    for export_name, source in required_exports:
        if f'window.{export_name}' in content:
            print_ok(f"window.{export_name} already exported")
        else:
            print_warn(f"window.{export_name} not found - manual fix needed")

    return 0

def remove_json_assertions():
    """Remove JSON import assertions for browser compatibility"""
    print(f"\n{Colors.BOLD}Removing JSON import assertions...{Colors.END}\n")

    js_files = list(JS_DIR.glob("*.js"))
    fixed_count = 0

    for file in js_files:
        content = file.read_text()
        original = content

        # Remove assert { type: 'json' }
        content = re.sub(r'\s*assert\s*{\s*type:\s*[\'"]json[\'"]\s*}', '', content)

        if content != original:
            file.write_text(content)
            print_fix(f"{file.name}: Removed JSON assertions")
            fixed_count += 1

    if fixed_count == 0:
        print_ok("No JSON assertions found")
    else:
        print_ok(f"Fixed {fixed_count} file(s)")

    return fixed_count

def main():
    print(f"{Colors.CYAN}{Colors.BOLD}PKN Auto-Fix Tool{Colors.END}\n")

    total_fixes = 0
    total_fixes += fix_common_typos()
    total_fixes += add_missing_exports()
    total_fixes += remove_json_assertions()

    print(f"\n{Colors.BOLD}Summary:{Colors.END}")
    if total_fixes == 0:
        print_ok("No issues found to fix")
    else:
        print_ok(f"Applied {total_fixes} automatic fix(es)")
        print_warn("Run './dev check' to verify fixes")

if __name__ == "__main__":
    main()
