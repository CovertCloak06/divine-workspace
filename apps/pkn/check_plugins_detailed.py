#!/usr/bin/env python3
"""
Detailed Plugin System Checker
Deep validation of plugin architecture
"""

import json
from pathlib import Path

PKN_DIR = Path(__file__).parent
PLUGINS_DIR = PKN_DIR / "plugins"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_ok(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.END}")

def print_warn(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")

def print_header(msg):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{msg}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}\n")

def check_plugin_structure(plugin_dir):
    """Check if plugin has required files and structure"""
    errors = []
    warnings = []

    # Check required files
    manifest = plugin_dir / "manifest.json"
    plugin_js = plugin_dir / "plugin.js"

    if not manifest.exists():
        errors.append("manifest.json missing")
    if not plugin_js.exists():
        errors.append("plugin.js missing")

    # Validate manifest
    if manifest.exists():
        try:
            with open(manifest) as f:
                data = json.load(f)

            required_fields = ['id', 'name', 'version', 'description']
            for field in required_fields:
                if field not in data:
                    errors.append(f"manifest.json missing required field: {field}")

            # Check if ID matches directory name
            if data.get('id') != plugin_dir.name:
                warnings.append(f"ID '{data.get('id')}' doesn't match directory name '{plugin_dir.name}'")

        except json.JSONDecodeError as e:
            errors.append(f"manifest.json invalid JSON: {e}")

    # Check plugin.js exports
    if plugin_js.exists():
        content = plugin_js.read_text()

        if 'export class' not in content and 'export default' not in content:
            errors.append("plugin.js doesn't export a class")

        if 'extends PluginBase' not in content:
            warnings.append("Plugin class doesn't extend PluginBase")

    return errors, warnings

def main():
    print(f"{Colors.CYAN}{Colors.BOLD}PKN Plugin System Checker{Colors.END}\n")

    if not PLUGINS_DIR.exists():
        print_error(f"Plugins directory not found: {PLUGINS_DIR}")
        return 1

    plugin_dirs = [p for p in PLUGINS_DIR.iterdir() if p.is_dir() and not p.name.startswith('.')]

    print(f"Found {len(plugin_dirs)} plugin directories\n")

    total_errors = 0
    total_warnings = 0

    for plugin_dir in sorted(plugin_dirs):
        print_header(f"Plugin: {plugin_dir.name}")

        errors, warnings = check_plugin_structure(plugin_dir)

        if not errors and not warnings:
            print_ok("All checks passed")
        else:
            for error in errors:
                print_error(error)
                total_errors += 1
            for warning in warnings:
                print_warn(warning)
                total_warnings += 1

    print_header("Summary")
    if total_errors == 0 and total_warnings == 0:
        print_ok("All plugins are valid!")
    else:
        if total_errors > 0:
            print_error(f"{total_errors} error(s) found")
        if total_warnings > 0:
            print_warn(f"{total_warnings} warning(s)")

    return total_errors

if __name__ == "__main__":
    exit(main())
