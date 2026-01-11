#!/usr/bin/env python3
"""
Plugin System Debugger
Checks if all plugins are properly configured and can be loaded
"""

import os
import json
import sys
from pathlib import Path

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def print_header(text):
    """Print a colored header"""
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}{text}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")

def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓{RESET} {text}")

def print_error(text):
    """Print error message"""
    print(f"{RED}✗{RESET} {text}")

def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠{RESET} {text}")

def check_plugin_directory(plugin_path):
    """
    Check if a plugin directory has all required files
    Returns: (is_valid, errors)
    """
    errors = []

    # Check manifest.json
    manifest_path = plugin_path / "manifest.json"
    if not manifest_path.exists():
        errors.append("Missing manifest.json")
    else:
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)

            # Validate required fields
            required_fields = ['id', 'name', 'version']
            for field in required_fields:
                if field not in manifest:
                    errors.append(f"manifest.json missing required field: {field}")

            # Check optional but important fields
            if 'description' not in manifest:
                errors.append("manifest.json missing description (recommended)")

        except json.JSONDecodeError as e:
            errors.append(f"manifest.json is invalid JSON: {e}")

    # Check plugin.js
    plugin_js_path = plugin_path / "plugin.js"
    if not plugin_js_path.exists():
        errors.append("Missing plugin.js")
    else:
        # Quick check if it exports a class
        content = plugin_js_path.read_text()
        if 'export' not in content and 'class' not in content:
            errors.append("plugin.js doesn't seem to export a class")

    return len(errors) == 0, errors

def main():
    """Main function"""
    print_header("PKN Plugin System Debugger")

    # Get the project root (assuming script is in scripts/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    plugins_dir = project_root / "plugins"

    print(f"Project root: {project_root}")
    print(f"Plugins directory: {plugins_dir}")

    # Check if plugins directory exists
    if not plugins_dir.exists():
        print_error(f"Plugins directory not found: {plugins_dir}")
        sys.exit(1)

    print_success(f"Plugins directory found")

    # Get all plugin directories
    plugin_dirs = [d for d in plugins_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]

    if not plugin_dirs:
        print_warning("No plugin directories found")
        sys.exit(0)

    print(f"\nFound {len(plugin_dirs)} plugin directories\n")

    # Check each plugin
    valid_plugins = 0
    invalid_plugins = 0

    for plugin_dir in sorted(plugin_dirs):
        plugin_name = plugin_dir.name
        is_valid, errors = check_plugin_directory(plugin_dir)

        if is_valid:
            print_success(f"{plugin_name}")
            valid_plugins += 1

            # Show manifest info
            try:
                manifest_path = plugin_dir / "manifest.json"
                with open(manifest_path) as f:
                    manifest = json.load(f)
                print(f"  Name: {manifest.get('name', 'N/A')}")
                print(f"  Version: {manifest.get('version', 'N/A')}")
                print(f"  Description: {manifest.get('description', 'N/A')}")
            except:
                pass
        else:
            print_error(f"{plugin_name}")
            invalid_plugins += 1
            for error in errors:
                print(f"  → {error}")

        print()  # Blank line between plugins

    # Summary
    print_header("Summary")
    print(f"Valid plugins: {GREEN}{valid_plugins}{RESET}")
    print(f"Invalid plugins: {RED}{invalid_plugins}{RESET}")

    if invalid_plugins > 0:
        print(f"\n{YELLOW}Fix the errors above to enable these plugins{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}All plugins are properly configured!{RESET}")

        # Additional checks
        print_header("Additional Checks")

        # Check if pkn.html loads plugins
        pkn_html = project_root / "frontend" / "pkn.html"
        if pkn_html.exists():
            content = pkn_html.read_text()
            if 'pluginManager' in content:
                print_success("pkn.html has plugin manager code")
            else:
                print_warning("pkn.html might not initialize plugin manager")

            if 'import.*plugin.*from' in content or 'WelcomeMessagePlugin' in content:
                print_success("pkn.html imports plugin classes")
            else:
                print_warning("pkn.html might not import plugin classes")
        else:
            print_error("pkn.html not found")

        # Check if server is running
        import urllib.request
        try:
            response = urllib.request.urlopen('http://localhost:8010/health', timeout=2)
            print_success("Server is running on port 8010")
        except:
            print_warning("Server is not running (start with ./pkn_control.sh start-all)")

        sys.exit(0)

if __name__ == "__main__":
    main()
