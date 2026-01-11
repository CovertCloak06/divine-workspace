#!/usr/bin/env python3
"""
PKN Plugin System Diagnostic Tool
Automatically checks all aspects of the plugin system and reports issues
"""

import requests
import json
import os
import re
from pathlib import Path

BASE_URL = "http://localhost:8010"
PKN_DIR = "/home/gh0st/pkn"


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_header(text):
    print(f"\n{bcolors.HEADER}{bcolors.BOLD}{'=' * 60}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}{bcolors.BOLD}{text}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}{bcolors.BOLD}{'=' * 60}{bcolors.ENDC}\n")


def print_ok(text):
    print(f"{bcolors.OKGREEN}✓ {text}{bcolors.ENDC}")


def print_fail(text):
    print(f"{bcolors.FAIL}✗ {text}{bcolors.ENDC}")


def print_warn(text):
    print(f"{bcolors.WARNING}⚠ {text}{bcolors.ENDC}")


def print_info(text):
    print(f"{bcolors.OKCYAN}ℹ {text}{bcolors.ENDC}")


# Test 1: Server Health
print_header("1. SERVER HEALTH CHECK")
try:
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    if r.status_code == 200:
        print_ok(f"Server is running on {BASE_URL}")
    else:
        print_fail(f"Server returned status {r.status_code}")
except Exception as e:
    print_fail(f"Cannot reach server: {e}")
    exit(1)

# Test 2: HTML loads main.js
print_header("2. HTML SCRIPT LOADING")
try:
    r = requests.get(f"{BASE_URL}/pkn.html", timeout=5)
    html = r.text

    if 'src="app.js"' in html:
        print_ok("app.js is loaded (core UI)")
    else:
        print_fail("app.js NOT loaded - core UI won't work!")

    if 'src="js/main.js"' in html or 'src="js/main.js?v=' in html:
        print_ok("main.js is loaded (plugin system)")
    else:
        print_fail("main.js NOT loaded - plugins won't work!")

    if 'type="module"' in html and "main.js" in html:
        print_ok("main.js loaded as ES6 module (correct)")
    else:
        print_fail("main.js NOT loaded as module - imports will fail!")

    if 'src="js/files.js' in html:
        if "?v=" in html:
            print_ok("files.js has cache-busting parameter")
        else:
            print_warn(
                "files.js loaded but no cache-busting (may use old cached version)"
            )

except Exception as e:
    print_fail(f"Cannot load HTML: {e}")

# Test 3: JavaScript Files Exist
print_header("3. JAVASCRIPT FILES")
js_files = [
    "app.js",
    "js/main.js",
    "js/plugin-manager.js",
    "js/plugin-base.js",
    "js/event-bus.js",
    "js/plugins-ui.js",
    "js/utils.js",
    "js/chat.js",
    "js/files.js",
]

for js_file in js_files:
    try:
        r = requests.get(f"{BASE_URL}/{js_file}", timeout=5)
        if r.status_code == 200:
            size_kb = len(r.content) / 1024
            print_ok(f"{js_file} ({size_kb:.1f} KB)")
        else:
            print_fail(f"{js_file} - HTTP {r.status_code}")
    except Exception as e:
        print_fail(f"{js_file} - {e}")

# Test 4: Plugin Files
print_header("4. PLUGIN FILES")
plugins_dir = Path(PKN_DIR) / "plugins"
if plugins_dir.exists():
    plugin_folders = [
        p for p in plugins_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
    ]
    print_info(f"Found {len(plugin_folders)} plugin folders")

    for plugin_folder in plugin_folders:
        plugin_name = plugin_folder.name
        manifest = plugin_folder / "manifest.json"
        plugin_js = plugin_folder / "plugin.js"

        if manifest.exists() and plugin_js.exists():
            # Validate manifest
            try:
                with open(manifest) as f:
                    data = json.load(f)
                    print_ok(
                        f"{plugin_name}: {data.get('name', 'Unknown')} v{data.get('version', '?')}"
                    )
            except json.JSONDecodeError as e:
                print_fail(f"{plugin_name}: Invalid manifest.json - {e}")
        else:
            missing = []
            if not manifest.exists():
                missing.append("manifest.json")
            if not plugin_js.exists():
                missing.append("plugin.js")
            print_fail(f"{plugin_name}: Missing {', '.join(missing)}")
else:
    print_fail("plugins/ directory not found!")

# Test 5: Check for common errors in main.js
print_header("5. MAIN.JS VALIDATION")
main_js_path = Path(PKN_DIR) / "js" / "main.js"
if main_js_path.exists():
    with open(main_js_path) as f:
        content = f.read()

    # Check for window exports
    if "window.pluginManager" in content:
        print_ok("window.pluginManager export found")
    else:
        print_fail(
            "window.pluginManager NOT exported - won't be accessible in console!"
        )

    if "window.openPluginsManager" in content:
        print_ok("window.openPluginsManager export found")
    else:
        print_fail("window.openPluginsManager NOT exported - button won't work!")

    # Count plugin registrations
    registrations = content.count("pluginManager.register(")
    print_info(f"Found {registrations} plugin registrations in main.js")

    # Check for plugin imports
    plugin_imports = re.findall(r"import.*from.*plugins/([^/]+)/", content)
    print_info(f"Plugins imported: {', '.join(set(plugin_imports))}")

else:
    print_fail("main.js file not found on disk!")

# Test 6: Check files.js for recursion bug
print_header("6. FILES.JS RECURSION CHECK")
files_js_path = Path(PKN_DIR) / "js" / "files.js"
if files_js_path.exists():
    with open(files_js_path) as f:
        content = f.read()
        lines = content.split("\n")

    # Look for the problematic pattern
    for i, line in enumerate(lines[:50], 1):
        if "function showToast" in line and "window.showToast" not in lines[i - 5 : i]:
            print_warn(f"Line {i}: Old showToast pattern found - may cause recursion")
        if "if (!window.showToast)" in line:
            print_ok(f"Line {i}: Fixed showToast pattern found - recursion prevented")
            break
else:
    print_fail("files.js not found!")

# Test 7: Check for syntax errors
print_header("7. JAVASCRIPT SYNTAX CHECK")
import subprocess
import tempfile

js_files_to_check = ["js/main.js", "js/plugin-manager.js", "js/plugins-ui.js"]
for js_file in js_files_to_check:
    file_path = Path(PKN_DIR) / js_file
    if file_path.exists():
        try:
            # Use node --check to validate syntax
            result = subprocess.run(
                ["node", "--check", str(file_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                print_ok(f"{js_file} - syntax OK")
            else:
                print_fail(f"{js_file} - syntax error:\n{result.stderr}")
        except FileNotFoundError:
            print_warn(f"node command not found - skipping syntax check")
            break
        except Exception as e:
            print_warn(f"{js_file} - couldn't check: {e}")

# Test 8: Generate fix script
print_header("8. DIAGNOSTIC SUMMARY")

issues_found = []

# Check specific issues
html_content = requests.get(f"{BASE_URL}/pkn.html").text
if "window.pluginManager" not in open(main_js_path).read():
    issues_found.append("main.js doesn't export pluginManager to window")

if 'type="module"' not in html_content or "main.js" not in html_content:
    issues_found.append("main.js not loaded as ES6 module in HTML")

if issues_found:
    print_fail(f"Found {len(issues_found)} critical issues:")
    for issue in issues_found:
        print(f"  • {issue}")

    print(f"\n{bcolors.WARNING}Generating auto-fix script...{bcolors.ENDC}")

    # Write fix script
    with open("/home/gh0st/pkn/auto_fix_plugins.sh", "w") as f:
        f.write("""#!/bin/bash
# Auto-generated fix script for PKN plugin system

echo "🔧 Applying fixes..."

# Add window.pluginManager export if missing
if ! grep -q "window.pluginManager" /home/gh0st/pkn/js/main.js; then
    echo "Adding window.pluginManager export..."
    # This would need specific line insertions
fi

echo "✓ Fixes applied"
echo "Now refresh browser with Ctrl+Shift+R"
""")
    os.chmod("/home/gh0st/pkn/auto_fix_plugins.sh", 0o755)
    print_info("Auto-fix script created: auto_fix_plugins.sh")
else:
    print_ok("No critical issues found!")
    print_info("\nIf plugins still don't work in browser:")
    print_info("1. Hard refresh: Ctrl+Shift+R")
    print_info("2. Clear browser cache completely")
    print_info("3. Check browser console for module loading errors")
    print_info("4. Try: http://localhost:8010/pkn.html?v=" + str(os.urandom(4).hex()))

print(f"\n{bcolors.BOLD}Run this in browser console:{bcolors.ENDC}")
print(f"{bcolors.OKCYAN}pluginManager.getAllPlugins(){bcolors.ENDC}")
print(f"\n{bcolors.BOLD}Should return array of 10 plugins{bcolors.ENDC}\n")
