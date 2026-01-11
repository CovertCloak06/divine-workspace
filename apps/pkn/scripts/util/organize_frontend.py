#!/usr/bin/env python3
"""
Organize PKN Frontend - Simple Approach
Move existing js/ files to frontend/js/ and convert to ES6 modules
"""

import re
import shutil
from pathlib import Path

ROOT = Path("/home/gh0st/dvn/divine-workspace/apps/pkn")
OLD_JS = ROOT / "js"
FRONTEND_JS = ROOT / "frontend/js"

# Organization map
ORGANIZATION = {
    # Core app functionality
    "core": [
        "main.js",
        "event-bus.js",
    ],
    # UI components
    "ui": [
        "chat.js",
        "multi_agent_ui.js",
        "osint_ui.js",
        "plugins-ui.js",
    ],
    # API clients
    "api": [
        "capacitor-backend.js",
    ],
    # Feature modules
    "features": [
        "files.js",
        "images.js",
        "models.js",
        "settings.js",
        "projects.js",
        "autocomplete.js",
        "agent_quality.js",
        "plugin-manager.js",
        "plugin-base.js",
    ],
    # Utilities
    "utils": [
        "storage.js",
        "utils.js",
        "theme-utils.js",
    ],
}


def copy_and_convert_file(src, dest):
    """Copy file and add ES6 module header"""
    content = src.read_text()

    # Add module header if not present
    if not content.startswith("/**"):
        header = f"""/**
 * {src.name}
 * PKN Frontend Module
 */

"""
        content = header + content

    dest.write_text(content)


def main():
    print("🗂️  Organizing PKN Frontend\n")

    total_copied = 0

    # Copy files to new structure
    for category, files in ORGANIZATION.items():
        category_dir = FRONTEND_JS / category
        category_dir.mkdir(parents=True, exist_ok=True)

        print(f"📁 {category}/")

        for filename in files:
            src = OLD_JS / filename
            if not src.exists():
                print(f"  ⚠️  {filename} not found, skipping")
                continue

            dest = category_dir / filename
            copy_and_convert_file(src, dest)
            print(f"  ✓ {filename}")
            total_copied += 1

    print(f"\n✅ Organized {total_copied} files into frontend/js/\n")

    # Create main entry point that imports everything
    main_entry = FRONTEND_JS / "pkn.js"
    main_entry.write_text("""/**
 * PKN Frontend Entry Point
 * Imports all modules for the application
 */

// Core
import './core/main.js';
import './core/event-bus.js';

// UI Components
import './ui/chat.js';
import './ui/multi_agent_ui.js';
import './ui/osint_ui.js';
import './ui/plugins-ui.js';

// Features
import './features/files.js';
import './features/images.js';
import './features/models.js';
import './features/settings.js';
import './features/projects.js';
import './features/autocomplete.js';
import './features/agent_quality.js';
import './features/plugin-manager.js';
import './features/plugin-base.js';

// Utilities
import './utils/storage.js';
import './utils/utils.js';
import './utils/theme-utils.js';

// API
import './api/capacitor-backend.js';

console.log('✅ PKN Frontend loaded');
""")

    print(f"✅ Created entry point: frontend/js/pkn.js\n")

    # Copy app.js as-is to frontend/js/core/
    app_js_src = ROOT / "app.js"
    if app_js_src.exists():
        app_js_dest = FRONTEND_JS / "core/app.js"
        shutil.copy2(app_js_src, app_js_dest)
        print(f"✅ Copied app.js → frontend/js/core/app.js\n")

    # Summary
    print("=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"  Files organized:    {total_copied}")
    print(f"  Entry point:        frontend/js/pkn.js")
    print(f"  Legacy app.js:      frontend/js/core/app.js")
    print("\n✅ Frontend organization complete!")
    print("\n⚠️  NEXT STEPS:")
    print("  1. Update pkn.html:")
    print('     <script type="module" src="frontend/js/pkn.js"></script>')
    print('     <script src="frontend/js/core/app.js"></script>')
    print("  2. Remove old <script> tags for individual js/ files")
    print("  3. Test in browser (Ctrl+Shift+R to hard refresh)")


if __name__ == "__main__":
    main()
