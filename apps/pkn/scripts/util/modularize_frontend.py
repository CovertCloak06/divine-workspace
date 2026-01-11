#!/usr/bin/env python3
"""
Modularize PKN Frontend
Extracts app.js functions into ES6 modules and organizes existing js/ files
"""

import re
import shutil
from pathlib import Path

# Paths
ROOT = Path("/home/gh0st/dvn/divine-workspace/apps/pkn")
APP_JS = ROOT / "app.js"
OLD_JS = ROOT / "js"
FRONTEND = ROOT / "frontend/js"

# Module organization mapping
MODULE_MAP = {
    # Existing modular files -> frontend locations
    "chat.js": "ui/chat",
    "files.js": "features/files",
    "images.js": "features/images",
    "models.js": "features/models",
    "settings.js": "features/settings",
    "projects.js": "features/projects",
    "autocomplete.js": "features/autocomplete",
    "agent_quality.js": "features/agent-quality",
    "multi_agent_ui.js": "ui/multi-agent",
    "osint_ui.js": "ui/osint",
    "plugin-manager.js": "features/plugins",
    "plugin-base.js": "features/plugins",
    "plugins-ui.js": "ui/plugins",
    "storage.js": "utils/storage",
    "utils.js": "utils/helpers",
    "theme-utils.js": "utils/theme",
    "event-bus.js": "core/events",
    "main.js": "core/main",
    "capacitor-backend.js": "api/capacitor",
}

# Functions to extract from app.js
EXTRACTIONS = {
    "utils/toast.js": [
        "showToast",
        "formatError",
        "showFormattedError",
    ],
    "ui/welcome.js": [
        "hideWelcomeScreen",
        "showWelcomeScreen",
    ],
    "ui/sidebar.js": [
        "toggleSidebar",
        "openSidebar",
        "closeSidebar",
    ],
    "ui/modals.js": [
        "toggleSettings",
        "openSettingsModal",
        "closeSettingsModal",
        "toggleAgentSwitcher",
    ],
    "core/app.js": [
        "initializeApp",
        "setupEventListeners",
    ],
    "api/client.js": [
        "sendMessage",
        "sendExample",
        "stopGeneration",
    ],
}


def move_existing_files():
    """Move existing js/*.js files to frontend/js structure"""
    print("📦 Moving existing modular files...")

    moved = 0
    for filename, dest_path in MODULE_MAP.items():
        src = OLD_JS / filename
        if not src.exists():
            continue

        # Determine destination directory
        dest_dir = (
            FRONTEND / dest_path.rsplit("/", 1)[0] if "/" in dest_path else FRONTEND
        )
        dest_file = dest_dir / filename

        # Create directory if needed
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Copy file (keep original for now)
        shutil.copy2(src, dest_file)
        print(f"  ✓ {filename} → frontend/js/{dest_path}/{filename}")
        moved += 1

    print(f"✅ Moved {moved} existing files\n")
    return moved


def extract_function(content, func_name):
    """Extract a function definition from JavaScript content"""
    # Match function declaration
    pattern = rf"^(function {re.escape(func_name)}\s*\([^)]*\)\s*{{)"

    lines = content.split("\n")
    result = []
    in_function = False
    brace_count = 0

    for line in lines:
        if re.search(pattern, line, re.MULTILINE):
            in_function = True
            brace_count = line.count("{") - line.count("}")
            result.append(line)
            if brace_count == 0:
                break
            continue

        if in_function:
            result.append(line)
            brace_count += line.count("{") - line.count("}")

            if brace_count == 0:
                break

    return "\n".join(result) if result else None


def create_module(module_path, functions, app_js_content):
    """Create a new ES6 module with extracted functions"""
    full_path = FRONTEND / module_path
    full_path.parent.mkdir(parents=True, exist_ok=True)

    module_content = f"""/**
 * {module_path}
 * Extracted from app.js
 */

"""

    extracted = []
    for func_name in functions:
        func_code = extract_function(app_js_content, func_name)
        if func_code:
            # Convert to ES6 export
            func_code = re.sub(r"^function ", "export function ", func_code)
            module_content += func_code + "\n\n"
            extracted.append(func_name)

    if extracted:
        full_path.write_text(module_content)
        return extracted
    return []


def convert_to_es6_module(file_path):
    """Convert a JavaScript file to ES6 module with exports"""
    content = file_path.read_text()

    # Find all function declarations
    functions = re.findall(r"^function\s+(\w+)\s*\(", content, re.MULTILINE)

    if not functions:
        return False

    # Convert function declarations to exports
    for func in functions:
        content = re.sub(
            rf"^function {func}\b",
            f"export function {func}",
            content,
            flags=re.MULTILINE,
        )

    # Add module header
    header = f"""/**
 * {file_path.name}
 * ES6 Module
 */

"""

    content = header + content
    file_path.write_text(content)
    return True


def create_index_exports():
    """Create index.js files for barrel exports"""
    print("📝 Creating index.js barrel exports...")

    # Core index
    core_index = FRONTEND / "core/index.js"
    core_index.write_text("""/**
 * Core module exports
 */

export { initializeApp, setupEventListeners } from './app.js';
export * from './events.js';
export * from './main.js';
""")

    # UI index
    ui_index = FRONTEND / "ui/index.js"
    ui_index.write_text("""/**
 * UI module exports
 */

export * from './welcome.js';
export * from './sidebar.js';
export * from './modals.js';
export * from './chat/chat.js';
export * from './multi-agent/multi_agent_ui.js';
export * from './osint/osint_ui.js';
""")

    # API index
    api_index = FRONTEND / "api/index.js"
    api_index.write_text("""/**
 * API module exports
 */

export * from './client.js';
export * from './capacitor/capacitor-backend.js';
""")

    # Features index
    features_index = FRONTEND / "features/index.js"
    features_index.write_text("""/**
 * Features module exports
 */

export * from './files/files.js';
export * from './images/images.js';
export * from './models/models.js';
export * from './settings/settings.js';
export * from './projects/projects.js';
export * from './autocomplete/autocomplete.js';
""")

    # Utils index
    utils_index = FRONTEND / "utils/index.js"
    utils_index.write_text("""/**
 * Utility module exports
 */

export * from './toast.js';
export * from './storage/storage.js';
export * from './helpers/utils.js';
export * from './theme/theme-utils.js';
""")

    print("✅ Created 5 index.js files\n")


def main():
    print("🚀 Modularizing PKN Frontend\n")

    # Step 1: Move existing modular files
    moved = move_existing_files()

    # Step 2: Read app.js
    if not APP_JS.exists():
        print(f"❌ {APP_JS} not found")
        return

    app_js_content = APP_JS.read_text()
    print(f"📖 Read app.js ({len(app_js_content)} characters)\n")

    # Step 3: Extract functions from app.js
    print("✂️  Extracting functions from app.js...")
    total_extracted = 0

    for module_path, functions in EXTRACTIONS.items():
        extracted = create_module(module_path, functions, app_js_content)
        if extracted:
            print(f"  ✓ {module_path}: {', '.join(extracted)}")
            total_extracted += len(extracted)

    print(f"✅ Extracted {total_extracted} functions from app.js\n")

    # Step 4: Convert moved files to ES6 modules
    print("🔄 Converting files to ES6 modules...")
    converted = 0

    for js_file in FRONTEND.rglob("*.js"):
        if js_file.name == "index.js":
            continue
        if convert_to_es6_module(js_file):
            rel_path = js_file.relative_to(FRONTEND)
            print(f"  ✓ {rel_path}")
            converted += 1

    print(f"✅ Converted {converted} files to ES6\n")

    # Step 5: Create barrel exports
    create_index_exports()

    # Summary
    print("=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"  Existing files moved:     {moved}")
    print(f"  Functions extracted:      {total_extracted}")
    print(f"  Files converted to ES6:   {converted}")
    print(f"  Index files created:      5")
    print("\n✅ Frontend modularization complete!")
    print("\n⚠️  NEXT STEPS:")
    print("  1. Update pkn.html to use ES6 module imports")
    print("  2. Remove old script tags")
    print("  3. Test in browser")


if __name__ == "__main__":
    main()
