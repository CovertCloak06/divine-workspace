#!/usr/bin/env python3
"""
Auto-fix broken JavaScript imports and generate global exports.
Fixes the exact issues we keep running into with ES6 modules.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set

class ImportFixer:
    def __init__(self, app_path: str):
        self.app_path = Path(app_path)
        self.fixes_applied = []
        self.errors = []

    def fix_plugin_imports(self) -> None:
        """Fix all plugin imports from ../../js/plugin-base.js to ../../features/plugin-base.js"""
        plugin_dir = self.app_path / "frontend/js/plugins"
        if not plugin_dir.exists():
            plugin_dir = self.app_path / "js/plugins"

        if not plugin_dir.exists():
            return

        for plugin_file in plugin_dir.rglob("*.js"):
            with open(plugin_file, 'r') as f:
                content = f.read()

            old_import = "from '../../js/plugin-base.js'"
            new_import = "from '../../features/plugin-base.js'"

            if old_import in content:
                content = content.replace(old_import, new_import)
                with open(plugin_file, 'w') as f:
                    f.write(content)
                self.fixes_applied.append(f"Fixed plugin import in {plugin_file.name}")

    def fix_relative_imports(self, js_file: Path) -> None:
        """Fix relative imports to use correct paths"""
        with open(js_file, 'r') as f:
            content = f.read()

        original_content = content

        # Common wrong patterns → correct patterns
        fixes = [
            (r"from '\./utils\.js'", "from '../utils/utils.js'"),
            (r"from '\./storage\.js'", "from '../utils/storage.js'"),
            (r"from '\./event-bus\.js'", "from '../core/event-bus.js'"),
            (r"from '\./plugin-manager\.js'", "from '../features/plugin-manager.js'"),
        ]

        for pattern, replacement in fixes:
            content = re.sub(pattern, replacement, content)

        if content != original_content:
            with open(js_file, 'w') as f:
                f.write(content)
            self.fixes_applied.append(f"Fixed relative imports in {js_file.relative_to(self.app_path)}")

    def generate_global_exports(self, app_name: str) -> str:
        """Generate code to expose module exports globally"""
        js_dir = self.app_path / "frontend/js"
        if not js_dir.exists():
            js_dir = self.app_path / "js"

        exports = []

        # Find all exported functions in modules
        for js_file in js_dir.rglob("*.js"):
            if 'node_modules' in str(js_file):
                continue

            with open(js_file, 'r') as f:
                content = f.read()

            # Find export function declarations
            export_pattern = r'export\s+(?:function|const|let|var)\s+(\w+)'
            matches = re.findall(export_pattern, content)

            for func_name in matches:
                module_path = f"./{js_file.relative_to(self.app_path / 'frontend')}"
                exports.append(f"  import {{ {func_name} }} from '{module_path}';")
                exports.append(f"  window.{func_name} = {func_name};")

        if not exports:
            return ""

        return f"""<!-- Auto-generated global exports for {app_name} -->
<script type="module">
{chr(10).join(exports)}

  console.log('✅ Global exports loaded for HTML onclick handlers');
</script>
"""

    def fix_app(self) -> Dict:
        """Run all fixes on the app"""
        print(f"\n🔧 Fixing {self.app_path.name}...")

        # Fix plugin imports
        self.fix_plugin_imports()

        # Fix relative imports in all JS files
        js_files = list(self.app_path.rglob("*.js"))
        for js_file in js_files:
            if 'node_modules' in str(js_file) or '.venv' in str(js_file):
                continue

            # Only fix files in features/ and ui/ directories
            if '/features/' in str(js_file) or '/ui/' in str(js_file):
                self.fix_relative_imports(js_file)

        return {
            "fixes": self.fixes_applied,
            "errors": self.errors
        }

def main():
    workspace = Path("/home/gh0st/dvn/divine-workspace/apps")

    total_fixes = 0

    for app_dir in workspace.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith('.'):
            continue

        # Only fix apps with frontend code
        if not (app_dir / "frontend").exists() and not (app_dir / "js").exists():
            continue

        fixer = ImportFixer(app_dir)
        results = fixer.fix_app()

        total_fixes += len(results["fixes"])

        if results["fixes"]:
            print(f"\n✅ Applied {len(results['fixes'])} fixes in {app_dir.name}:")
            for fix in results["fixes"]:
                print(f"  • {fix}")

        if results["errors"]:
            print(f"\n❌ ERRORS in {app_dir.name}:")
            for error in results["errors"]:
                print(f"  • {error}")

    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SUMMARY")
    print(f"{'='*60}")
    print(f"Total fixes applied: {total_fixes}")

    if total_fixes > 0:
        print(f"\n✅ Fixed {total_fixes} import issues")
        print(f"\n💡 TIP: Run 'python3 scripts/check-imports.py' to verify fixes")
        return 0
    else:
        print(f"\n✅ No fixes needed")
        return 0

if __name__ == "__main__":
    exit(main())
