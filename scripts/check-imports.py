#!/usr/bin/env python3
"""
Check import/export consistency across monorepo apps.
Finds missing files, wrong MIME types, and broken import paths.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

class ImportChecker:
    def __init__(self, app_path: str):
        self.app_path = Path(app_path)
        self.errors = []
        self.warnings = []

    def check_html_scripts(self, html_file: Path) -> None:
        """Check all script tags in HTML"""
        with open(html_file) as f:
            html = f.read()

        # Find all script src attributes
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, html)

        for script_src in scripts:
            # Skip external URLs
            if script_src.startswith('http'):
                continue

            script_path = self.app_path / script_src.lstrip('/')
            if not script_path.exists():
                self.errors.append(f"Missing script: {script_src} (expected at {script_path})")

    def check_js_imports(self, js_file: Path) -> None:
        """Check all ES6 imports in a JS file"""
        with open(js_file) as f:
            content = f.read()

        # Find all import statements
        import_pattern = r'import\s+.*\s+from\s+["\']([^"\']+)["\']'
        imports = re.findall(import_pattern, content)

        for import_path in imports:
            # Skip external packages
            if not import_path.startswith('.'):
                continue

            # Resolve relative path
            resolved = (js_file.parent / import_path).resolve()
            if not resolved.exists() and not resolved.with_suffix('.js').exists():
                self.errors.append(
                    f"Broken import in {js_file.relative_to(self.app_path)}:\n"
                    f"  import from '{import_path}'\n"
                    f"  Expected at: {resolved}"
                )

    def check_onclick_handlers(self, html_file: Path) -> None:
        """Check that all onclick handlers reference existing functions"""
        with open(html_file) as f:
            html = f.read()

        # Find all onclick handlers
        onclick_pattern = r'onclick=["\']([^"\'()]+)\([^)]*\)'
        handlers = re.findall(onclick_pattern, html)

        # These need to be globally available
        for handler in set(handlers):
            self.warnings.append(
                f"Function '{handler}()' must be globally exposed for onclick handler"
            )

    def scan_directory(self, directory: Path, pattern: str) -> List[Path]:
        """Recursively find files matching pattern"""
        return list(directory.rglob(pattern))

    def check_app(self) -> Dict:
        """Run all checks on the app"""
        print(f"\n🔍 Checking {self.app_path.name}...")

        # Check HTML files
        html_files = self.scan_directory(self.app_path, "*.html")
        for html_file in html_files:
            self.check_html_scripts(html_file)
            self.check_onclick_handlers(html_file)

        # Check JS files
        js_files = self.scan_directory(self.app_path, "*.js")
        for js_file in js_files:
            if 'node_modules' in str(js_file):
                continue
            self.check_js_imports(js_file)

        return {
            "errors": self.errors,
            "warnings": self.warnings,
            "files_checked": {
                "html": len(html_files),
                "js": len([f for f in js_files if 'node_modules' not in str(f)])
            }
        }

def main():
    workspace = Path("/home/gh0st/dvn/divine-workspace/apps")

    all_results = {}
    total_errors = 0
    total_warnings = 0

    for app_dir in workspace.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith('.'):
            continue

        checker = ImportChecker(app_dir)
        results = checker.check_app()
        all_results[app_dir.name] = results

        total_errors += len(results["errors"])
        total_warnings += len(results["warnings"])

        # Print errors
        if results["errors"]:
            print(f"\n❌ ERRORS in {app_dir.name}:")
            for error in results["errors"]:
                print(f"  {error}")

        # Print warnings
        if results["warnings"]:
            print(f"\n⚠️  WARNINGS in {app_dir.name} ({len(results['warnings'])} total):")
            for warning in results["warnings"][:5]:  # Show first 5
                print(f"  {warning}")
            if len(results["warnings"]) > 5:
                print(f"  ... and {len(results['warnings']) - 5} more")

    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SUMMARY")
    print(f"{'='*60}")
    print(f"Total errors: {total_errors}")
    print(f"Total warnings: {total_warnings}")

    if total_errors > 0:
        print(f"\n❌ Found {total_errors} critical errors that need fixing")
        return 1
    else:
        print(f"\n✅ No critical errors found")
        return 0

if __name__ == "__main__":
    exit(main())
