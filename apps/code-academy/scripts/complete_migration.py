#!/usr/bin/env python3
"""
Complete Code Academy Migration to src/
Moves remaining js/ files to src/ with proper organization
"""

import shutil
from pathlib import Path

ROOT = Path('/home/gh0st/dvn/divine-workspace/apps/code-academy')
JS_DIR = ROOT / 'js'
SRC_DIR = ROOT / 'src'

# Migration mapping
MIGRATIONS = {
    # Managers
    'theme-manager.js': 'managers/ThemeManager.js',
    'progress-tracker.js': 'managers/ProgressTracker.js',

    # Components
    'code-playground.js': 'components/CodePlayground.js',
    'challenge-editor.js': 'components/ChallengeEditor.js',
    'guided-editor.js': 'components/GuidedEditor.js',
    'terminal-widget.js': 'components/TerminalWidget.js',
    'visual-adjuster.js': 'components/VisualAdjuster.js',
    'error-boundary.js': 'components/ErrorBoundary.js',

    # Core
    'academy.js': 'core/Academy.js',

    # Utils (if not already in src/utils)
    'web-vitals-tracker.js': 'utils/web-vitals-tracker.js',
}

def convert_to_es6_module(content, filename):
    """Add ES6 module header and convert class exports"""
    # Add header
    header = f'''/**
 * {filename}
 * Code Academy Module
 */

'''

    # If file has a class, export it
    if 'class ' in content:
        # Find main class name
        import re
        match = re.search(r'class\s+(\w+)', content)
        if match:
            class_name = match.group(1)
            # Add export default at the end if not already there
            if 'export default' not in content and 'export {' not in content:
                content = content.rstrip() + f'\n\nexport default {class_name};\n'

    return header + content


def migrate_file(src_file, dest_path):
    """Migrate a single file to src/ structure"""
    dest_file = SRC_DIR / dest_path
    dest_file.parent.mkdir(parents=True, exist_ok=True)

    # Read content
    content = src_file.read_text()

    # Convert to ES6 module
    content = convert_to_es6_module(content, src_file.name)

    # Write to destination
    dest_file.write_text(content)

    return dest_file


def main():
    print("🚀 Completing Code Academy migration to src/\n")

    migrated = 0
    skipped = 0

    for js_file, dest_path in MIGRATIONS.items():
        src_file = JS_DIR / js_file

        if not src_file.exists():
            print(f"  ⚠️  {js_file} not found, skipping")
            skipped += 1
            continue

        # Check if already migrated
        dest_file = SRC_DIR / dest_path
        if dest_file.exists():
            print(f"  ✓ {dest_path} (already exists)")
            skipped += 1
            continue

        # Migrate
        result = migrate_file(src_file, dest_path)
        print(f"  ✓ {js_file} → {dest_path}")
        migrated += 1

    print(f"\n✅ Migration complete!")
    print(f"  Migrated: {migrated} files")
    print(f"  Skipped:  {skipped} files (already existed)")

    # Create main entry point
    print("\n📝 Creating main entry point...")

    main_js = SRC_DIR / 'main.js'
    main_js.write_text('''/**
 * Code Academy - Main Entry Point
 * Loads all modules and initializes the application
 */

// Core
import Academy from './core/Academy.js';
import TutorialEngine from './core/TutorialEngine.js';

// Services
import LessonLoader from './services/LessonLoader.js';

// Components
import TaskRenderer from './components/TaskRenderer.js';
import CodeEditor from './components/CodeEditor.js';
import QuizComponent from './components/QuizComponent.js';
import CodePlayground from './components/CodePlayground.js';
import ChallengeEditor from './components/ChallengeEditor.js';
import GuidedEditor from './components/GuidedEditor.js';
import TerminalWidget from './components/TerminalWidget.js';
import VisualAdjuster from './components/VisualAdjuster.js';
import ErrorBoundary from './components/ErrorBoundary.js';

// Managers
import ThemeManager from './managers/ThemeManager.js';
import ProgressTracker from './managers/ProgressTracker.js';

// Utils
import { formatContent } from './utils/formatters.js';
import * as validators from './utils/validators.js';

// Initialize the application
console.log('✅ Code Academy modules loaded');

// Make Academy available globally for backward compatibility
window.Academy = Academy;
window.TutorialEngine = TutorialEngine;

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('🚀 Code Academy initialized');
    });
} else {
    console.log('🚀 Code Academy initialized');
}

export {
    Academy,
    TutorialEngine,
    LessonLoader,
    TaskRenderer,
    CodeEditor,
    QuizComponent,
    ThemeManager,
    ProgressTracker,
    formatContent,
    validators
};
''')

    print(f"✅ Created src/main.js entry point\n")

    print("=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"  Files in src/components/: {len(list((SRC_DIR / 'components').glob('*.js')))}")
    print(f"  Files in src/managers/:   {len(list((SRC_DIR / 'managers').glob('*.js')))}")
    print(f"  Files in src/core/:       {len(list((SRC_DIR / 'core').glob('*.js')))}")
    print(f"  Files in src/services/:   {len(list((SRC_DIR / 'services').glob('*.js')))}")
    print(f"  Files in src/utils/:      {len(list((SRC_DIR / 'utils').glob('*.js')))}")
    print("\n✅ Code Academy migration complete!")
    print("\n⚠️  NEXT STEPS:")
    print("  1. Update index.html:")
    print('     <script type="module" src="src/main.js"></script>')
    print("  2. Remove old <script> tags for js/*.js files")
    print("  3. Test in browser")


if __name__ == '__main__':
    main()
