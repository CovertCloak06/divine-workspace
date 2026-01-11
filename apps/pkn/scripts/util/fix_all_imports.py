#!/usr/bin/env python3
"""
Fix all imports after backend modularization
Updates import paths to use proper backend.* structure
"""

import re
from pathlib import Path

def fix_file_imports(file_path):
    """Fix imports in a single file"""
    content = file_path.read_text()
    original = content

    # Determine file location for relative imports
    backend_dir = Path('/home/gh0st/dvn/divine-workspace/apps/pkn/backend')
    rel_path = file_path.relative_to(backend_dir)
    depth = len(rel_path.parts) - 1

    # Routes are 1 level deep (backend/routes/*.py)
    # Tools are 1 level deep (backend/tools/*.py)
    # Memory, agents, config are 1 level deep

    # ========================================
    # Fix old imports to new structure
    # ========================================

    # agent_manager → ..agents.manager
    content = re.sub(
        r'from agent_manager import',
        'from ..agents.manager import',
        content
    )
    content = re.sub(
        r'import agent_manager',
        'from ..agents import manager as agent_manager',
        content
    )

    # conversation_memory → ..memory.conversation_memory
    content = re.sub(
        r'from conversation_memory import',
        'from ..memory.conversation_memory import',
        content
    )
    content = re.sub(
        r'import conversation_memory',
        'from ..memory import conversation_memory',
        content
    )

    # code_context → ..memory.code_context
    content = re.sub(
        r'from code_context import',
        'from ..memory.code_context import',
        content
    )
    content = re.sub(
        r'import code_context',
        'from ..memory import code_context',
        content
    )

    # local_image_gen → ..image_gen.local_image_gen
    content = re.sub(
        r'from local_image_gen import',
        'from ..image_gen.local_image_gen import',
        content
    )
    content = re.sub(
        r'import local_image_gen',
        'from ..image_gen import local_image_gen',
        content
    )

    # tools.* → ..tools.* (for routes and agents)
    content = re.sub(
        r'from tools\.(\w+) import',
        r'from ..tools.\1 import',
        content
    )
    content = re.sub(
        r'from tools import',
        'from ..tools import',
        content
    )

    # Utils imports
    content = re.sub(
        r'from utils\.(\w+) import',
        r'from ..utils.\1 import',
        content
    )

    # Config imports
    content = re.sub(
        r'from config\.settings import',
        'from ..config.settings import',
        content
    )

    # ========================================
    # Special fixes for specific file types
    # ========================================

    # In agents/manager.py: tools → ..tools
    if 'agents/manager.py' in str(file_path):
        content = re.sub(
            r'^from tools import',
            'from ..tools import',
            content,
            flags=re.MULTILINE
        )

    # In routes/__init__.py: blueprint imports need relative
    if 'routes/__init__.py' in str(file_path):
        # Already correct from generation script
        pass

    # In server.py: routes → .routes
    if file_path.name == 'server.py':
        content = re.sub(
            r'from routes import',
            'from .routes import',
            content
        )
        content = re.sub(
            r'from config import',
            'from .config import',
            content
        )

    # ========================================
    # Flask app reference fixes
    # ========================================

    # Routes that use app.logger need to import app
    if 'routes/' in str(file_path):
        # Check if file uses app.logger
        if 'app.logger' in content and 'from flask import' in content:
            # Add current_app import if not present
            if 'current_app' not in content:
                content = re.sub(
                    r'(from flask import.*?)\n',
                    r'\1, current_app\n',
                    content,
                    count=1
                )
            # Replace app.logger with current_app.logger
            content = re.sub(
                r'\bapp\.logger\b',
                'current_app.logger',
                content
            )

        # Remove standalone 'app' references if current_app is used
        if 'current_app' in content:
            content = re.sub(
                r'\bapp\.response_class\b',
                'current_app.response_class',
                content
            )

    # ========================================
    # Write if changed
    # ========================================

    if content != original:
        file_path.write_text(content)
        return True
    return False


def main():
    backend_dir = Path('/home/gh0st/dvn/divine-workspace/apps/pkn/backend')

    print("🔧 Fixing imports in backend/...")

    # Find all Python files
    py_files = list(backend_dir.rglob('*.py'))
    py_files = [f for f in py_files if '__pycache__' not in str(f)]

    fixed_count = 0

    for file in sorted(py_files):
        rel_path = file.relative_to(backend_dir)

        if fix_file_imports(file):
            print(f"  ✓ {rel_path}")
            fixed_count += 1
        else:
            print(f"  - {rel_path}")

    print(f"\n✅ Fixed imports in {fixed_count}/{len(py_files)} files")


if __name__ == '__main__':
    main()
