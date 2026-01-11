"""
Editor Routes Blueprint
Extracted from divinenode_server.py
"""
from flask import Blueprint, request, jsonify
import json
from pathlib import Path


# Create blueprint
editor_bp = Blueprint('editor', __name__)

@editor_bp.route('/api/editor/files', methods=['GET'])
def list_editable_files():
    """
    List all editable files in the PKN directory
    Returns: JSON list of files with name and path
    """
    try:
        pkn_dir = Path(__file__).parent
        editable_extensions = {'.py', '.js', '.html', '.css', '.json', '.md', '.txt', '.sh', '.env'}

        files = []
        for file_path in pkn_dir.rglob('*'):
            # Skip hidden files, cache, venv, and large directories
            if any(part.startswith('.') for part in file_path.parts):
                continue
            if any(exclude in str(file_path) for exclude in ['__pycache__', 'node_modules', '.venv', '.git']):
                continue

            if file_path.is_file() and file_path.suffix in editable_extensions:
                rel_path = file_path.relative_to(pkn_dir)
                files.append({
                    'name': str(rel_path),
                    'path': str(file_path)
                })

        # Sort by name
        files.sort(key=lambda x: x['name'])

        return jsonify({'files': files}), 200
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return jsonify({'error': str(e)}), 500


@editor_bp.route('/api/editor/read', methods=['POST'])
def read_file_content():
    """
    Read content of a file
    Request: { "file_path": "/path/to/file" }
    Returns: { "content": "file contents..." }
    """
    try:
        data = request.json
        file_path = Path(data.get('file_path', ''))

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        # Security: Only allow reading files within PKN directory
        pkn_dir = Path(__file__).parent
        try:
            file_path.relative_to(pkn_dir)
        except ValueError:
            return jsonify({'error': 'Access denied - file outside PKN directory'}), 403

        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return jsonify({'content': content}), 200
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return jsonify({'error': str(e)}), 500


@editor_bp.route('/api/editor/write', methods=['POST'])
def write_file_content():
    """
    Write content to a file
    Request: { "file_path": "/path/to/file", "content": "new content..." }
    Returns: { "success": true }
    """
    try:
        data = request.json
        file_path = Path(data.get('file_path', ''))
        content = data.get('content', '')

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        # Security: Only allow writing files within PKN directory
        pkn_dir = Path(__file__).parent
        try:
            file_path.relative_to(pkn_dir)
        except ValueError:
            return jsonify({'error': 'Access denied - file outside PKN directory'}), 403

        # Create backup before writing
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

        # Write new content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✓ [Editor] Saved: {file_path.name} (backup: {backup_path.name})")
        return jsonify({'success': True, 'message': f'File saved: {file_path.name}'}), 200
    except Exception as e:
        print(f"Error writing file: {str(e)}")
        return jsonify({'error': str(e)}), 500

