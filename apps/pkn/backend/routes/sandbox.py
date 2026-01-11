"""
Sandbox Routes Blueprint
Extracted from divinenode_server.py
"""
from flask import Blueprint, request, jsonify
import json
import time
# TODO: Update import after agent_manager is split
# from ..agents.manager import AgentManager


# Create blueprint
sandbox_bp = Blueprint('sandbox', __name__)

@sandbox_bp.route('/api/sandbox/execute', methods=['POST'])
def api_sandbox_execute():
    """
    Execute code in a safe sandbox environment.

    Request body:
    {
        "code": "print('hello')",
        "language": "python|javascript|shell",
        "timeout": 30
    }

    Returns:
    {
        "success": true,
        "output": "hello",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        code = data.get('code', '')
        language = data.get('language', 'python')
        timeout = data.get('timeout', 30)

        if not code:
            return jsonify({'error': 'No code provided', 'status': 'error'}), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(agent_manager.execute_code_safely(
                code, language, timeout
            ))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Sandbox system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

