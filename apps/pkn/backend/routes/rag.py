"""
Rag Routes Blueprint
Extracted from divinenode_server.py
"""
from flask import Blueprint, request, jsonify
import json
# TODO: Update import after agent_manager is split
# from ..agents.manager import AgentManager


# Create blueprint
rag_bp = Blueprint('rag', __name__)

@rag_bp.route('/api/rag/search', methods=['POST'])
def api_rag_search():
    """
    Search codebase using RAG semantic search.

    Request body:
    {
        "query": "search query",
        "n_results": 5
    }

    Returns:
    {
        "success": true,
        "results": [...],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        query = data.get('query', '')
        n_results = data.get('n_results', 5)

        if not query:
            return jsonify({'error': 'No query provided', 'status': 'error'}), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(agent_manager.search_codebase_with_rag(query, n_results))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'RAG system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

