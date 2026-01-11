"""
Session Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json


# Create blueprint
session_bp = Blueprint("session", __name__)


@session_bp.route("/api/session/<session_id>", methods=["GET"])
def api_get_session(session_id):
    """Get session information"""
    try:
        from ..memory import conversation_memory

        summary = conversation_memory.get_session_summary(session_id)
        if not summary:
            return jsonify({"error": "Session not found", "status": "error"}), 404

        return jsonify({"summary": summary, "status": "success"}), 200

    except ImportError as e:
        return jsonify(
            {"error": "Conversation memory not available", "status": "error"}
        ), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@session_bp.route("/api/session/<session_id>/history", methods=["GET"])
def api_get_session_history(session_id):
    """Get conversation history for a session"""
    try:
        from ..memory import conversation_memory

        limit = request.args.get("limit", type=int)
        history = conversation_memory.get_conversation_history(session_id, limit=limit)

        if history is None:
            return jsonify({"error": "Session not found", "status": "error"}), 404

        return jsonify(
            {"history": history, "count": len(history), "status": "success"}
        ), 200

    except ImportError as e:
        return jsonify(
            {"error": "Conversation memory not available", "status": "error"}
        ), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500
