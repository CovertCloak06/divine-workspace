"""
Planning Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import uuid
# Note: AgentManager imported lazily in functions to avoid circular imports


# Create blueprint
planning_bp = Blueprint("planning", __name__)


@planning_bp.route("/create", methods=["POST"])
def api_create_plan():
    """
    Create a structured execution plan for a complex task.

    Request body:
    {
        "task": "Complex task description",
        "context": {"optional": "context"}
    }

    Returns:
    {
        "success": true,
        "plan_id": "uuid",
        "goal": "...",
        "steps": [...],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        task = data.get("task", "")
        context = data.get("context")

        if not task:
            return jsonify({"error": "No task provided", "status": "error"}), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(agent_manager.create_task_plan(task, context))

            return jsonify(
                {**result, "status": "success" if result.get("success") else "error"}
            ), 200

        except ImportError as e:
            return jsonify(
                {"error": "Planning system not available", "status": "error"}
            ), 503

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@planning_bp.route("/execute/<plan_id>", methods=["POST"])
def api_execute_plan(plan_id):
    """
    Execute a created plan step by step.

    Request body:
    {
        "session_id": "optional-session-id"
    }

    Returns:
    {
        "success": true,
        "steps_completed": 5,
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        session_id = data.get("session_id", str(uuid.uuid4()))

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(agent_manager.execute_plan(plan_id, session_id))

            return jsonify(
                {**result, "status": "success" if result.get("success") else "error"}
            ), 200

        except ImportError as e:
            return jsonify(
                {"error": "Planning system not available", "status": "error"}
            ), 503

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500
