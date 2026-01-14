"""
Delegation Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import uuid
# TODO: Update import after agent_manager is split
# from ..agents.manager import AgentManager


# Create blueprint
delegation_bp = Blueprint("delegation", __name__)


@delegation_bp.route("/delegate", methods=["POST"])
def api_delegate_task():
    """
    Delegate a task from one agent to another.

    Request body:
    {
        "from_agent": "coder",
        "to_agent": "researcher",
        "task": "Find docs on asyncio",
        "context": {"optional": "context"},
        "parent_task_id": "optional-id"
    }

    Returns:
    {
        "success": true,
        "delegation_id": "uuid",
        "result": {...},
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        from_agent = data.get("from_agent", "")
        to_agent = data.get("to_agent", "")
        task = data.get("task", "")
        context = data.get("context")
        parent_task_id = data.get("parent_task_id")

        if not all([from_agent, to_agent, task]):
            return jsonify(
                {
                    "error": "from_agent, to_agent, and task are required",
                    "status": "error",
                }
            ), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(
                agent_manager.delegate_to_agent(
                    from_agent, to_agent, task, context, parent_task_id
                )
            )

            return jsonify(
                {**result, "status": "success" if result.get("success") else "error"}
            ), 200

        except ImportError as e:
            return jsonify(
                {"error": "Delegation system not available", "status": "error"}
            ), 503

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@delegation_bp.route("/collaborate", methods=["POST"])
def api_collaborate():
    """
    Have multiple agents collaborate on a task.

    Request body:
    {
        "agents": ["reasoner", "researcher", "coder"],
        "task": "Design and implement API",
        "session_id": "optional-session-id",
        "coordinator": "reasoner"
    }

    Returns:
    {
        "success": true,
        "final_result": "...",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        agents = data.get("agents", [])
        task = data.get("task", "")
        session_id = data.get("session_id", str(uuid.uuid4()))
        coordinator = data.get("coordinator", "reasoner")

        if not agents or not task:
            return jsonify(
                {"error": "agents and task are required", "status": "error"}
            ), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            result = asyncio.run(
                agent_manager.collaborate_agents(agents, task, session_id, coordinator)
            )

            return jsonify(
                {**result, "status": "success" if result.get("success") else "error"}
            ), 200

        except ImportError as e:
            return jsonify(
                {"error": "Collaboration system not available", "status": "error"}
            ), 503

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500
