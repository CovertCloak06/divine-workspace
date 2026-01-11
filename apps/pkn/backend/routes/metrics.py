"""
Metrics Routes Blueprint
Extracted from divinenode_server.py
"""
from flask import Blueprint, request, jsonify
import json
# TODO: Update import after agent_manager is split
# from ..agents.manager import AgentManager


# Create blueprint
metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/api/metrics/agent/<agent_type>', methods=['GET'])
def api_get_agent_metrics(agent_type):
    """
    Get performance metrics for a specific agent.

    Query params:
    - days: Number of days to look back (default: 30)

    Returns:
    {
        "success": true,
        "total_executions": 100,
        "success_rate": 95.5,
        "avg_duration_ms": 5000,
        "status": "success"
    }
    """
    try:
        days = request.args.get('days', 30, type=int)

        try:
            from ..agents import manager as agent_manager

            result = agent_manager.get_agent_metrics(agent_type, days)

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Metrics system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500


@metrics_bp.route('/api/metrics/report', methods=['GET'])
def api_get_metrics_report():
    """
    Get comprehensive performance report for all agents.

    Query params:
    - days: Number of days to look back (default: 7)

    Returns:
    {
        "report": "markdown formatted report",
        "status": "success"
    }
    """
    try:
        days = request.args.get('days', 7, type=int)

        try:
            from ..agents import manager as agent_manager

            report = agent_manager.get_performance_report(days)

            return jsonify({
                'report': report,
                'status': 'success'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Metrics system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

