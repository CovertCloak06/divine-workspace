"""
Code Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify, current_app
import json


# Create blueprint
code_bp = Blueprint("code", __name__)


@code_bp.route("/analyze", methods=["POST"])
def api_code_analyze():
    """
    Analyze a code file and return symbols, imports, structure.

    Request body:
    {
        "file_path": "/path/to/file.py"
    }

    Returns:
    {
        "symbols": [...],
        "imports": [...],
        "language": "python",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        file_path = data.get("file_path", "")

        if not file_path:
            return jsonify({"error": "No file_path provided", "status": "error"}), 400

        try:
            from ..memory import code_context

            # Analyze the file
            result = code_context.analyze_file(file_path)
            result["status"] = "success"

            return jsonify(result), 200

        except ImportError as e:
            current_app.logger.error(
                f"Failed to from ..memory import code_context: {e}"
            )
            return jsonify(
                {"error": "Code context system not available", "status": "error"}
            ), 503
        except Exception as e:
            current_app.logger.error(f"File analysis error: {e}")
            return jsonify({"error": str(e), "status": "error"}), 500

    except Exception as e:
        current_app.logger.error(f"Code analyze endpoint error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


@code_bp.route("/scan-project", methods=["POST"])
def api_code_scan_project():
    """
    Scan entire project and build symbol index.

    Request body:
    {
        "extensions": [".py", ".js", ".html", ".css"]  (optional)
    }

    Returns:
    {
        "stats": {"python": 29, "javascript": 16, ...},
        "project_stats": {...},
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        extensions = data.get("extensions", [".py", ".js", ".html", ".css"])

        try:
            from ..memory import code_context

            # Scan project
            stats = code_context.scan_project(extensions)
            project_stats = code_context.get_project_stats()

            return jsonify(
                {"stats": stats, "project_stats": project_stats, "status": "success"}
            ), 200

        except ImportError as e:
            current_app.logger.error(
                f"Failed to from ..memory import code_context: {e}"
            )
            return jsonify(
                {"error": "Code context system not available", "status": "error"}
            ), 503
        except Exception as e:
            current_app.logger.error(f"Project scan error: {e}")
            return jsonify({"error": str(e), "status": "error"}), 500

    except Exception as e:
        current_app.logger.error(f"Project scan endpoint error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500
