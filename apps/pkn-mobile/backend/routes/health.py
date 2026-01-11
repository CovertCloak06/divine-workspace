"""
Health Check Route
Simple health endpoint for mobile PKN
"""

from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
def health_check():
    """Check if server is running."""
    return jsonify(
        {"status": "healthy", "version": "mobile-1.0.0", "llm_backend": "openai-api"}
    )
