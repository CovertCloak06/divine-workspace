"""
PKN Mobile Routes
Simplified routes for mobile deployment
"""

from flask import Blueprint

# Import route blueprints
from .chat import chat_bp
from .health import health_bp


def register_routes(app):
    """Register all route blueprints with the Flask app."""
    app.register_blueprint(health_bp)
    app.register_blueprint(chat_bp, url_prefix="/api")

    print("✅ Registered 2 mobile route blueprints")
