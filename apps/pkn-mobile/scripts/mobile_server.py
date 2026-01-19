#!/usr/bin/env python3
"""
PKN Mobile Server Launcher
Handles path setup for Termux environment where files are in ~/pkn/ directly
"""

import sys
import os

# Add pkn directory to path for absolute imports
PKN_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PKN_HOME not in sys.path:
    sys.path.insert(0, PKN_HOME)

# Now we can use absolute imports
from flask import Flask, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
env_path = Path(PKN_HOME) / ".env"
load_dotenv(env_path, override=True)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Root directory for static files
ROOT = Path(PKN_HOME)


@app.route("/")
@app.route("/pkn.html")
def index():
    """Serve main HTML file"""
    response = send_from_directory(ROOT, "pkn.html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/<path:filename>")
def static_files(filename):
    """Serve static files (css, js, img, etc.)"""
    path = ROOT / filename
    if path.exists() and path.is_file():
        response = send_from_directory(ROOT, filename)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        if filename.endswith('.js'):
            response.headers["Content-Type"] = "text/javascript; charset=utf-8"
        elif filename.endswith('.mjs'):
            response.headers["Content-Type"] = "text/javascript; charset=utf-8"
        elif filename.endswith('.css'):
            response.headers["Content-Type"] = "text/css; charset=utf-8"
        elif filename.endswith('.json'):
            response.headers["Content-Type"] = "application/json; charset=utf-8"

        return response
    return {"error": "Not found"}, 404


def register_routes():
    """Register all route blueprints - using absolute imports"""
    from routes.health import health_bp
    from routes.phonescan import phonescan_bp
    from routes.network import network_bp
    from routes.osint import osint_bp
    from routes.files import files_bp
    from routes.editor import editor_bp
    from routes.images import images_bp
    from routes.models import models_bp
    from routes.chat import chat_bp
    from routes.code import code_bp
    from routes.multi_agent import multi_agent_bp
    from routes.rag import rag_bp
    from routes.planning import planning_bp
    from routes.delegation import delegation_bp
    from routes.sandbox import sandbox_bp
    from routes.metrics import metrics_bp
    from routes.session import session_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(phonescan_bp, url_prefix="/api")
    app.register_blueprint(network_bp, url_prefix="/api/network")
    app.register_blueprint(osint_bp, url_prefix="/api/osint")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(editor_bp, url_prefix="/api/editor")
    app.register_blueprint(images_bp, url_prefix="/api")
    app.register_blueprint(models_bp, url_prefix="/api/models")
    app.register_blueprint(chat_bp, url_prefix="/api")
    app.register_blueprint(code_bp, url_prefix="/api/code")
    app.register_blueprint(multi_agent_bp, url_prefix="/api/multi-agent")
    app.register_blueprint(rag_bp, url_prefix="/api/rag")
    app.register_blueprint(planning_bp, url_prefix="/api/planning")
    app.register_blueprint(delegation_bp, url_prefix="/api/delegation")
    app.register_blueprint(sandbox_bp, url_prefix="/api/sandbox")
    app.register_blueprint(metrics_bp, url_prefix="/api/metrics")
    app.register_blueprint(session_bp, url_prefix="/api/session")

    print(f"✅ Registered 17 route blueprints")


# Register routes
register_routes()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8010, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    print(f"🚀 Starting PKN Mobile on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
