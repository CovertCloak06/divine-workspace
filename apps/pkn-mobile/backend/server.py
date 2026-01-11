#!/usr/bin/env python3
"""
PKN Mobile Server
Simplified Flask server for mobile deployment (Termux)
Uses OpenAI API instead of local LLM
"""

import sys
from pathlib import Path
from flask import Flask, send_from_directory
from flask_cors import CORS

# Add backend to path for imports
app_root = Path(__file__).parent.parent
sys.path.insert(0, str(app_root))

from backend.routes import register_routes

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Register API routes
register_routes(app)

# Static file serving from frontend/
ROOT = Path(__file__).parent.parent / 'frontend'


@app.route('/')
@app.route('/pkn.html')
def index():
    """Serve main HTML file."""
    return send_from_directory(ROOT, 'pkn.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files (CSS, JS, images)."""
    return send_from_directory(ROOT, filename)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='PKN Mobile Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8010, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    print(f"🚀 Starting PKN Mobile Server on {args.host}:{args.port}")
    print(f"📱 Optimized for mobile deployment (Termux)")
    print(f"☁️  Using OpenAI API (no local LLM required)")

    app.run(host=args.host, port=args.port, debug=args.debug)
