#!/usr/bin/env python3
"""
PKN Flask Server - Main Entry Point
Modularized backend with route blueprints
"""
from flask import Flask, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from pathlib import Path

from .routes import register_all_routes

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for local development

# Static file serving (serves pkn.html, css, js, img)
ROOT = Path(__file__).parent.parent  # Points to apps/pkn/

@app.route('/')
@app.route('/pkn.html')
def index():
    """Serve main HTML file"""
    response = send_from_directory(ROOT, 'pkn.html')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/<path:filename>')
def static_files(filename):
    """Serve static files (css, js, img, etc.)"""
    path = ROOT / filename
    if path.exists() and path.is_file():
        response = send_from_directory(ROOT, filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return {'error': 'Not found'}, 404

# Register all API routes
register_all_routes(app)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8010, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    print(f"🚀 Starting PKN server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
