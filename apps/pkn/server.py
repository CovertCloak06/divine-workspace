#!/usr/bin/env python3
"""
PKN Server Launcher
Launches the modular backend server
"""

import sys
from pathlib import Path

# Add the app root to Python path so backend.* imports work
app_root = Path(__file__).parent
sys.path.insert(0, str(app_root))

# Import and run the backend server
from backend.server import app

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8010, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    print(f"🚀 Starting PKN server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
