#!/usr/bin/env python3
"""
Quick Server - Instant HTTP server with extras
Usage: qserver [port] [--upload] [--cors] [--dir PATH]
"""

import http.server
import socketserver
import argparse
import os
import json
import cgi
from urllib.parse import parse_qs, urlparse
from pathlib import Path

class EnhancedHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with upload support and CORS"""

    def __init__(self, *args, upload=False, cors=False, **kwargs):
        self.upload_enabled = upload
        self.cors_enabled = cors
        super().__init__(*args, **kwargs)

    def end_headers(self):
        if self.cors_enabled:
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        if not self.upload_enabled:
            self.send_error(403, "Upload disabled")
            return

        content_type = self.headers.get('Content-Type', '')

        if 'multipart/form-data' in content_type:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )

            if 'file' in form:
                file_item = form['file']
                filename = Path(file_item.filename).name
                filepath = Path(self.directory) / filename

                with open(filepath, 'wb') as f:
                    f.write(file_item.file.read())

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "ok",
                    "filename": filename,
                    "size": filepath.stat().st_size
                }).encode())
                return

        self.send_error(400, "Bad request")

    def list_directory(self, path):
        """Enhanced directory listing with upload form"""
        response = super().list_directory(path)
        if self.upload_enabled and response:
            # Inject upload form
            content = response.read().decode()
            upload_form = '''
            <div style="padding:10px;background:#1a1a2e;border:1px solid #00ffff;margin:10px 0;border-radius:8px;">
                <form method="POST" enctype="multipart/form-data" style="display:flex;gap:10px;align-items:center;">
                    <input type="file" name="file" style="color:#00ffff;">
                    <button type="submit" style="background:#00ffff;color:#000;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;">Upload</button>
                </form>
            </div>
            '''
            content = content.replace('<hr>', upload_form + '<hr>', 1)

            from io import BytesIO
            encoded = content.encode()
            response = BytesIO(encoded)
            response.seek(0)
        return response


def main():
    parser = argparse.ArgumentParser(description='Quick HTTP Server with extras')
    parser.add_argument('port', nargs='?', type=int, default=8000)
    parser.add_argument('--upload', '-u', action='store_true', help='Enable file uploads')
    parser.add_argument('--cors', '-c', action='store_true', help='Enable CORS headers')
    parser.add_argument('--dir', '-d', default='.', help='Directory to serve')
    args = parser.parse_args()

    os.chdir(args.dir)

    handler = lambda *a, **kw: EnhancedHandler(*a, upload=args.upload, cors=args.cors, **kw)

    with socketserver.TCPServer(("", args.port), handler) as httpd:
        print(f"🚀 Serving at http://0.0.0.0:{args.port}")
        print(f"   Directory: {os.getcwd()}")
        print(f"   Upload: {'✓' if args.upload else '✗'}")
        print(f"   CORS: {'✓' if args.cors else '✗'}")
        print("   Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Server stopped")


if __name__ == '__main__':
    main()
