#!/usr/bin/env python3
"""
HTTP Server - Quick file server for sharing files
Usage: http_server.py [port] [--directory path]
"""

import http.server
import socketserver
import argparse
import os
import socket
import threading
import urllib.parse
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'


def format_size(size):
    """Format file size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class ColorHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with colored logging"""

    def __init__(self, *args, directory=None, **kwargs):
        self.base_directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        method = args[0].split()[0] if args else ''
        path = args[0].split()[1] if args and len(args[0].split()) > 1 else ''
        status = args[1] if len(args) > 1 else ''

        # Color based on status
        if status.startswith('2'):
            color = GREEN
        elif status.startswith('3'):
            color = YELLOW
        elif status.startswith('4') or status.startswith('5'):
            color = RED
        else:
            color = RESET

        # Decode path
        path = urllib.parse.unquote(path)

        timestamp = self.log_date_time_string()
        print(f"  {DIM}{timestamp}{RESET} {color}{method}{RESET} {path} {color}{status}{RESET}")

    def list_directory(self, path):
        """Generate directory listing with better formatting"""
        try:
            entries = os.listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        entries.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))

        # Build HTML
        display_path = urllib.parse.unquote(self.path)

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Index of {display_path}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; font-weight: 300; }}
        table {{ border-collapse: collapse; width: 100%; max-width: 800px; }}
        th, td {{ text-align: left; padding: 12px 16px; border-bottom: 1px solid #333; }}
        th {{ color: #888; font-weight: 500; font-size: 12px; text-transform: uppercase; }}
        a {{ color: #00d4ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .dir {{ color: #ffd700; }}
        .size {{ color: #888; font-size: 14px; }}
        .icon {{ margin-right: 8px; }}
    </style>
</head>
<body>
    <h1>Index of {display_path}</h1>
    <table>
        <tr><th>Name</th><th>Size</th><th>Modified</th></tr>
'''

        # Parent directory link
        if display_path != '/':
            html += '<tr><td><span class="icon">📁</span><a href=".." class="dir">..</a></td><td></td><td></td></tr>'

        for name in entries:
            if name.startswith('.'):
                continue

            fullname = os.path.join(path, name)
            display_name = name
            link = urllib.parse.quote(name, errors='surrogatepass')

            try:
                stat = os.stat(fullname)
                size = stat.st_size
                mtime = stat.st_mtime
            except OSError:
                continue

            if os.path.isdir(fullname):
                display_name = name + '/'
                link = link + '/'
                size_str = '-'
                icon = '📁'
                cls = 'dir'
            else:
                size_str = format_size(size)
                # Choose icon based on extension
                ext = os.path.splitext(name)[1].lower()
                icons = {
                    '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
                    '.json': '📋', '.md': '📝', '.txt': '📄',
                    '.jpg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
                    '.mp3': '🎵', '.mp4': '🎬', '.pdf': '📕',
                    '.zip': '📦', '.tar': '📦', '.gz': '📦',
                }
                icon = icons.get(ext, '📄')
                cls = ''

            from datetime import datetime
            modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')

            html += f'<tr><td><span class="icon">{icon}</span><a href="{link}" class="{cls}">{display_name}</a></td>'
            html += f'<td class="size">{size_str}</td><td class="size">{modified}</td></tr>'

        html += '''
    </table>
</body>
</html>'''

        encoded = html.encode('utf-8', 'surrogateescape')
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()

        return encoded


class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded HTTP server"""
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description='Quick HTTP Server')
    parser.add_argument('port', nargs='?', type=int, default=8000, help='Port to serve on')
    parser.add_argument('--directory', '-d', default='.', help='Directory to serve')
    parser.add_argument('--bind', '-b', default='0.0.0.0', help='Address to bind')
    args = parser.parse_args()

    directory = os.path.abspath(args.directory)

    if not os.path.isdir(directory):
        print(f"{RED}Directory not found: {directory}{RESET}")
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🌐 HTTP File Server                           ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {BOLD}Directory:{RESET} {directory}")
    print(f"  {BOLD}Port:{RESET}      {args.port}")

    # Get URLs
    local_ip = get_local_ip()

    print(f"\n  {BOLD}Access URLs:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  {CYAN}Local:{RESET}   http://127.0.0.1:{args.port}/")
    print(f"  {CYAN}Network:{RESET} http://{local_ip}:{args.port}/")

    # Count files
    file_count = sum(len(files) for _, _, files in os.walk(directory))
    print(f"\n  {DIM}Serving {file_count} files{RESET}")

    print(f"\n  {YELLOW}Press Ctrl+C to stop{RESET}\n")
    print(f"  {BOLD}Request Log:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    # Create handler with directory
    handler = lambda *args, **kwargs: ColorHandler(*args, directory=directory, **kwargs)

    try:
        with ThreadedHTTPServer((args.bind, args.port), handler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Server stopped{RESET}\n")
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f"\n  {RED}Port {args.port} is already in use{RESET}")
            print(f"  {DIM}Try a different port: http_server.py 8080{RESET}\n")
        else:
            print(f"\n  {RED}Error: {e}{RESET}\n")


if __name__ == '__main__':
    main()
