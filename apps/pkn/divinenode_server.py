#!/usr/bin/env python3
"""
===========================================
DIVINE NODE FLASK SERVER (divinenode_server.py)
===========================================
Cross-references:
- HTML: pkn.html (serves static files and handles API calls)
- JS: tools.js (PhoneScan and network tools call /phonescan and /network endpoints)
- JS: app.js (image generation calls /api/generate-image)
- Config: config.js (LOCAL_IMAGE_GEN_URL points to /api/generate-image)
- Mobile: termux_menu.sh (starts this server on port 8010)
- Requirements: requirements.txt (Flask, phonenumbers, requests dependencies)

Server Endpoints:
- /phonescan: Phone number validation and carrier lookup
- /network: Network utilities (IP geolocate, DNS, port scan)
- /api/generate-image: LOCAL AI image generation via Stable Diffusion (100% private)
- /api/editor/files: List editable files in PKN directory (Monaco Editor)
- /api/editor/read: Read file content for editing
- /api/editor/write: Save file content (creates .bak backups)
- /health: Server health check
- Static files: Serves pkn.html, main.css, app.js, tools.js, config.js

Deployment:
- Desktop: python divinenode_server.py (port 8010)
- Mobile: Run via termux_menu.sh in Termux environment
===========================================
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import subprocess
import socket
import json
import time
import os
import contextlib
import uuid
import requests
from pathlib import Path

# Local image generation
import local_image_gen

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for local development

# Serve the static frontend files (pkn.html, css, js, img, etc.)
ROOT = Path(__file__).parent

# Local LLM endpoints (can be overridden via environment variables)
# These values may include a path like /v1; normalize when building full URLs below.
OLLAMA_BASE = os.environ.get('OLLAMA_BASE', 'http://127.0.0.1:11434')
LOCAL_LLM_BASE = os.environ.get('LOCAL_LLM_BASE', 'http://127.0.0.1:8000/v1')


def _join_url(base: str, *parts: str) -> str:
    """Join a base URL with path parts, avoiding double slashes."""
    if not base:
        return '/'.join(p.strip('/') for p in parts)
    base = base.rstrip('/')
    paths = [p.strip('/') for p in parts if p]
    if not paths:
        return base
    return base + '/' + '/'.join(paths)

@app.route('/')
@app.route('/pkn.html')
def index():
    response = send_from_directory(ROOT, 'pkn.html')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/<path:filename>')
def static_files(filename):
    # Serve files from the project root so existing relative paths work
    path = ROOT / filename
    if path.exists() and path.is_file():
        response = send_from_directory(ROOT, filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    # Not found — preserve earlier behavior for API routes
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/phonescan', methods=['POST'])
def phonescan():
    try:
        data = request.get_json()
        number = data.get('number', '')
        
        if not number:
            return jsonify({'error': 'No phone number provided'}), 400
        
        # Parse the phone number
        parsed = phonenumbers.parse(number, None)
        
        # Get information
        is_valid = phonenumbers.is_valid_number(parsed)
        country = geocoder.description_for_number(parsed, 'en')
        carrier_name = carrier.name_for_number(parsed, 'en')
        timezones = timezone.time_zones_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)
        
        # Map number type to readable string
        type_map = {
            0: 'Fixed Line',
            1: 'Mobile',
            2: 'Fixed Line or Mobile',
            3: 'Toll Free',
            4: 'Premium Rate',
            5: 'Shared Cost',
            6: 'VoIP',
            7: 'Personal Number',
            8: 'Pager',
            9: 'UAN',
            10: 'Voicemail',
            99: 'Unknown'
        }
        
        result = {
            'number': number,
            'valid': is_valid,
            'country': country or 'Unknown',
            'carrier': carrier_name or 'Unknown',
            'timezones': list(timezones) if timezones else ['Unknown'],
            'type': type_map.get(number_type, 'Unknown'),
            'international_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'e164_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'summary': f"""Phone Number Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Number: {number}
Valid: {'✓ Yes' if is_valid else '✗ No'}
Country: {country or 'Unknown'}
Carrier: {carrier_name or 'Unknown'}
Type: {type_map.get(number_type, 'Unknown')}
Timezones: {', '.join(timezones) if timezones else 'Unknown'}
International: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}
E.164: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        }
        
        return jsonify(result), 200
        
    except phonenumbers.NumberParseException as e:
        return jsonify({
            'error': f'Invalid phone number format: {str(e)}',
            'summary': f'Error: Invalid phone number format - {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'error': str(e),
            'summary': f'Error: {str(e)}'
        }), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'phonescan'}), 200

# Add API-style health endpoint for clients expecting /api/health
@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'status': 'ok', 'service': 'divinenode_api'}), 200


# --- Network utility endpoints (backend-powered) ---
@app.route('/api/network/dns', methods=['POST'])
def network_dns():
    try:
        data = request.get_json() or {}
        domain = data.get('domain', '')
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        # Simple lookup using socket (returns A/AAAA depending on system resolver)
        try:
            infos = socket.getaddrinfo(domain, None)
            addrs = []
            for info in infos:
                addr = info[4][0]
                if addr not in addrs:
                    addrs.append(addr)
            return jsonify({'domain': domain, 'addresses': addrs}), 200
        except Exception as e:
            return jsonify({'error': f'DNS lookup failed: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network/ping', methods=['POST'])
def network_ping():
    try:
        data = request.get_json() or {}
        host = data.get('host', '')
        count = int(data.get('count', 4))
        if not host:
            return jsonify({'error': 'No host provided'}), 400

        # Limit count to prevent abuse
        if count < 1 or count > 10:
            count = 4

        # Use system ping (Linux). Capture stdout.
        try:
            proc = subprocess.run(['ping', '-c', str(count), host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            out = proc.stdout.strip()
            err = proc.stderr.strip()
            status = proc.returncode
            return jsonify({'host': host, 'count': count, 'returncode': status, 'stdout': out, 'stderr': err}), 200
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Ping command timed out'}), 500
        except Exception as e:
            return jsonify({'error': f'Ping failed: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network/portscan', methods=['POST'])
def network_portscan():
    try:
        data = request.get_json() or {}
        host = data.get('host', '')
        ports = data.get('ports', [])
        timeout = float(data.get('timeout', 1.0))

        if not host:
            return jsonify({'error': 'No host provided'}), 400

        # If ports not provided, use common ports
        if not ports:
            ports = [22, 80, 443, 8080]

        # Sanitize ports: only ints, reasonable range, limit number
        clean_ports = []
        for p in ports:
            try:
                pi = int(p)
                if 1 <= pi <= 65535:
                    clean_ports.append(pi)
            except Exception:
                continue
        clean_ports = clean_ports[:30]

        results = []
        for p in clean_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            start = time.time()
            try:
                s.connect((host, p))
                elapsed = (time.time() - start) * 1000.0
                results.append({'port': p, 'open': True, 'rtt_ms': round(elapsed, 2)})
            except socket.timeout:
                results.append({'port': p, 'open': False, 'reason': 'timeout'})
            except Exception as e:
                results.append({'port': p, 'open': False, 'reason': str(e)})
            finally:
                # Use contextlib.suppress to silence errors
                with contextlib.suppress(Exception):
                    s.close()

        return jsonify({'host': host, 'results': results}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- OSINT endpoints ---
# Import OSINT tools
from tools.osint_tools import OSINTTools
osint = OSINTTools()

@app.route('/api/osint/whois', methods=['POST'])
def osint_whois():
    """Perform WHOIS lookup on domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        result = osint.whois_lookup(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/dns', methods=['POST'])
def osint_dns():
    """Perform DNS lookups on domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        record_types = data.get('record_types', ['A', 'AAAA', 'MX', 'TXT', 'NS'])

        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        result = osint.dns_lookup(domain, record_types)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/ip-geo', methods=['POST'])
def osint_ip_geo():
    """Get IP geolocation information"""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()

        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400

        result = osint.ip_geolocation(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/port-scan', methods=['POST'])
def osint_port_scan():
    """Perform basic port scan (AUTHORIZED USE ONLY)"""
    try:
        data = request.get_json()
        host = data.get('host', '').strip()
        ports = data.get('ports', [80, 443, 22, 21, 25, 3306, 5432, 8080])

        if not host:
            return jsonify({'error': 'No host provided'}), 400

        result = osint.port_scan_basic(host, ports)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/email-validate', methods=['POST'])
def osint_email_validate():
    """Validate email address format and MX records"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()

        if not email:
            return jsonify({'error': 'No email provided'}), 400

        result = osint.email_validate(email)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/username-search', methods=['POST'])
def osint_username_search():
    """Search for username across social platforms"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()

        if not username:
            return jsonify({'error': 'No username provided'}), 400

        result = osint.username_search(username)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/web-tech', methods=['POST'])
def osint_web_tech():
    """Detect web technologies used by a website"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        result = osint.web_technologies(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/ssl-cert', methods=['POST'])
def osint_ssl_cert():
    """Get SSL certificate information"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        result = osint.ssl_certificate_info(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/wayback', methods=['POST'])
def osint_wayback():
    """Check Wayback Machine for archived versions"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        result = osint.wayback_check(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/subdomain-enum', methods=['POST'])
def osint_subdomain_enum():
    """Enumerate subdomains for a domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        result = osint.subdomain_enum(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/reverse-dns', methods=['POST'])
def osint_reverse_dns():
    """Perform reverse DNS lookup on IP address"""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()

        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400

        result = osint.reverse_dns(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/osint/phone-lookup', methods=['POST'])
def osint_phone_lookup():
    """Get phone number carrier and timezone info"""
    try:
        data = request.get_json()
        phone = data.get('phone', '').strip()

        if not phone:
            return jsonify({'error': 'No phone number provided'}), 400

        result = osint.phone_number_lookup(phone)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500


# --- File storage endpoints ---
UPLOAD_DIR = Path(__file__).parent / 'uploads'
META_FILE = UPLOAD_DIR / 'files.json'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# File upload configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    # Documents
    'txt', 'pdf', 'doc', 'docx', 'odt', 'rtf',
    # Images
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
    # Code
    'py', 'js', 'html', 'css', 'json', 'xml', 'yaml', 'yml',
    'c', 'cpp', 'h', 'hpp', 'java', 'rs', 'go', 'sh', 'md',
    # Data
    'csv', 'tsv', 'xlsx', 'xls',
    # Archives
    'zip', 'tar', 'gz', 'bz2', '7z',
    # Other
    'log', 'ini', 'cfg', 'conf'
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _load_meta():
    # Loads file metadata for uploads (see /api/files/upload)
    # Related: _save_meta, list_files, delete_file
    try:
        if META_FILE.exists():
            return json.loads(META_FILE.read_text())
    except Exception:
        pass
    return {}

def _save_meta(meta):
    # Saves file metadata for uploads (see /api/files/upload)
    # Related: _load_meta, list_files, delete_file
    with contextlib.suppress(Exception):
        META_FILE.write_text(json.dumps(meta, indent=2))


@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        f = request.files['file']
        if f.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Validate file extension
        if not allowed_file(f.filename):
            return jsonify({'error': 'File type not allowed'}), 400

        # Check file size (read content to validate)
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)  # Reset to beginning

        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': f'File too large. Max size: {MAX_FILE_SIZE // (1024*1024)}MB'}), 400

        if file_size == 0:
            return jsonify({'error': 'File is empty'}), 400

        # generate id and store
        fid = str(uuid.uuid4())
        safe_name = os.path.basename(f.filename)
        # Additional security: sanitize filename
        safe_name = safe_name.replace('..', '').replace('/', '').replace('\\', '')
        dest = UPLOAD_DIR / f"{fid}_{safe_name}"
        f.save(dest)

        # basic metadata
        meta = _load_meta()
        meta[fid] = {
            'id': fid,
            'filename': safe_name,
            'stored_name': dest.name,
            'size': dest.stat().st_size,
            'uploaded_at': int(time.time())
        }
        _save_meta(meta)

        return jsonify({'id': fid, 'filename': safe_name, 'size': meta[fid]['size']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/list', methods=['GET'])
def list_files():
    try:
        meta = _load_meta()
        files = list(meta.values())
        # sort by uploaded_at desc
        files.sort(key=lambda x: x.get('uploaded_at', 0), reverse=True)
        return jsonify({'files': files}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/<file_id>/summary', methods=['GET'])
def file_summary(file_id):
    try:
        meta = _load_meta()
        entry = meta.get(file_id)
        if not entry:
            return jsonify({'error': 'File not found'}), 404

        path = UPLOAD_DIR / entry['stored_name']
        if not path.exists():
            return jsonify({'error': 'Stored file missing'}), 404

        # Only attempt to read text files (simple heuristic)
        try:
            text = path.read_text(errors='ignore')
        except Exception as e:
            return jsonify({'error': f'Could not read file: {str(e)}'}), 500

        snippet = text[:3000]
        # simple summary: first 500 chars + top words
        first = snippet[:500]
        words = [w.strip('.,:;"\'"()[]{}').lower() for w in snippet.split()]
        # Stopwords for summary (see app.js for similar logic in chat summarization)
        stop = {
            'the', 'and', 'for', 'that', 'with', 'this', 'from', 'are', 'was', 'were', 'have', 'has', 'will', 'you', 'your', 'not', 'but', 'can', 'our', 'all', 'any', 'too', 'its', "it's"
        }
        freq = {}
        for w in words:
            if len(w) < 3 or w in stop: continue
            freq[w] = freq.get(w, 0) + 1
        top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:8]
        keywords = [k for k,v in top]

        return jsonify({'id': file_id, 'filename': entry['filename'], 'summary': first, 'keywords': keywords}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    try:
        meta = _load_meta()
        entry = meta.get(file_id)
        if not entry:
            return jsonify({'error': 'File not found'}), 404

        file_path = UPLOAD_DIR / entry['stored_name']
        if file_path.exists():
            os.remove(file_path)

        del meta[file_id]
        _save_meta(meta)

        return jsonify({'message': 'File deleted successfully', 'id': file_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== FILE EXPLORER ENDPOINTS =====

@app.route('/api/files/browse', methods=['POST'])
def browse_directory():
    """Browse files in a directory"""
    try:
        data = request.json
        path = data.get('path', '/')

        # Security: Prevent directory traversal
        if '..' in path or path.startswith('~'):
            return jsonify({'error': 'Invalid path'}), 400

        # Convert to Path object
        from pathlib import Path
        import stat

        dir_path = Path(path)

        if not dir_path.exists():
            return jsonify({'error': 'Path does not exist'}), 404

        if not dir_path.is_dir():
            return jsonify({'error': 'Path is not a directory'}), 400

        files = []
        try:
            for item in dir_path.iterdir():
                try:
                    stats = item.stat()
                    files.append({
                        'name': item.name,
                        'type': 'directory' if item.is_dir() else 'file',
                        'size': stats.st_size if item.is_file() else 0,
                        'modified': stats.st_mtime
                    })
                except (PermissionError, OSError):
                    # Skip files we can't access
                    continue
        except PermissionError:
            return jsonify({'error': 'Permission denied'}), 403

        return jsonify({
            'path': str(dir_path),
            'files': files
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download', methods=['POST'])
def download_file_from_path():
    """Download a file from filesystem"""
    try:
        data = request.json
        path = data.get('path', '')

        # Security: Prevent directory traversal
        if '..' in path or path.startswith('~'):
            return jsonify({'error': 'Invalid path'}), 400

        from pathlib import Path
        file_path = Path(path)

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        if not file_path.is_file():
            return jsonify({'error': 'Path is not a file'}), 400

        from flask import send_file
        return send_file(
            str(file_path),
            as_attachment=True,
            download_name=file_path.name
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/view', methods=['POST'])
def view_file_content():
    """View text file content"""
    try:
        data = request.json
        path = data.get('path', '')
        max_lines = data.get('max_lines', 500)

        # Security: Prevent directory traversal
        if '..' in path or path.startswith('~'):
            return jsonify({'error': 'Invalid path'}), 400

        from pathlib import Path
        file_path = Path(path)

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        if not file_path.is_file():
            return jsonify({'error': 'Path is not a file'}), 400

        # Check file size (limit to 10MB for text view)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return jsonify({'error': 'File too large to view (max 10MB)'}), 400

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        return jsonify({
                            'content': ''.join(lines),
                            'truncated': True,
                            'lines_read': i
                        }), 200
                    lines.append(line)

                return jsonify({
                    'content': ''.join(lines),
                    'truncated': False,
                    'lines_read': len(lines)
                }), 200
        except UnicodeDecodeError:
            return jsonify({'error': 'File is not a text file or has invalid encoding'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/delete', methods=['POST'])
def delete_filesystem_item():
    """Delete a file or directory"""
    try:
        data = request.json
        path = data.get('path', '')
        recursive = data.get('recursive', False)

        # Security: Prevent directory traversal
        if '..' in path or path.startswith('~'):
            return jsonify({'error': 'Invalid path'}), 400

        from pathlib import Path
        import shutil

        item_path = Path(path)

        if not item_path.exists():
            return jsonify({'error': 'Path not found'}), 404

        # Additional safety: Don't allow deleting critical system directories
        critical_paths = ['/sdcard', '/data/data/com.termux/files/home', '/']
        if str(item_path) in critical_paths:
            return jsonify({'error': 'Cannot delete critical system directory'}), 403

        if item_path.is_dir():
            if not recursive:
                # Check if directory is empty
                if any(item_path.iterdir()):
                    return jsonify({'error': 'Directory not empty. Use recursive delete.'}), 400
                item_path.rmdir()
            else:
                shutil.rmtree(item_path)
        else:
            item_path.unlink()

        return jsonify({'message': 'Deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/mkdir', methods=['POST'])
def create_directory():
    """Create a new directory"""
    try:
        data = request.json
        path = data.get('path', '')

        # Security: Prevent directory traversal
        if '..' in path or path.startswith('~'):
            return jsonify({'error': 'Invalid path'}), 400

        from pathlib import Path
        dir_path = Path(path)

        if dir_path.exists():
            return jsonify({'error': 'Path already exists'}), 400

        dir_path.mkdir(parents=False, exist_ok=False)

        return jsonify({'message': 'Directory created successfully', 'path': str(dir_path)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# CODE EDITOR API ENDPOINTS
# ============================================

@app.route('/api/editor/files', methods=['GET'])
def list_editable_files():
    """
    List all editable files in the PKN directory
    Returns: JSON list of files with name and path
    """
    try:
        pkn_dir = Path(__file__).parent
        editable_extensions = {'.py', '.js', '.html', '.css', '.json', '.md', '.txt', '.sh', '.env'}

        files = []
        for file_path in pkn_dir.rglob('*'):
            # Skip hidden files, cache, venv, and large directories
            if any(part.startswith('.') for part in file_path.parts):
                continue
            if any(exclude in str(file_path) for exclude in ['__pycache__', 'node_modules', '.venv', '.git']):
                continue

            if file_path.is_file() and file_path.suffix in editable_extensions:
                rel_path = file_path.relative_to(pkn_dir)
                files.append({
                    'name': str(rel_path),
                    'path': str(file_path)
                })

        # Sort by name
        files.sort(key=lambda x: x['name'])

        return jsonify({'files': files}), 200
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/editor/read', methods=['POST'])
def read_file_content():
    """
    Read content of a file
    Request: { "file_path": "/path/to/file" }
    Returns: { "content": "file contents..." }
    """
    try:
        data = request.json
        file_path = Path(data.get('file_path', ''))

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        # Security: Only allow reading files within PKN directory
        pkn_dir = Path(__file__).parent
        try:
            file_path.relative_to(pkn_dir)
        except ValueError:
            return jsonify({'error': 'Access denied - file outside PKN directory'}), 403

        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return jsonify({'content': content}), 200
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/editor/write', methods=['POST'])
def write_file_content():
    """
    Write content to a file
    Request: { "file_path": "/path/to/file", "content": "new content..." }
    Returns: { "success": true }
    """
    try:
        data = request.json
        file_path = Path(data.get('file_path', ''))
        content = data.get('content', '')

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        # Security: Only allow writing files within PKN directory
        pkn_dir = Path(__file__).parent
        try:
            file_path.relative_to(pkn_dir)
        except ValueError:
            return jsonify({'error': 'Access denied - file outside PKN directory'}), 403

        # Create backup before writing
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

        # Write new content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✓ [Editor] Saved: {file_path.name} (backup: {backup_path.name})")
        return jsonify({'success': True, 'message': f'File saved: {file_path.name}'}), 200
    except Exception as e:
        print(f"Error writing file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-image', methods=['POST'])
def generate_image():
    """
    Generate images using LOCAL Stable Diffusion
    100% private - runs on your machine, no external APIs
    """
    try:
        data = request.json
        prompt = data.get('prompt', '')

        if not prompt:
            return jsonify({'error': 'Prompt is required'}), 400

        print(f"🎨 [Image Gen] Generating locally: {prompt[:50]}...")

        # Use local image generator (completely private)
        # Euler scheduler: 30-50 steps recommended
        # CPU mode: 30 steps (~2.5 min), GPU mode: 50 steps (~30 sec)
        image_data = local_image_gen.generate_image(
            prompt=prompt,
            num_inference_steps=30,  # Euler works well with 30 steps
            width=512,
            height=512
        )

        print(f"✓ [Image Gen] Generated successfully")
        return jsonify({'image': image_data}), 200

    except Exception as e:
        print(f"✗ [Image Gen] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Local generation failed: {str(e)}'}), 500

@app.route('/api/generate-image-stream', methods=['POST'])
def generate_image_stream():
    """
    Generate images with Server-Sent Events for real-time progress updates
    """
    import json
    from flask import Response, stream_with_context

    data = request.json
    prompt = data.get('prompt', '')

    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400

    def generate_with_progress():
        """Generator function that yields SSE events"""
        try:
            print(f"🎨 [Image Gen SSE] Starting: {prompt[:50]}...")

            # Send initial status
            yield f"data: {json.dumps({'status': 'starting', 'message': 'Initializing image generator...'})}\n\n"

            # Progress callback
            def progress_callback(step, total_steps):
                progress = step / total_steps
                data = {
                    'status': 'progress',
                    'step': step,
                    'total_steps': total_steps,
                    'progress': progress,
                    'message': f'Generating... {step}/{total_steps} steps ({int(progress * 100)}%)'
                }
                return f"data: {json.dumps(data)}\n\n"

            # Storage for progress events
            progress_events = []

            def store_progress(step, total_steps):
                event = progress_callback(step, total_steps)
                progress_events.append(event)

            # Generate image with progress callback
            image_data = local_image_gen.generate_image(
                prompt=prompt,
                num_inference_steps=30,
                width=512,
                height=512,
                callback=store_progress
            )

            # Yield all progress events
            for event in progress_events:
                yield event

            # Send completion event with image
            yield f"data: {json.dumps({'status': 'complete', 'image': image_data, 'message': 'Image generated successfully!'})}\n\n"

            print(f"✓ [Image Gen SSE] Completed successfully")

        except Exception as e:
            print(f"✗ [Image Gen SSE] Error: {str(e)}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'status': 'error', 'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate_with_progress()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/models/ollama', methods=['GET'])
def list_ollama_models():
    # Returns available Ollama models (see app.js: refreshOllamaModels)
    try:
        # Try a few commonly-used Ollama endpoints in case the base includes or omits a /v1 prefix.
        candidate_paths = [
            ('api', 'models'),
            ('models',),
            ('v1', 'models'),
            ('api', 'tags'),
            ('tags',),
        ]

        models = []
        last_err = None
        for parts in candidate_paths:
            url = _join_url(OLLAMA_BASE, *parts)
            try:
                resp = requests.get(url, timeout=8)
                resp.raise_for_status()
                data = resp.json() or {}
                # Common keys: 'models' or 'tags' (depending on Ollama version)
                if isinstance(data, dict):
                    if 'models' in data and isinstance(data['models'], list):
                        models = data['models']
                        break
                    if 'tags' in data and isinstance(data['tags'], list):
                        # tags may be simple strings or objects
                        models = [{'name': t if isinstance(t, str) else t.get('name', str(t))} for t in data['tags']]
                        break
                    # Some endpoints return a plain list
                    if isinstance(data, list):
                        models = [{'name': (m.get('name') if isinstance(m, dict) else str(m))} for m in data]
                        break
                # otherwise keep trying
            except requests.RequestException as e:
                last_err = e

        if not models:
            # Return empty list with an informative message if none discovered
            if last_err:
                return jsonify({'models': [], 'error': f'Ollama query failed: {last_err}'}), 502
            return jsonify({'models': []}), 200

        return jsonify({'models': models}), 200
    except requests.RequestException as e:
        return jsonify({'error': f'Ollama request failed: {str(e)}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/llamacpp', methods=['GET'])
def list_llamacpp_models():
    """Return all GGUF models in llama.cpp/models/ directory"""
    try:
        models_dir = ROOT / 'llama.cpp' / 'models'
        if not models_dir.exists() or not models_dir.is_dir():
            return jsonify({'models': []}), 200
        models = []
        for f in models_dir.iterdir():
            if f.is_file() and f.suffix.lower() == '.gguf':
                models.append({'name': f.name})
        return jsonify({'models': models}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/health', methods=['GET'])
def models_health():
    """Quick health check for configured LLM backends (Ollama and local OpenAI-compatible server)."""
    results = {}
    # Check Ollama
    try:
        ok = False
        candidate = [
            _join_url(OLLAMA_BASE, 'api', 'models'),
            _join_url(OLLAMA_BASE, 'models'),
            _join_url(OLLAMA_BASE, 'api', 'tags'),
            _join_url(OLLAMA_BASE, 'health'),
        ]
        last_err = None
        for url in candidate:
            try:
                r = requests.get(url, timeout=4)
                if r.ok:
                    ok = True
                    break
            except Exception as e:
                last_err = str(e)
        results['ollama'] = {'base': OLLAMA_BASE, 'ok': ok, 'error': None if ok else last_err}
    except Exception as e:
        results['ollama'] = {'base': OLLAMA_BASE, 'ok': False, 'error': str(e)}

    # Check local OpenAI-compatible LLM (llama-server / llama.cpp server)
    try:
        ok = False
        candidate = [
            _join_url(LOCAL_LLM_BASE, 'chat', 'completions'),
            _join_url(LOCAL_LLM_BASE, 'v1', 'chat', 'completions'),
            _join_url(LOCAL_LLM_BASE, ''),
        ]
        last_err = None
        for url in candidate:
            try:
                r = requests.get(url, timeout=4)
                if r.ok:
                    ok = True
                    break
            except Exception as e:
                last_err = str(e)
        results['local_llm'] = {'base': LOCAL_LLM_BASE, 'ok': ok, 'error': None if ok else last_err}
    except Exception as e:
        results['local_llm'] = {'base': LOCAL_LLM_BASE, 'ok': False, 'error': str(e)}

    return jsonify(results), 200

@app.route('/api/chat', methods=['POST'])
def api_chat():
    try:
        data = request.get_json() or {}
        model_id = data.get('modelId', '')
        messages = data.get('messages', [])

        # Backwards compatibility: accept 'local' shorthand.
        if model_id == 'local':
            app.logger.debug('Normalized legacy modelId "local" to llamacpp:local')
            model_id = 'llamacpp:local'

        msg_count = len(messages) if isinstance(messages, list) else '?'
        app.logger.debug('api_chat request: model_id=%s', model_id)
        app.logger.debug('api_chat messages_count=%s', msg_count)

        if not model_id:
            return jsonify({'error': 'No modelId provided'}), 400

        if not isinstance(messages, list) or len(messages) == 0:
            return jsonify({'error': 'No messages provided'}), 400

        # Expect ids like "ollama:mannix/llama3.1-8b-lexi:q4_0"
        if model_id.startswith('ollama:'):
            ollama_model = model_id.replace('ollama:', '', 1)
            ollama_messages = []
            for m in messages:
                role = m.get('role', 'user')
                content = m.get('content', '')
                ollama_messages.append({'role': role, 'content': content})
            try:
                # Try a couple of possible Ollama chat endpoints (base may already include /v1)
                candidate_chat_paths = [
                    ('api', 'chat'),
                    ('chat',),
                    ('v1', 'chat'),
                ]
                last_exc = None
                for parts in candidate_chat_paths:
                    url = _join_url(OLLAMA_BASE, *parts)
                    try:
                        app.logger.debug('Attempting Ollama chat POST to %s (model=%s)', url, ollama_model)
                        resp = requests.post(
                            url,
                            json={
                                'model': ollama_model,
                                'stream': False,
                                'messages': ollama_messages,
                            },
                            timeout=600,
                        )
                        app.logger.debug('Ollama response from %s: status=%s', url, getattr(resp, 'status_code', None))
                        resp.raise_for_status()
                        # Be tolerant of non-JSON responses (some Ollama setups may stream or return plain text)
                        try:
                            return jsonify(resp.json()), 200
                        except ValueError:
                            # Non-JSON body — return as text payload for debugging/client handling
                            return jsonify({'text': resp.text}), 200
                    except requests.RequestException as e:
                        last_exc = e
                        # try next candidate
                # If none of the candidates worked, return the last error
                return jsonify({'error': f'Ollama request failed: {last_exc}'}), 502
            except requests.RequestException as e:
                return jsonify({'error': f'Ollama request failed: {str(e)}'}), 502
        elif model_id.startswith('llamacpp:') or model_id.startswith('llama-server:') or model_id.startswith('openai:'):
            # Forward to a local OpenAI-compatible Llama server (llama.cpp's server or llama-server)
            # Expect format: "llamacpp:MODEL_NAME" or "llama-server:MODEL_NAME" (MODEL_NAME optional)
            model_name = model_id.split(':', 1)[1] if ':' in model_id else ''
            payload = {
                'model': model_name or 'local',
                'messages': [{'role': m.get('role', 'user'), 'content': m.get('content', '')} for m in messages]
            }
            try:
                # Use normalized joining to avoid double path components
                url = _join_url(LOCAL_LLM_BASE, 'chat', 'completions')
                app.logger.debug('Forwarding to local LLM at %s payload model=%s', url, payload.get('model'))
                resp = requests.post(url, json=payload, timeout=600)
                app.logger.debug('Local LLM response status=%s', getattr(resp, 'status_code', None))
                resp.raise_for_status()
                try:
                    return jsonify(resp.json()), 200
                except ValueError:
                    return jsonify({'text': resp.text}), 200
            except requests.RequestException as e:
                return jsonify({'error': f'Local Llama request failed: {str(e)}'}), 502
        else:
            return jsonify({'error': 'Unsupported provider/modelId'}), 400

    except requests.RequestException as e:
        return jsonify({'error': f'Ollama request failed: {str(e)}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent', methods=['POST'])
def api_agent():
    """
    Enhanced Parakleon agent endpoint with tool use and web access.

    Request body:
    {
        "instruction": "Your task for the agent",
        "conversation_id": "optional-unique-id"
    }

    Returns:
    {
        "response": "Agent's response",
        "tools_used": ["list", "of", "tools"],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        instruction = data.get('instruction', '')
        conversation_id = data.get('conversation_id', str(uuid.uuid4()))

        if not instruction:
            return jsonify({'error': 'No instruction provided'}), 400

        app.logger.debug(f'Agent request: conversation_id={conversation_id}')
        app.logger.debug(f'Agent instruction: {instruction[:100]}...')

        # Import and run the enhanced agent
        try:
            from local_parakleon_agent import run_agent, WEB_TOOLS_AVAILABLE

            # Run the agent with the instruction
            response = run_agent(instruction)

            return jsonify({
                'response': response,
                'web_tools_available': WEB_TOOLS_AVAILABLE,
                'conversation_id': conversation_id,
                'status': 'success'
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import agent: {e}')
            return jsonify({
                'error': 'Enhanced agent not available. Install langchain-openai and langchain-core.',
                'details': str(e)
            }), 503
        except Exception as e:
            app.logger.error(f'Agent execution failed: {e}')
            return jsonify({
                'error': 'Agent execution failed',
                'details': str(e)
            }), 500

    except Exception as e:
        app.logger.error(f'Agent endpoint error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/autocomplete', methods=['POST'])
def api_autocomplete():
    """
    Code autocomplete endpoint for intelligent code suggestions.

    Request body:
    {
        "prefix": "partial code to complete",
        "file_path": "/path/to/current/file.py",
        "context_line": "full line of code for context",
        "language": "python|javascript|html|css (optional)"
    }

    Returns:
    {
        "completions": [
            {"text": "suggestion", "type": "function|class|variable", "detail": "signature"}
        ],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        prefix = data.get('prefix', '')
        file_path = data.get('file_path', '')
        context_line = data.get('context_line', '')

        if not prefix:
            return jsonify({'completions': [], 'status': 'no_prefix'}), 200

        try:
            from code_context import code_context

            # Get completions from code context system
            completions = code_context.get_completions(
                prefix=prefix,
                file_path=file_path,
                context_line=context_line
            )

            return jsonify({
                'completions': completions,
                'prefix': prefix,
                'status': 'success'
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import code_context: {e}')
            return jsonify({
                'error': 'Code context system not available',
                'completions': [],
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'Autocomplete error: {e}')
            return jsonify({
                'error': str(e),
                'completions': [],
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Autocomplete endpoint error: {e}')
        return jsonify({'error': str(e), 'completions': [], 'status': 'error'}), 500

@app.route('/api/code/analyze', methods=['POST'])
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
        file_path = data.get('file_path', '')

        if not file_path:
            return jsonify({'error': 'No file_path provided', 'status': 'error'}), 400

        try:
            from code_context import code_context

            # Analyze the file
            result = code_context.analyze_file(file_path)
            result['status'] = 'success'

            return jsonify(result), 200

        except ImportError as e:
            app.logger.error(f'Failed to import code_context: {e}')
            return jsonify({
                'error': 'Code context system not available',
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'File analysis error: {e}')
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Code analyze endpoint error: {e}')
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/code/scan-project', methods=['POST'])
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
        extensions = data.get('extensions', ['.py', '.js', '.html', '.css'])

        try:
            from code_context import code_context

            # Scan project
            stats = code_context.scan_project(extensions)
            project_stats = code_context.get_project_stats()

            return jsonify({
                'stats': stats,
                'project_stats': project_stats,
                'status': 'success'
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import code_context: {e}')
            return jsonify({
                'error': 'Code context system not available',
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'Project scan error: {e}')
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Project scan endpoint error: {e}')
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/multi-agent/chat', methods=['POST'])
def api_multi_agent_chat():
    """
    Multi-agent chat endpoint with intelligent routing and conversation memory.

    Request body:
    {
        "message": "User's message",
        "session_id": "optional-session-id",
        "user_id": "optional-user-id"
    }

    Returns:
    {
        "response": "Agent's response",
        "session_id": "session-id",
        "agent_used": "coder|researcher|executor|reasoner|general",
        "routing": {...routing details...},
        "execution_time": 1.23,
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        message = data.get('message', '')
        session_id = data.get('session_id')
        user_id = data.get('user_id', 'default')

        if not message:
            return jsonify({'error': 'No message provided', 'status': 'error'}), 400

        try:
            from conversation_memory import conversation_memory
            from agent_manager import agent_manager
            import asyncio

            # Create or get session
            if not session_id or not conversation_memory.get_session(session_id):
                session_id = conversation_memory.create_session(user_id)
                app.logger.info(f'Created new session: {session_id}')
            else:
                app.logger.info(f'Using existing session: {session_id}')

            # Add user message to history
            conversation_memory.add_message(session_id, 'user', message)

            # Route and execute task
            app.logger.debug(f'Routing task: {message[:50]}...')
            result = asyncio.run(agent_manager.execute_task(message, session_id))

            # Add assistant response to history
            if result['status'] == 'success':
                conversation_memory.add_message(
                    session_id,
                    'assistant',
                    result['response'],
                    agent=result['agent_used'],
                    tools_used=result.get('tools_used', [])
                )

            # Get conversation summary for response
            summary = conversation_memory.get_session_summary(session_id)

            return jsonify({
                'response': result['response'],
                'session_id': session_id,
                'agent_used': result['agent_used'],
                'agent_name': result.get('agent_name', ''),
                'routing': result.get('routing', {}),
                'execution_time': result['execution_time'],
                'tools_used': result.get('tools_used', []),
                'conversation_summary': {
                    'total_messages': summary['total_messages'],
                    'agents_used': summary['agents_used']
                },
                'status': result['status']
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import multi-agent system: {e}')
            return jsonify({
                'error': 'Multi-agent system not available',
                'details': str(e),
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'Multi-agent execution error: {e}')
            return jsonify({
                'error': 'Multi-agent execution failed',
                'details': str(e),
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Multi-agent chat endpoint error: {e}')
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/multi-agent/chat/stream', methods=['POST'])
def api_multi_agent_chat_stream():
    """
    Multi-agent chat endpoint with Server-Sent Events (SSE) streaming.

    Request body:
    {
        "message": "User's message",
        "session_id": "optional-session-id",
        "user_id": "optional-user-id"
    }

    Returns: SSE stream with events:
    - start: {"agent": "coder", "routing": {...}}
    - chunk: {"content": "token text"}
    - done: {"execution_time": 1.23, "tools_used": [...]}
    - error: {"content": "error message"}
    """
    # IMPORTANT: Parse request data OUTSIDE the generator to avoid Flask context error
    try:
        data = request.get_json() or {}
        message = data.get('message', '')
        session_id = data.get('session_id')
        user_id = data.get('user_id', 'default')
    except Exception as e:
        app.logger.error(f'Failed to parse request: {e}')
        return jsonify({'error': 'Invalid request data'}), 400

    if not message:
        return jsonify({'error': 'No message provided'}), 400

    def generate(message, session_id, user_id):
        try:

            try:
                from conversation_memory import conversation_memory
                from agent_manager import agent_manager
                import asyncio

                # Create or get session
                if not session_id or not conversation_memory.get_session(session_id):
                    session_id = conversation_memory.create_session(user_id)
                    app.logger.info(f'Created new session: {session_id}')
                else:
                    app.logger.info(f'Using existing session: {session_id}')

                # Add user message to history
                conversation_memory.add_message(session_id, 'user', message)

                # Stream the response - run async code in sync context
                full_response = ""
                agent_used = None
                tools_used = []
                execution_time = 0

                # Create new event loop for this generator
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                try:
                    # Get the async generator
                    async_gen = agent_manager.execute_task_streaming(message, session_id)

                    # Consume it synchronously
                    while True:
                        try:
                            # Get next event from async generator
                            event = loop.run_until_complete(async_gen.__anext__())
                            event_type = event.get('type')

                            if event_type == 'start':
                                agent_used = event.get('agent')
                                # Send start event with session info
                                yield f"event: start\ndata: {json.dumps({**event, 'session_id': session_id})}\n\n"

                            elif event_type == 'chunk':
                                full_response += event.get('content', '')
                                yield f"event: chunk\ndata: {json.dumps(event)}\n\n"

                            elif event_type == 'done':
                                execution_time = event.get('execution_time', 0)
                                tools_used = event.get('tools_used', [])
                                agent_used = event.get('agent_used', agent_used)
                                yield f"event: done\ndata: {json.dumps(event)}\n\n"

                            elif event_type == 'error':
                                yield f"event: error\ndata: {json.dumps(event)}\n\n"
                                break

                        except StopAsyncIteration:
                            # Generator finished normally
                            break

                finally:
                    loop.close()

                # Add assistant response to conversation history
                if full_response:
                    conversation_memory.add_message(
                        session_id,
                        'assistant',
                        full_response,
                        agent=agent_used,
                        tools_used=tools_used
                    )

            except ImportError as e:
                app.logger.error(f'Failed to import multi-agent system: {e}')
                yield f"event: error\ndata: {json.dumps({'content': 'Multi-agent system not available'})}\n\n"
            except Exception as e:
                app.logger.error(f'Multi-agent streaming error: {e}')
                yield f"event: error\ndata: {json.dumps({'content': str(e)})}\n\n"

        except Exception as e:
            app.logger.error(f'Stream generation error: {e}')
            yield f"event: error\ndata: {json.dumps({'content': str(e)})}\n\n"

    return app.response_class(
        generate(message, session_id, user_id),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

async def _async_generator_to_sync(async_gen):
    """Helper to convert async generator to sync for Flask"""
    try:
        while True:
            item = await async_gen.__anext__()
            yield item
    except StopAsyncIteration:
        pass

@app.route('/api/multi-agent/classify', methods=['POST'])
def api_classify_task():
    """
    Classify a task without executing it.

    Request body:
    {
        "instruction": "Task to classify"
    }

    Returns:
    {
        "agent_type": "coder|researcher|executor|reasoner|general",
        "complexity": "simple|medium|complex",
        "confidence": 0.85,
        "estimated_time": "2-5 seconds",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        instruction = data.get('instruction', '')

        if not instruction:
            return jsonify({'error': 'No instruction provided', 'status': 'error'}), 400

        try:
            from agent_manager import agent_manager

            routing = agent_manager.route_task(instruction)

            return jsonify({
                'agent_type': routing['agent'].value,
                'classification': {
                    'complexity': routing['classification']['complexity'].value,
                    'confidence': routing['classification']['confidence'],
                    'reasoning': routing['classification']['reasoning'],
                    'requires_tools': routing['classification']['requires_tools']
                },
                'strategy': routing['strategy'],
                'estimated_time': routing['estimated_time'],
                'agent_config': {
                    'name': routing['agent_config']['name'],
                    'capabilities': routing['agent_config']['capabilities'],
                    'speed': routing['agent_config']['speed']
                },
                'status': 'success'
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import agent_manager: {e}')
            return jsonify({
                'error': 'Agent manager not available',
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'Task classification error: {e}')
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Classify endpoint error: {e}')
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/multi-agent/agents', methods=['GET'])
def api_list_agents():
    """
    Get list of available agents.

    Returns:
    {
        "agents": [...],
        "status": "success"
    }
    """
    try:
        from agent_manager import agent_manager

        agents = agent_manager.get_available_agents()

        return jsonify({
            'agents': agents,
            'count': len(agents),
            'status': 'success'
        }), 200

    except ImportError as e:
        return jsonify({
            'error': 'Agent manager not available',
            'status': 'error'
        }), 503
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/multi-agent/vote', methods=['POST'])
def api_vote_on_decision():
    """
    Voting mechanism for complex decisions.
    Queries multiple agents including external LLMs for consensus.

    Request body:
    {
        "question": "Which approach is best?",
        "options": ["Option 1", "Option 2", "Option 3"],
        "context": "Additional context...",
        "use_external": true
    }

    Returns:
    {
        "choice": "Option 2",
        "votes": {"consultant": "Option 2", "reasoner": "Option 2"},
        "reasoning": {...},
        "consensus": 1.0,
        "final_reasoning": "...",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        question = data.get('question', '')
        options = data.get('options', [])
        context = data.get('context', '')
        use_external = data.get('use_external', True)

        if not question:
            return jsonify({'error': 'No question provided', 'status': 'error'}), 400

        if not options or len(options) < 2:
            return jsonify({'error': 'At least 2 options required', 'status': 'error'}), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            # Run voting
            result = asyncio.run(agent_manager.vote_on_decision(
                question=question,
                options=options,
                context=context,
                use_external=use_external
            ))

            return jsonify({
                'choice': result['choice'],
                'votes': result['votes'],
                'reasoning': result['reasoning'],
                'consensus': result['consensus'],
                'final_reasoning': result['final_reasoning'],
                'status': 'success'
            }), 200

        except ImportError as e:
            app.logger.error(f'Failed to import agent_manager: {e}')
            return jsonify({
                'error': 'Agent manager not available',
                'status': 'error'
            }), 503
        except Exception as e:
            app.logger.error(f'Voting error: {e}')
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500

    except Exception as e:
        app.logger.error(f'Vote endpoint error: {e}')
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/rag/search', methods=['POST'])
def api_rag_search():
    """
    Search codebase using RAG semantic search.

    Request body:
    {
        "query": "search query",
        "n_results": 5
    }

    Returns:
    {
        "success": true,
        "results": [...],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        query = data.get('query', '')
        n_results = data.get('n_results', 5)

        if not query:
            return jsonify({'error': 'No query provided', 'status': 'error'}), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.search_codebase_with_rag(query, n_results))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'RAG system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/planning/create', methods=['POST'])
def api_create_plan():
    """
    Create a structured execution plan for a complex task.

    Request body:
    {
        "task": "Complex task description",
        "context": {"optional": "context"}
    }

    Returns:
    {
        "success": true,
        "plan_id": "uuid",
        "goal": "...",
        "steps": [...],
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        task = data.get('task', '')
        context = data.get('context')

        if not task:
            return jsonify({'error': 'No task provided', 'status': 'error'}), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.create_task_plan(task, context))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Planning system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/planning/execute/<plan_id>', methods=['POST'])
def api_execute_plan(plan_id):
    """
    Execute a created plan step by step.

    Request body:
    {
        "session_id": "optional-session-id"
    }

    Returns:
    {
        "success": true,
        "steps_completed": 5,
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id', str(uuid.uuid4()))

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.execute_plan(plan_id, session_id))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Planning system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/delegation/delegate', methods=['POST'])
def api_delegate_task():
    """
    Delegate a task from one agent to another.

    Request body:
    {
        "from_agent": "coder",
        "to_agent": "researcher",
        "task": "Find docs on asyncio",
        "context": {"optional": "context"},
        "parent_task_id": "optional-id"
    }

    Returns:
    {
        "success": true,
        "delegation_id": "uuid",
        "result": {...},
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        from_agent = data.get('from_agent', '')
        to_agent = data.get('to_agent', '')
        task = data.get('task', '')
        context = data.get('context')
        parent_task_id = data.get('parent_task_id')

        if not all([from_agent, to_agent, task]):
            return jsonify({
                'error': 'from_agent, to_agent, and task are required',
                'status': 'error'
            }), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.delegate_to_agent(
                from_agent, to_agent, task, context, parent_task_id
            ))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Delegation system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/delegation/collaborate', methods=['POST'])
def api_collaborate():
    """
    Have multiple agents collaborate on a task.

    Request body:
    {
        "agents": ["reasoner", "researcher", "coder"],
        "task": "Design and implement API",
        "session_id": "optional-session-id",
        "coordinator": "reasoner"
    }

    Returns:
    {
        "success": true,
        "final_result": "...",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        agents = data.get('agents', [])
        task = data.get('task', '')
        session_id = data.get('session_id', str(uuid.uuid4()))
        coordinator = data.get('coordinator', 'reasoner')

        if not agents or not task:
            return jsonify({
                'error': 'agents and task are required',
                'status': 'error'
            }), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.collaborate_agents(
                agents, task, session_id, coordinator
            ))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Collaboration system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/sandbox/execute', methods=['POST'])
def api_sandbox_execute():
    """
    Execute code in a safe sandbox environment.

    Request body:
    {
        "code": "print('hello')",
        "language": "python|javascript|shell",
        "timeout": 30
    }

    Returns:
    {
        "success": true,
        "output": "hello",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        code = data.get('code', '')
        language = data.get('language', 'python')
        timeout = data.get('timeout', 30)

        if not code:
            return jsonify({'error': 'No code provided', 'status': 'error'}), 400

        try:
            from agent_manager import agent_manager
            import asyncio

            result = asyncio.run(agent_manager.execute_code_safely(
                code, language, timeout
            ))

            return jsonify({
                **result,
                'status': 'success' if result.get('success') else 'error'
            }), 200

        except ImportError as e:
            return jsonify({
                'error': 'Sandbox system not available',
                'status': 'error'
            }), 503

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/metrics/agent/<agent_type>', methods=['GET'])
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
            from agent_manager import agent_manager

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

@app.route('/api/metrics/report', methods=['GET'])
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
            from agent_manager import agent_manager

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

@app.route('/api/session/<session_id>', methods=['GET'])
def api_get_session(session_id):
    """Get session information"""
    try:
        from conversation_memory import conversation_memory

        summary = conversation_memory.get_session_summary(session_id)
        if not summary:
            return jsonify({'error': 'Session not found', 'status': 'error'}), 404

        return jsonify({
            'summary': summary,
            'status': 'success'
        }), 200

    except ImportError as e:
        return jsonify({'error': 'Conversation memory not available', 'status': 'error'}), 503
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/session/<session_id>/history', methods=['GET'])
def api_get_session_history(session_id):
    """Get conversation history for a session"""
    try:
        from conversation_memory import conversation_memory

        limit = request.args.get('limit', type=int)
        history = conversation_memory.get_conversation_history(session_id, limit=limit)

        if history is None:
            return jsonify({'error': 'Session not found', 'status': 'error'}), 404

        return jsonify({
            'history': history,
            'count': len(history),
            'status': 'success'
        }), 200

    except ImportError as e:
        return jsonify({'error': 'Conversation memory not available', 'status': 'error'}), 503
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run PhoneScan API server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Run Flask in debug mode')
    args = parser.parse_args()

    print("=" * 50)
    print("PhoneScan API Server")
    print("=" * 50)
    print(f"Running on: http://{args.host}:{args.port}")
    print("Endpoint: POST /api/phonescan")
    print("Health check: GET /health")
    print("=" * 50)
    app.run(host=args.host, port=args.port, debug=args.debug)
