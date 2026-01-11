#!/usr/bin/env python3
"""
Divine Workspace Dashboard
Web-based control panel for planning, building, and debugging
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import subprocess
import os
from pathlib import Path
import json

app = Flask(__name__)
CORS(app)

WORKSPACE = Path("/home/gh0st/dvn/divine-workspace")

@app.route("/")
def index():
    """VS Code-like IDE"""
    return render_template("vscode.html")

@app.route("/builder")
def visual_builder():
    """Visual Web Page Builder IDE - Full Featured"""
    return render_template("ide-full.html")

@app.route("/classic")
def classic_dashboard():
    """Classic dashboard page"""
    return render_template("dashboard.html")

@app.route("/api/health")
def health():
    """Get health status of all services"""
    status = {
        "pkn": check_service_running("8010"),
        "code_academy": check_service_running("8011"),
        "mobile_pkn": check_service_running("8012"),
        "tools": {
            "node": check_command("node --version"),
            "pnpm": check_command("pnpm --version"),
            "python": check_command("python3 --version"),
            "just": check_command("just --version"),
        }
    }
    return jsonify(status)

@app.route("/api/check-imports")
def run_check_imports():
    """Run import checker"""
    try:
        result = subprocess.run(
            ["python3", "scripts/check-imports.py"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse output to extract errors/warnings
        output = result.stdout + result.stderr
        errors = output.count("❌ ERRORS")
        warnings = output.count("⚠️  WARNINGS")

        return jsonify({
            "success": result.returncode == 0,
            "output": output,
            "errors": errors,
            "warnings": warnings
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/fix-imports", methods=["POST"])
def run_fix_imports():
    """Run import fixer"""
    try:
        result = subprocess.run(
            ["python3", "scripts/fix-imports.py"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout + result.stderr
        fixes = output.count("✅ Applied")

        return jsonify({
            "success": True,
            "output": output,
            "fixes": fixes
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ci", methods=["POST"])
def run_ci():
    """Run full CI pipeline"""
    try:
        result = subprocess.run(
            ["just", "ci"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=300
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/start/<service>", methods=["POST"])
def start_service(service):
    """Start a service"""
    try:
        if service == "pkn":
            subprocess.Popen(
                ["just", "dev-app", "pkn"],
                cwd=WORKSPACE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        elif service == "code-academy":
            subprocess.Popen(
                ["just", "dev-app", "code-academy"],
                cwd=WORKSPACE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        elif service == "pkn-mobile":
            subprocess.Popen(
                ["just", "dev-app", "pkn-mobile"],
                cwd=WORKSPACE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

        return jsonify({"success": True, "message": f"Starting {service}..."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/stop/<service>", methods=["POST"])
def stop_service(service):
    """Stop a service"""
    try:
        ports = {"pkn": "8010", "code-academy": "8011", "pkn-mobile": "8012"}
        if service in ports:
            subprocess.run(["pkill", "-f", f"port {ports[service]}"])

        return jsonify({"success": True, "message": f"Stopped {service}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/build/<app>", methods=["POST"])
def build_app(app):
    """Build specific app"""
    try:
        result = subprocess.run(
            ["just", "build-app", app],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=300
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/test/<app>", methods=["POST"])
def test_app(app):
    """Run tests for specific app"""
    try:
        result = subprocess.run(
            ["just", "test-app", app],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=300
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deps/install", methods=["POST"])
def install_deps():
    """Install all dependencies"""
    try:
        result = subprocess.run(
            ["pnpm", "install"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=600
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deps/update", methods=["POST"])
def update_deps():
    """Update all dependencies"""
    try:
        result = subprocess.run(
            ["pnpm", "update"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=600
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/clean", methods=["POST"])
def clean_build():
    """Clean build artifacts"""
    try:
        result = subprocess.run(
            ["just", "clean"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=60
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def check_service_running(port):
    """Check if service is running on port"""
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}"],
            capture_output=True,
            text=True
        )
        return "LISTEN" in result.stdout
    except:
        return False

def check_command(cmd):
    """Check if command exists"""
    try:
        subprocess.run(cmd.split(), capture_output=True, timeout=5)
        return True
    except:
        return False

@app.route("/api/files/tree")
def get_file_tree():
    """Get file tree for project"""
    try:
        project = request.args.get('project', 'pkn')
        project_path = WORKSPACE / 'apps' / project

        def build_tree(path, max_depth=3, current_depth=0):
            if current_depth > max_depth:
                return None

            items = []
            try:
                for item in sorted(path.iterdir()):
                    # Skip hidden, node_modules, venv, etc
                    if item.name.startswith('.') or item.name in ['node_modules', '__pycache__', '.venv', 'dist', 'build']:
                        continue

                    if item.is_dir():
                        children = build_tree(item, max_depth, current_depth + 1)
                        items.append({
                            'name': item.name,
                            'type': 'directory',
                            'path': str(item.relative_to(WORKSPACE)),
                            'children': children or []
                        })
                    else:
                        items.append({
                            'name': item.name,
                            'type': 'file',
                            'path': str(item.relative_to(WORKSPACE))
                        })
            except PermissionError:
                pass

            return items

        tree = build_tree(project_path)
        return jsonify({"success": True, "tree": tree})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/files/read")
def read_file():
    """Read file content"""
    try:
        file_path = request.args.get('path')
        full_path = WORKSPACE / file_path

        # Security check - ensure path is within workspace
        if not str(full_path.resolve()).startswith(str(WORKSPACE.resolve())):
            return jsonify({"success": False, "error": "Access denied"}), 403

        content = full_path.read_text()
        return jsonify({"success": True, "content": content, "path": file_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/files/write", methods=["POST"])
def write_file():
    """Write file content"""
    try:
        data = request.json
        file_path = data.get('path')
        content = data.get('content')

        full_path = WORKSPACE / file_path

        # Security check
        if not str(full_path.resolve()).startswith(str(WORKSPACE.resolve())):
            return jsonify({"success": False, "error": "Access denied"}), 403

        full_path.write_text(content)
        return jsonify({"success": True, "message": f"Saved {file_path}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/git/status")
def git_status():
    """Get git status"""
    try:
        result = subprocess.run(
            ["git", "status", "--short"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=10
        )

        return jsonify({
            "success": True,
            "status": result.stdout,
            "clean": len(result.stdout.strip()) == 0
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/git/diff")
def git_diff():
    """Get git diff"""
    try:
        file_path = request.args.get('path', '')
        cmd = ["git", "diff"]
        if file_path:
            cmd.append(file_path)

        result = subprocess.run(
            cmd,
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=10
        )

        return jsonify({"success": True, "diff": result.stdout})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/git/commit", methods=["POST"])
def git_commit():
    """Create git commit"""
    try:
        data = request.json
        message = data.get('message')

        # Add all changes
        subprocess.run(["git", "add", "-A"], cwd=WORKSPACE, timeout=10)

        # Commit
        result = subprocess.run(
            ["git", "commit", "-m", message],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=30
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/git/push", methods=["POST"])
def git_push():
    """Git push"""
    try:
        result = subprocess.run(
            ["git", "push"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=60
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/search")
def search_files():
    """Search for text in files"""
    try:
        query = request.args.get('query')
        project = request.args.get('project', 'pkn')
        project_path = WORKSPACE / 'apps' / project

        result = subprocess.run(
            ["grep", "-r", "-n", "-i", query, str(project_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse grep output
        matches = []
        for line in result.stdout.split('\n'):
            if line:
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    matches.append({
                        'file': parts[0].replace(str(project_path) + '/', ''),
                        'line': parts[1],
                        'text': parts[2]
                    })

        return jsonify({"success": True, "matches": matches})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/check-file-sizes")
def check_file_sizes():
    """Check file sizes (200 line limit)"""
    try:
        result = subprocess.run(
            ["just", "check-file-sizes"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=60
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/lint")
def lint_code():
    """Lint code"""
    try:
        result = subprocess.run(
            ["just", "lint"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=120
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/format", methods=["POST"])
def format_code():
    """Format code"""
    try:
        result = subprocess.run(
            ["just", "format"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=120
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/just/<command>", methods=["POST"])
def run_just_command(command):
    """Run any just command"""
    try:
        result = subprocess.run(
            ["just", command],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=600
        )

        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("🎯 Divine Workspace Dashboard")
    print("=" * 60)
    print("📊 Dashboard: http://localhost:9000")
    print("🔧 Health API: http://localhost:9000/api/health")
    print("=" * 60)
    app.run(host="0.0.0.0", port=9000, debug=True)
