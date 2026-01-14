"""
Network Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import subprocess
import socket
import json
import time


# Create blueprint
network_bp = Blueprint("network", __name__)


@network_bp.route("/dns", methods=["POST"])
def network_dns():
    try:
        data = request.get_json() or {}
        domain = data.get("domain", "")
        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        # Simple lookup using socket (returns A/AAAA depending on system resolver)
        try:
            infos = socket.getaddrinfo(domain, None)
            addrs = []
            for info in infos:
                addr = info[4][0]
                if addr not in addrs:
                    addrs.append(addr)
            return jsonify({"domain": domain, "addresses": addrs}), 200
        except Exception as e:
            return jsonify({"error": f"DNS lookup failed: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@network_bp.route("/ping", methods=["POST"])
def network_ping():
    try:
        data = request.get_json() or {}
        host = data.get("host", "")
        count = int(data.get("count", 4))
        if not host:
            return jsonify({"error": "No host provided"}), 400

        # Limit count to prevent abuse
        if count < 1 or count > 10:
            count = 4

        # Use system ping (Linux). Capture stdout.
        try:
            proc = subprocess.run(
                ["ping", "-c", str(count), host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
            out = proc.stdout.strip()
            err = proc.stderr.strip()
            status = proc.returncode
            return jsonify(
                {
                    "host": host,
                    "count": count,
                    "returncode": status,
                    "stdout": out,
                    "stderr": err,
                }
            ), 200
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Ping command timed out"}), 500
        except Exception as e:
            return jsonify({"error": f"Ping failed: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@network_bp.route("/portscan", methods=["POST"])
def network_portscan():
    try:
        data = request.get_json() or {}
        host = data.get("host", "")
        ports = data.get("ports", [])
        timeout = float(data.get("timeout", 1.0))

        if not host:
            return jsonify({"error": "No host provided"}), 400

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
                results.append({"port": p, "open": True, "rtt_ms": round(elapsed, 2)})
            except socket.timeout:
                results.append({"port": p, "open": False, "reason": "timeout"})
            except Exception as e:
                results.append({"port": p, "open": False, "reason": str(e)})
            finally:
                # Use contextlib.suppress to silence errors
                with contextlib.suppress(Exception):
                    s.close()

        return jsonify({"host": host, "results": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- OSINT endpoints ---
# Import OSINT tools
