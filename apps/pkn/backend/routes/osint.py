"""
Osint Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import time


# Create blueprint
osint_bp = Blueprint("osint", __name__)


@osint_bp.route("/api/osint/whois", methods=["POST"])
def osint_whois():
    """Perform WHOIS lookup on domain"""
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()

        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        result = osint.whois_lookup(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/dns", methods=["POST"])
def osint_dns():
    """Perform DNS lookups on domain"""
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()
        record_types = data.get("record_types", ["A", "AAAA", "MX", "TXT", "NS"])

        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        result = osint.dns_lookup(domain, record_types)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/ip-geo", methods=["POST"])
def osint_ip_geo():
    """Get IP geolocation information"""
    try:
        data = request.get_json()
        ip = data.get("ip", "").strip()

        if not ip:
            return jsonify({"error": "No IP address provided"}), 400

        result = osint.ip_geolocation(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/port-scan", methods=["POST"])
def osint_port_scan():
    """Perform basic port scan (AUTHORIZED USE ONLY)"""
    try:
        data = request.get_json()
        host = data.get("host", "").strip()
        ports = data.get("ports", [80, 443, 22, 21, 25, 3306, 5432, 8080])

        if not host:
            return jsonify({"error": "No host provided"}), 400

        result = osint.port_scan_basic(host, ports)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/email-validate", methods=["POST"])
def osint_email_validate():
    """Validate email address format and MX records"""
    try:
        data = request.get_json()
        email = data.get("email", "").strip()

        if not email:
            return jsonify({"error": "No email provided"}), 400

        result = osint.email_validate(email)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/username-search", methods=["POST"])
def osint_username_search():
    """Search for username across social platforms"""
    try:
        data = request.get_json()
        username = data.get("username", "").strip()

        if not username:
            return jsonify({"error": "No username provided"}), 400

        result = osint.username_search(username)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/web-tech", methods=["POST"])
def osint_web_tech():
    """Detect web technologies used by a website"""
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        result = osint.web_technologies(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/ssl-cert", methods=["POST"])
def osint_ssl_cert():
    """Get SSL certificate information"""
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()

        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        result = osint.ssl_certificate_info(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/wayback", methods=["POST"])
def osint_wayback():
    """Check Wayback Machine for archived versions"""
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        result = osint.wayback_check(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/subdomain-enum", methods=["POST"])
def osint_subdomain_enum():
    """Enumerate subdomains for a domain"""
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()

        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        result = osint.subdomain_enum(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/reverse-dns", methods=["POST"])
def osint_reverse_dns():
    """Perform reverse DNS lookup on IP address"""
    try:
        data = request.get_json()
        ip = data.get("ip", "").strip()

        if not ip:
            return jsonify({"error": "No IP address provided"}), 400

        result = osint.reverse_dns(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@osint_bp.route("/api/osint/phone-lookup", methods=["POST"])
def osint_phone_lookup():
    """Get phone number carrier and timezone info"""
    try:
        data = request.get_json()
        phone = data.get("phone", "").strip()

        if not phone:
            return jsonify({"error": "No phone number provided"}), 400

        result = osint.phone_number_lookup(phone)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


# --- File storage endpoints ---
