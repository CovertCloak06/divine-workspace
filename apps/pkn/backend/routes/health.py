"""
Health Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import requests
import time

from ..config.settings import OLLAMA_BASE, LOCAL_LLM_BASE, join_url

# Create blueprint
health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "phonescan"}), 200


# Add API-style health endpoint for clients expecting /api/health


@health_bp.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "service": "divinenode_api"}), 200


# --- Network utility endpoints (backend-powered) ---


@health_bp.route("/api/models/health", methods=["GET"])
def models_health():
    """Quick health check for configured LLM backends (Ollama and local OpenAI-compatible server)."""
    results = {}
    # Check Ollama
    try:
        ok = False
        candidate = [
            join_url(OLLAMA_BASE, "api", "models"),
            join_url(OLLAMA_BASE, "models"),
            join_url(OLLAMA_BASE, "api", "tags"),
            join_url(OLLAMA_BASE, "health"),
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
        results["ollama"] = {
            "base": OLLAMA_BASE,
            "ok": ok,
            "error": None if ok else last_err,
        }
    except Exception as e:
        results["ollama"] = {"base": OLLAMA_BASE, "ok": False, "error": str(e)}

    # Check local OpenAI-compatible LLM (llama-server / llama.cpp server)
    try:
        ok = False
        candidate = [
            join_url(LOCAL_LLM_BASE, "chat", "completions"),
            join_url(LOCAL_LLM_BASE, "v1", "chat", "completions"),
            join_url(LOCAL_LLM_BASE, ""),
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
        results["local_llm"] = {
            "base": LOCAL_LLM_BASE,
            "ok": ok,
            "error": None if ok else last_err,
        }
    except Exception as e:
        results["local_llm"] = {"base": LOCAL_LLM_BASE, "ok": False, "error": str(e)}

    return jsonify(results), 200
