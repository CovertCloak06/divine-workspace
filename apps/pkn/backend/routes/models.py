"""
Models Routes Blueprint
Extracted from divinenode_server.py
"""
from flask import Blueprint, request, jsonify
import json
import requests
import time

from ..config.settings import OLLAMA_BASE, LOCAL_LLM_BASE, join_url

# Create blueprint
models_bp = Blueprint('models', __name__)

@models_bp.route('/api/models/ollama', methods=['GET'])
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
            url = join_url(OLLAMA_BASE, *parts)
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



@models_bp.route('/api/models/llamacpp', methods=['GET'])
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


