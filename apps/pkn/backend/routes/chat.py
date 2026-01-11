"""
from ..config.settings import OLLAMA_BASE, LOCAL_LLM_BASE, join_url
Chat Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify, current_app
import json
import uuid
import requests
import time


# Create blueprint
chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/api/chat", methods=["POST"])
def api_chat():
    try:
        data = request.get_json() or {}
        model_id = data.get("modelId", "")
        messages = data.get("messages", [])

        # Backwards compatibility: accept 'local' shorthand.
        if model_id == "local":
            current_app.logger.debug(
                'Normalized legacy modelId "local" to llamacpp:local'
            )
            model_id = "llamacpp:local"

        msg_count = len(messages) if isinstance(messages, list) else "?"
        current_app.logger.debug("api_chat request: model_id=%s", model_id)
        current_app.logger.debug("api_chat messages_count=%s", msg_count)

        if not model_id:
            return jsonify({"error": "No modelId provided"}), 400

        if not isinstance(messages, list) or len(messages) == 0:
            return jsonify({"error": "No messages provided"}), 400

        # Expect ids like "ollama:mannix/llama3.1-8b-lexi:q4_0"
        if model_id.startswith("ollama:"):
            ollama_model = model_id.replace("ollama:", "", 1)
            ollama_messages = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                ollama_messages.append({"role": role, "content": content})
            try:
                # Try a couple of possible Ollama chat endpoints (base may already include /v1)
                candidate_chat_paths = [
                    ("api", "chat"),
                    ("chat",),
                    ("v1", "chat"),
                ]
                last_exc = None
                for parts in candidate_chat_paths:
                    url = join_url(OLLAMA_BASE, *parts)
                    try:
                        current_app.logger.debug(
                            "Attempting Ollama chat POST to %s (model=%s)",
                            url,
                            ollama_model,
                        )
                        resp = requests.post(
                            url,
                            json={
                                "model": ollama_model,
                                "stream": False,
                                "messages": ollama_messages,
                            },
                            timeout=600,
                        )
                        current_app.logger.debug(
                            "Ollama response from %s: status=%s",
                            url,
                            getattr(resp, "status_code", None),
                        )
                        resp.raise_for_status()
                        # Be tolerant of non-JSON responses (some Ollama setups may stream or return plain text)
                        try:
                            return jsonify(resp.json()), 200
                        except ValueError:
                            # Non-JSON body — return as text payload for debugging/client handling
                            return jsonify({"text": resp.text}), 200
                    except requests.RequestException as e:
                        last_exc = e
                        # try next candidate
                # If none of the candidates worked, return the last error
                return jsonify({"error": f"Ollama request failed: {last_exc}"}), 502
            except requests.RequestException as e:
                return jsonify({"error": f"Ollama request failed: {str(e)}"}), 502
        elif (
            model_id.startswith("llamacpp:")
            or model_id.startswith("llama-server:")
            or model_id.startswith("openai:")
        ):
            # Forward to a local OpenAI-compatible Llama server (llama.cpp's server or llama-server)
            # Expect format: "llamacpp:MODEL_NAME" or "llama-server:MODEL_NAME" (MODEL_NAME optional)
            model_name = model_id.split(":", 1)[1] if ":" in model_id else ""
            payload = {
                "model": model_name or "local",
                "messages": [
                    {"role": m.get("role", "user"), "content": m.get("content", "")}
                    for m in messages
                ],
            }
            try:
                # Use normalized joining to avoid double path components
                url = join_url(LOCAL_LLM_BASE, "chat", "completions")
                current_app.logger.debug(
                    "Forwarding to local LLM at %s payload model=%s",
                    url,
                    payload.get("model"),
                )
                resp = requests.post(url, json=payload, timeout=600)
                current_app.logger.debug(
                    "Local LLM response status=%s", getattr(resp, "status_code", None)
                )
                resp.raise_for_status()
                try:
                    return jsonify(resp.json()), 200
                except ValueError:
                    return jsonify({"text": resp.text}), 200
            except requests.RequestException as e:
                return jsonify({"error": f"Local Llama request failed: {str(e)}"}), 502
        else:
            return jsonify({"error": "Unsupported provider/modelId"}), 400

    except requests.RequestException as e:
        return jsonify({"error": f"Ollama request failed: {str(e)}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@chat_bp.route("/api/agent", methods=["POST"])
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
        instruction = data.get("instruction", "")
        conversation_id = data.get("conversation_id", str(uuid.uuid4()))

        if not instruction:
            return jsonify({"error": "No instruction provided"}), 400

        current_app.logger.debug(f"Agent request: conversation_id={conversation_id}")
        current_app.logger.debug(f"Agent instruction: {instruction[:100]}...")

        # Import and run the enhanced agent
        try:
            from local_parakleon_agent import run_agent, WEB_TOOLS_AVAILABLE

            # Run the agent with the instruction
            response = run_agent(instruction)

            return jsonify(
                {
                    "response": response,
                    "web_tools_available": WEB_TOOLS_AVAILABLE,
                    "conversation_id": conversation_id,
                    "status": "success",
                }
            ), 200

        except ImportError as e:
            current_app.logger.error(f"Failed to import agent: {e}")
            return jsonify(
                {
                    "error": "Enhanced agent not available. Install langchain-openai and langchain-core.",
                    "details": str(e),
                }
            ), 503
        except Exception as e:
            current_app.logger.error(f"Agent execution failed: {e}")
            return jsonify({"error": "Agent execution failed", "details": str(e)}), 500

    except Exception as e:
        current_app.logger.error(f"Agent endpoint error: {e}")
        return jsonify({"error": str(e)}), 500


@chat_bp.route("/api/autocomplete", methods=["POST"])
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
        prefix = data.get("prefix", "")
        file_path = data.get("file_path", "")
        context_line = data.get("context_line", "")

        if not prefix:
            return jsonify({"completions": [], "status": "no_prefix"}), 200

        try:
            from ..memory import code_context

            # Get completions from code context system
            completions = code_context.get_completions(
                prefix=prefix, file_path=file_path, context_line=context_line
            )

            return jsonify(
                {"completions": completions, "prefix": prefix, "status": "success"}
            ), 200

        except ImportError as e:
            current_app.logger.error(
                f"Failed to from ..memory import code_context: {e}"
            )
            return jsonify(
                {
                    "error": "Code context system not available",
                    "completions": [],
                    "status": "error",
                }
            ), 503
        except Exception as e:
            current_app.logger.error(f"Autocomplete error: {e}")
            return jsonify({"error": str(e), "completions": [], "status": "error"}), 500

    except Exception as e:
        current_app.logger.error(f"Autocomplete endpoint error: {e}")
        return jsonify({"error": str(e), "completions": [], "status": "error"}), 500
