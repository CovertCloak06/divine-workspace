"""
Multi_Agent Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify, current_app
import json
import time
import os
import requests
# Note: AgentManager imported lazily in functions to avoid circular imports


# Create blueprint
multi_agent_bp = Blueprint("multi_agent", __name__)


def _call_openai_cloud(message: str, api_key: str = None) -> dict:
    """Call OpenAI API directly for cloud backend"""
    api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return {"error": "No OpenAI API key configured", "status": "error"}

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": message}],
                "max_tokens": 2048,
                "temperature": 0.7
            },
            timeout=60
        )
        resp.raise_for_status()
        data = resp.json()
        response_text = data["choices"][0]["message"]["content"]
        return {
            "response": response_text,
            "agent_used": "openai_cloud",
            "agent_name": "OpenAI GPT-4o-mini",
            "status": "success"
        }
    except requests.RequestException as e:
        return {"error": f"OpenAI API error: {str(e)}", "status": "error"}


@multi_agent_bp.route("/chat", methods=["POST"])
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
        message = data.get("message", "")
        session_id = data.get("session_id")
        user_id = data.get("user_id", "default")
        backend = data.get("backend", "local")  # 'local' (llama.cpp) or 'cloud' (OpenAI)

        if not message:
            return jsonify({"error": "No message provided", "status": "error"}), 400

        current_app.logger.info(f"Backend preference: {backend}")

        # Use OpenAI cloud directly if backend='cloud'
        if backend == "cloud":
            start_time = time.time()
            result = _call_openai_cloud(message)
            execution_time = time.time() - start_time

            if result.get("status") == "error":
                return jsonify(result), 500

            return jsonify({
                "response": result["response"],
                "session_id": session_id or "cloud_session",
                "agent_used": result["agent_used"],
                "agent_name": result["agent_name"],
                "routing": {"agent": "openai_cloud", "backend": "cloud"},
                "execution_time": execution_time,
                "tools_used": [],
                "conversation_summary": {"total_messages": 1, "agents_used": ["openai_cloud"]},
                "status": "success"
            }), 200

        # Local backend - use multi-agent system
        try:
            from ..memory import conversation_memory
            from ..agents import manager as agent_manager
            import asyncio

            # Create or get session
            if not session_id or not conversation_memory.get_session(session_id):
                session_id = conversation_memory.create_session(user_id)
                current_app.logger.info(f"Created new session: {session_id}")
            else:
                current_app.logger.info(f"Using existing session: {session_id}")

            # Add user message to history
            conversation_memory.add_message(session_id, "user", message)

            # Route and execute task
            current_app.logger.debug(f"Routing task: {message[:50]}...")
            result = asyncio.run(agent_manager.execute_task(message, session_id))

            # Add assistant response to history
            if result["status"] == "success":
                conversation_memory.add_message(
                    session_id,
                    "assistant",
                    result["response"],
                    agent=result["agent_used"],
                    tools_used=result.get("tools_used", []),
                )

            # Get conversation summary for response
            summary = conversation_memory.get_session_summary(session_id)

            return jsonify(
                {
                    "response": result["response"],
                    "session_id": session_id,
                    "agent_used": result["agent_used"],
                    "agent_name": result.get("agent_name", ""),
                    "routing": result.get("routing", {}),
                    "execution_time": result["execution_time"],
                    "tools_used": result.get("tools_used", []),
                    "conversation_summary": {
                        "total_messages": summary["total_messages"],
                        "agents_used": summary["agents_used"],
                    },
                    "status": result["status"],
                }
            ), 200

        except ImportError as e:
            current_app.logger.error(f"Failed to import multi-agent system: {e}")
            return jsonify(
                {
                    "error": "Multi-agent system not available",
                    "details": str(e),
                    "status": "error",
                }
            ), 503
        except Exception as e:
            current_app.logger.error(f"Multi-agent execution error: {e}")
            return jsonify(
                {
                    "error": "Multi-agent execution failed",
                    "details": str(e),
                    "status": "error",
                }
            ), 500

    except Exception as e:
        current_app.logger.error(f"Multi-agent chat endpoint error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/chat/stream", methods=["POST"])
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
        message = data.get("message", "")
        session_id = data.get("session_id")
        user_id = data.get("user_id", "default")
        backend = data.get("backend", "local")  # 'local' (llama.cpp) or 'cloud' (OpenAI)
    except Exception as e:
        current_app.logger.error(f"Failed to parse request: {e}")
        return jsonify({"error": "Invalid request data"}), 400

    if not message:
        return jsonify({"error": "No message provided"}), 400

    current_app.logger.info(f"Streaming backend preference: {backend}")

    def generate(message, session_id, user_id, backend):
        try:
            try:
                from ..memory import conversation_memory
                from ..agents import manager as agent_manager
                import asyncio

                # Create or get session
                if not session_id or not conversation_memory.get_session(session_id):
                    session_id = conversation_memory.create_session(user_id)
                    current_app.logger.info(f"Created new session: {session_id}")
                else:
                    current_app.logger.info(f"Using existing session: {session_id}")

                # Add user message to history
                conversation_memory.add_message(session_id, "user", message)

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
                    async_gen = agent_manager.execute_task_streaming(
                        message, session_id
                    )

                    # Consume it synchronously
                    while True:
                        try:
                            # Get next event from async generator
                            event = loop.run_until_complete(async_gen.__anext__())
                            event_type = event.get("type")

                            if event_type == "start":
                                agent_used = event.get("agent")
                                # Send start event with session info
                                yield f"event: start\ndata: {json.dumps({**event, 'session_id': session_id})}\n\n"

                            elif event_type == "chunk":
                                full_response += event.get("content", "")
                                yield f"event: chunk\ndata: {json.dumps(event)}\n\n"

                            elif event_type == "done":
                                execution_time = event.get("execution_time", 0)
                                tools_used = event.get("tools_used", [])
                                agent_used = event.get("agent_used", agent_used)
                                yield f"event: done\ndata: {json.dumps(event)}\n\n"

                            elif event_type == "error":
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
                        "assistant",
                        full_response,
                        agent=agent_used,
                        tools_used=tools_used,
                    )

            except ImportError as e:
                current_app.logger.error(f"Failed to import multi-agent system: {e}")
                yield f"event: error\ndata: {json.dumps({'content': 'Multi-agent system not available'})}\n\n"
            except Exception as e:
                current_app.logger.error(f"Multi-agent streaming error: {e}")
                yield f"event: error\ndata: {json.dumps({'content': str(e)})}\n\n"

        except Exception as e:
            current_app.logger.error(f"Stream generation error: {e}")
            yield f"event: error\ndata: {json.dumps({'content': str(e)})}\n\n"

    return current_app.response_class(
        generate(message, session_id, user_id, backend),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@multi_agent_bp.route("/classify", methods=["POST"])
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
        instruction = data.get("instruction", "")

        if not instruction:
            return jsonify({"error": "No instruction provided", "status": "error"}), 400

        try:
            from ..agents import manager as agent_manager

            routing = agent_manager.route_task(instruction)

            return jsonify(
                {
                    "agent_type": routing["agent"].value,
                    "classification": {
                        "complexity": routing["classification"]["complexity"].value,
                        "confidence": routing["classification"]["confidence"],
                        "reasoning": routing["classification"]["reasoning"],
                        "requires_tools": routing["classification"]["requires_tools"],
                    },
                    "strategy": routing["strategy"],
                    "estimated_time": routing["estimated_time"],
                    "agent_config": {
                        "name": routing["agent_config"]["name"],
                        "capabilities": routing["agent_config"]["capabilities"],
                        "speed": routing["agent_config"]["speed"],
                    },
                    "status": "success",
                }
            ), 200

        except ImportError as e:
            current_app.logger.error(
                f"Failed to from ..agents import manager as agent_manager: {e}"
            )
            return jsonify(
                {"error": "Agent manager not available", "status": "error"}
            ), 503
        except Exception as e:
            current_app.logger.error(f"Task classification error: {e}")
            return jsonify({"error": str(e), "status": "error"}), 500

    except Exception as e:
        current_app.logger.error(f"Classify endpoint error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/agents", methods=["GET"])
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
        from ..agents import manager as agent_manager

        agents = agent_manager.get_available_agents()

        return jsonify(
            {"agents": agents, "count": len(agents), "status": "success"}
        ), 200

    except ImportError as e:
        return jsonify({"error": "Agent manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/vote", methods=["POST"])
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
        question = data.get("question", "")
        options = data.get("options", [])
        context = data.get("context", "")
        use_external = data.get("use_external", True)

        if not question:
            return jsonify({"error": "No question provided", "status": "error"}), 400

        if not options or len(options) < 2:
            return jsonify(
                {"error": "At least 2 options required", "status": "error"}
            ), 400

        try:
            from ..agents import manager as agent_manager
            import asyncio

            # Run voting
            result = asyncio.run(
                agent_manager.vote_on_decision(
                    question=question,
                    options=options,
                    context=context,
                    use_external=use_external,
                )
            )

            return jsonify(
                {
                    "choice": result["choice"],
                    "votes": result["votes"],
                    "reasoning": result["reasoning"],
                    "consensus": result["consensus"],
                    "final_reasoning": result["final_reasoning"],
                    "status": "success",
                }
            ), 200

        except ImportError as e:
            current_app.logger.error(
                f"Failed to from ..agents import manager as agent_manager: {e}"
            )
            return jsonify(
                {"error": "Agent manager not available", "status": "error"}
            ), 503
        except Exception as e:
            current_app.logger.error(f"Voting error: {e}")
            return jsonify({"error": str(e), "status": "error"}), 500

    except Exception as e:
        current_app.logger.error(f"Vote endpoint error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


# === WORKFLOW ENDPOINTS ===

@multi_agent_bp.route("/workflows", methods=["GET"])
def api_list_workflows():
    """
    List all available multi-agent workflows.

    Returns:
    {
        "workflows": {"workflow_name": ["agent1", "agent2", ...]},
        "status": "success"
    }
    """
    try:
        from ..agents import workflow_manager
        workflows = workflow_manager.list_workflows()
        return jsonify({
            "workflows": workflows,
            "count": len(workflows),
            "status": "success"
        }), 200
    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/workflow/start", methods=["POST"])
def api_start_workflow():
    """
    Start a multi-agent workflow.

    Request body:
    {
        "workflow": "new-feature",
        "task": "Build user authentication"
    }

    Returns:
    {
        "workflow": "new-feature",
        "task": "...",
        "current_step": 1,
        "total_steps": 4,
        "current_agent": "reasoner",
        "agent_sequence": ["reasoner", "coder", "tester", "reviewer"],
        "status": "started"
    }
    """
    try:
        data = request.get_json() or {}
        workflow_name = data.get("workflow", "")
        task = data.get("task", "")

        if not workflow_name:
            return jsonify({"error": "No workflow specified", "status": "error"}), 400
        if not task:
            return jsonify({"error": "No task specified", "status": "error"}), 400

        from ..agents import workflow_manager
        result = workflow_manager.start_workflow(workflow_name, task)

        if "error" in result:
            return jsonify(result), 400

        return jsonify(result), 200

    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        current_app.logger.error(f"Start workflow error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/workflow/step", methods=["POST"])
def api_complete_workflow_step():
    """
    Complete the current workflow step and advance to next agent.

    Request body:
    {
        "result": "Findings from current agent...",
        "agent_name": "coder"  (optional)
    }

    Returns:
    {
        "status": "advancing",
        "completed_step": 1,
        "next_step": 2,
        "next_agent": "tester",
        "context": "Context from previous agents..."
    }
    """
    try:
        data = request.get_json() or {}
        result = data.get("result", "")
        agent_name = data.get("agent_name", "")

        if not result:
            return jsonify({"error": "No result provided", "status": "error"}), 400

        from ..agents import workflow_manager
        step_result = workflow_manager.complete_step(result, agent_name)

        if "error" in step_result:
            return jsonify(step_result), 400

        return jsonify(step_result), 200

    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        current_app.logger.error(f"Complete step error: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/workflow/status", methods=["GET"])
def api_workflow_status():
    """
    Get status of the active workflow.

    Returns:
    {
        "status": "active",
        "workflow": "new-feature",
        "current_step": 2,
        "total_steps": 4,
        "current_agent": "coder"
    }
    """
    try:
        from ..agents import workflow_manager
        status = workflow_manager.get_workflow_status()
        return jsonify(status), 200
    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/workflow/cancel", methods=["POST"])
def api_cancel_workflow():
    """
    Cancel the active workflow.

    Returns:
    {
        "status": "cancelled",
        "workflow": "new-feature",
        "cancelled_at_step": 2
    }
    """
    try:
        from ..agents import workflow_manager
        result = workflow_manager.cancel_workflow()
        if "error" in result:
            return jsonify(result), 400
        return jsonify(result), 200
    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/scratchpad", methods=["GET"])
def api_read_scratchpad():
    """
    Read from the workflow scratchpad.

    Query params:
    - key: Specific entry to read (optional, omit for all)

    Returns:
    {
        "data": {...scratchpad entries...},
        "status": "success"
    }
    """
    try:
        key = request.args.get("key", "")
        from ..agents import workflow_manager
        data = workflow_manager.scratchpad.read(key)
        return jsonify({"data": data, "status": "success"}), 200
    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/scratchpad", methods=["POST"])
def api_write_scratchpad():
    """
    Write to the workflow scratchpad.

    Request body:
    {
        "key": "findings",
        "content": "Agent findings...",
        "agent": "coder"  (optional)
    }

    Returns:
    {
        "key": "findings",
        "status": "success"
    }
    """
    try:
        data = request.get_json() or {}
        key = data.get("key", "")
        content = data.get("content", "")
        agent = data.get("agent", "unknown")

        if not key or not content:
            return jsonify({"error": "key and content required", "status": "error"}), 400

        from ..agents import workflow_manager
        workflow_manager.scratchpad.write(key, content, agent)
        return jsonify({"key": key, "status": "success"}), 200
    except ImportError:
        return jsonify({"error": "Workflow manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


# ============================================================
# BACKEND SWITCHING ENDPOINTS
# Toggle between local (Ollama) and cloud (Groq) backends
# ============================================================

@multi_agent_bp.route("/backend", methods=["GET"])
def get_backend_status():
    """
    Get current backend configuration status.

    Returns:
    {
        "backend": "local" | "cloud",
        "device": "mobile" | "pc",
        "cloud_available": true | false,
        "agents_count": 39
    }
    """
    try:
        from ..agents import manager as agent_manager
        status = agent_manager.get_backend_status()
        return jsonify({**status, "status": "success"}), 200
    except ImportError:
        return jsonify({"error": "Agent manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/backend", methods=["POST"])
def set_backend():
    """
    Switch between local and cloud backend.

    Request body:
    {
        "backend": "local" | "cloud"
    }

    Returns:
    {
        "success": true,
        "backend": "cloud",
        "device": "pc",
        "agents_count": 39,
        "cloud_available": true
    }
    """
    try:
        data = request.get_json() or {}
        backend = data.get("backend", "local")

        if backend not in ["local", "cloud"]:
            return jsonify({
                "error": "Invalid backend. Use 'local' or 'cloud'",
                "status": "error"
            }), 400

        from ..agents import manager as agent_manager
        result = agent_manager.set_backend(backend)
        return jsonify({**result, "status": "success" if result.get("success") else "error"}), 200
    except ImportError:
        return jsonify({"error": "Agent manager not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/models/recommended", methods=["GET"])
def get_recommended_models():
    """
    Get recommended models to pull for current device.

    Returns:
    {
        "device": "mobile" | "pc",
        "models": {
            "coder": {"model": "...", "name": "...", "description": "..."},
            ...
        },
        "pull_commands": ["ollama pull model1", ...]
    }
    """
    try:
        from ..config.model_config import (
            DeviceType, get_all_models_for_device, get_recommended_pulls
        )
        from ..agents import manager as agent_manager

        device = agent_manager.device_type
        models = get_all_models_for_device(device)
        pulls = get_recommended_pulls(device)

        return jsonify({
            "device": device.value,
            "models": models,
            "pull_commands": pulls,
            "status": "success"
        }), 200
    except ImportError as e:
        return jsonify({"error": f"Config not available: {e}", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@multi_agent_bp.route("/cloud/status", methods=["GET"])
def get_cloud_status():
    """
    Check which cloud providers are available.

    Returns:
    {
        "groq": true,
        "openai": false,
        "anthropic": false
    }
    """
    try:
        from ..config.model_config import get_cloud_status
        status = get_cloud_status()
        return jsonify({**status, "status": "success"}), 200
    except ImportError:
        return jsonify({"error": "Config not available", "status": "error"}), 503
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500
