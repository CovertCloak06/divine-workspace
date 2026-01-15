"""
Multi_Agent Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify, current_app
import json
import time
# TODO: Update import after agent_manager is split
# from ..agents.manager import AgentManager


# Create blueprint
multi_agent_bp = Blueprint("multi_agent", __name__)


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
