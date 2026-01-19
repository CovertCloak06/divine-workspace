#!/usr/bin/env python3
"""
Multi-Agent Coordination System
Manages and coordinates multiple specialized AI agents
ENHANCED with full tool integration and cloud/local toggle
"""

import os
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from pathlib import Path
from enum import Enum

# Import all tool modules
from ..tools import (
    code_tools,
    file_tools,
    system_tools,
    web_tools,
    memory_tools,
    osint_tools,
    scratchpad_tools,
    workflow_tools,
    git_tools,
    project_tools,
    # Security/Pentesting tools (Kali-style)
    pentest_tools,
    recon_tools,
    privesc_tools,
    network_tools,
    crypto_tools,
)
from ..tools.shadow import tools as shadow_tools

# Import advanced agent features
from ..tools.rag_tools import RAGMemory
from ..tools.planning_tools import TaskPlanner, PlanExecutor
from ..tools.delegation_tools import AgentDelegationManager
from ..tools.chain_tools import ToolChainExecutor
from ..tools.sandbox_tools import CodeSandbox
from ..tools.evaluation_tools import AgentEvaluator

# Import model configuration
from ..config.model_config import (
    BackendType,
    DeviceType,
    get_model_config,
    get_all_models_for_device,
    MOBILE_LOCAL_MODELS,
    PC_LOCAL_MODELS,
    CLOUD_MODELS,
    is_cloud_available,
)

# Import cloud providers
from ..utils.groq_cloud import groq_cloud, is_groq_available

# Import local modules
from .types import AgentType, TaskComplexity, AgentMessage
from .classifier import TaskClassifier


def detect_device_type() -> DeviceType:
    """Detect if running on mobile (Termux) or PC."""
    # Check for Termux environment
    if os.path.exists("/data/data/com.termux"):
        return DeviceType.MOBILE
    if "TERMUX_VERSION" in os.environ:
        return DeviceType.MOBILE
    if "com.termux" in os.environ.get("PREFIX", ""):
        return DeviceType.MOBILE
    return DeviceType.PC


class AgentManager:
    """
    Coordinates multiple specialized agents.
    Routes tasks to the most appropriate agent based on task type and complexity.
    Supports local (Ollama) and cloud (Groq/OpenAI) backends.
    """

    def __init__(self, project_root: str = None):
        from pathlib import Path

        # Auto-detect project root: backend/agents/manager.py -> apps/pkn/
        if project_root is None:
            project_root = Path(__file__).parent.parent.parent
        self.project_root = Path(project_root)
        self.agents = {}
        self.active_tasks = {}
        self.conversation_history = {}
        self.agent_stats = {}

        # Device and backend configuration
        self.device_type = detect_device_type()
        self.backend_mode = BackendType.LOCAL  # Default to local
        self._load_backend_preference()

        # Initialize classifier
        self.classifier = TaskClassifier()

        # Initialize available agents based on device and backend
        self._init_agents()

        # Give classifier access to agent configurations
        self.classifier.agents = self.agents

        print(f"Device: {self.device_type.value.upper()}, Backend: {self.backend_mode.value.upper()}")

        # Initialize advanced features
        try:
            from ..tools.rag_tools import RAGMemory

            self.rag_memory = RAGMemory(str(project_root))
        except ImportError:
            self.rag_memory = None

        try:
            from ..tools.planning_tools import TaskPlanner, PlanExecutor

            self.task_planner = None  # Lazy init
            self.plan_executor = PlanExecutor(self)
        except ImportError:
            self.task_planner = None
            self.plan_executor = None

        try:
            from ..tools.delegation_tools import AgentDelegationManager

            self.delegation_manager = AgentDelegationManager(self, str(project_root))
        except ImportError:
            self.delegation_manager = None

        try:
            from ..tools.chain_tools import ToolChainExecutor

            self.tool_chain_executor = ToolChainExecutor(self._get_tool_registry())
        except ImportError:
            self.tool_chain_executor = None

        try:
            from ..tools.sandbox_tools import CodeSandbox

            self.code_sandbox = CodeSandbox(str(project_root))
        except ImportError:
            self.code_sandbox = None

        try:
            from ..tools.evaluation_tools import AgentEvaluator

            self.evaluator = AgentEvaluator(str(project_root))
        except ImportError:
            self.evaluator = None

    def _load_backend_preference(self):
        """Load backend preference from environment or config file."""
        # Check environment variable first
        backend_env = os.getenv("PKN_BACKEND", "").lower()
        if backend_env == "cloud":
            self.backend_mode = BackendType.CLOUD
        elif backend_env == "local":
            self.backend_mode = BackendType.LOCAL

        # Try to load from config file
        config_file = self.project_root / "data" / "backend_config.json"
        if config_file.exists():
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                    if config.get("backend") == "cloud":
                        self.backend_mode = BackendType.CLOUD
            except Exception:
                pass

    def set_backend(self, backend: str) -> Dict[str, Any]:
        """
        Switch between local and cloud backend.

        Args:
            backend: 'local' or 'cloud'

        Returns:
            Status dict with new configuration
        """
        if backend.lower() == "cloud":
            if not is_groq_available():
                return {
                    "success": False,
                    "error": "Groq API key not configured. Get free key at https://console.groq.com",
                    "backend": self.backend_mode.value,
                }
            self.backend_mode = BackendType.CLOUD
        else:
            self.backend_mode = BackendType.LOCAL

        # Save preference
        config_file = self.project_root / "data" / "backend_config.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w") as f:
            json.dump({"backend": self.backend_mode.value}, f)

        # Reinitialize agents with new backend
        self._init_agents()
        self.classifier.agents = self.agents

        return {
            "success": True,
            "backend": self.backend_mode.value,
            "device": self.device_type.value,
            "agents_count": len(self.agents),
            "cloud_available": is_groq_available(),
        }

    def get_backend_status(self) -> Dict[str, Any]:
        """Get current backend configuration status."""
        return {
            "backend": self.backend_mode.value,
            "device": self.device_type.value,
            "cloud_available": is_groq_available(),
            "agents_count": len(self.agents),
        }

    def _init_agents(self):
        """Initialize agents based on device type and backend mode."""
        self.agents = {}
        is_cloud = self.backend_mode == BackendType.CLOUD
        is_mobile = self.device_type == DeviceType.MOBILE

        # Select model source based on backend mode
        if is_cloud:
            model_source = CLOUD_MODELS
            mode_label = "CLOUD (Groq)"
        elif is_mobile:
            model_source = MOBILE_LOCAL_MODELS
            mode_label = "MOBILE LOCAL (Ollama)"
        else:
            model_source = PC_LOCAL_MODELS
            mode_label = "PC LOCAL (Ollama)"

        # Core agents with their capabilities
        agent_capabilities = {
            "coder": ["code_writing", "debugging", "refactoring", "code_review"],
            "general": ["conversation", "simple_qa", "explanations"],
            "reasoner": ["planning", "logic", "problem_solving", "analysis"],
            "security": ["pentesting", "vulnerability_analysis", "exploit_dev", "osint"],
            "researcher": ["web_search", "documentation", "fact_checking"],
            "executor": ["command_execution", "file_operations", "system_tasks"],
            "vision": ["image_analysis", "screenshot_analysis", "ocr"],
        }

        # Map agent keys to AgentType enum
        agent_type_map = {
            "coder": AgentType.CODER,
            "general": AgentType.GENERAL,
            "reasoner": AgentType.REASONER,
            "security": AgentType.SECURITY,
            "researcher": AgentType.RESEARCHER,
            "executor": AgentType.EXECUTOR,
            "vision": AgentType.VISION,
        }

        # Initialize each core agent
        for agent_key, agent_type in agent_type_map.items():
            model_cfg = model_source.get(agent_key, model_source.get("general", {}))

            self.agents[agent_type] = {
                "name": model_cfg.get("name", f"{agent_key.title()} Agent"),
                "model": model_cfg.get("model", "ollama:mistral:latest"),
                "endpoint": "http://127.0.0.1:11434" if not is_cloud else None,
                "capabilities": agent_capabilities.get(agent_key, []),
                "speed": model_cfg.get("speed", "medium"),
                "quality": model_cfg.get("quality", "medium"),
                "tools_enabled": True,
                "uncensored": model_cfg.get("uncensored", False),
                "cloud": is_cloud,
                "provider": model_cfg.get("provider", "ollama"),
            }

        # Always add Vision Cloud agent (Groq free)
        self.agents[AgentType.VISION_CLOUD] = {
            "name": "Vision Analyst (Groq Cloud)",
            "model": "groq:llama-3.2-90b-vision-preview",
            "endpoint": None,
            "capabilities": ["image_analysis", "screenshot_analysis", "ocr", "visual_qa"],
            "speed": "fast",
            "quality": "very_high",
            "tools_enabled": False,
            "vision": True,
            "cloud": True,
            "free": True,
            "provider": "groq",
        }

        # Always add Claude Consultant (premium cloud)
        self.agents[AgentType.CONSULTANT] = {
            "name": "Claude Consultant",
            "model": "claude:claude-3-5-sonnet-20241022",
            "endpoint": None,
            "capabilities": ["high_level_decisions", "voting", "expert_advice", "complex_reasoning"],
            "speed": "medium",
            "quality": "exceptional",
            "tools_enabled": True,
            "cloud": True,
            "provider": "anthropic",
        }

        # Load specialist agents
        self._init_specialist_agents()

        print(f"✅ Initialized {len(self.agents)} agents [{mode_label}]")

    def _init_specialist_agents(self):
        """Load specialist agent configurations."""
        try:
            from .specialist_agents import get_specialist_agents
            specialists = get_specialist_agents()
            self.agents.update(specialists)
        except ImportError as e:
            print(f"⚠️ Could not load specialist agents: {e}")

    def get_tools_for_agent(self, agent_type: AgentType) -> List:
        """
        Get appropriate tools for each agent type.

        Returns list of langchain tools that the agent can use.
        """
        # All agents can use memory, scratchpad, and workflow tools
        common_tools = (
            memory_tools.TOOLS
            + scratchpad_tools.TOOLS  # Agent handoff storage
            + workflow_tools.TOOLS    # Multi-agent workflow coordination
        )

        if agent_type == AgentType.CODER:
            # Code operations + file search
            return code_tools.TOOLS + file_tools.TOOLS + common_tools

        elif agent_type == AgentType.EXECUTOR:
            # System control + file operations + git + project management
            return (
                system_tools.TOOLS
                + file_tools.TOOLS
                + git_tools.TOOLS      # Version control
                + project_tools.TOOLS  # Project management
                + common_tools
            )

        elif agent_type == AgentType.RESEARCHER:
            # Web research + OSINT + file search
            return web_tools.TOOLS + osint_tools.TOOLS + file_tools.TOOLS + common_tools

        elif agent_type == AgentType.REASONER:
            # Pure reasoning, just memory
            return common_tools

        elif agent_type == AgentType.SECURITY:
            # Security & pentesting tools: Full Kali-style toolkit
            return (
                osint_tools.TOOLS      # Port scanning, DNS, IP lookup
                + web_tools.TOOLS      # Web reconnaissance
                + system_tools.TOOLS   # System analysis, command execution
                + file_tools.TOOLS     # File operations for analysis
                + code_tools.TOOLS     # Code review for vulnerabilities
                + pentest_tools.TOOLS  # Shells, payloads, exploits
                + recon_tools.TOOLS    # Banner grab, headers, directory enum
                + privesc_tools.TOOLS  # SUID, cron, kernel exploits
                + network_tools.TOOLS  # TCP/UDP scan, traceroute, ARP
                + crypto_tools.TOOLS   # Hash crack, JWT, encoding
                + shadow_tools.TOOLS   # Shadow OSINT: username hunt, dorks, recon
                + common_tools
            )

        elif agent_type == AgentType.CONSULTANT:
            # ALL tools available (full suite)
            return (
                code_tools.TOOLS
                + file_tools.TOOLS
                + system_tools.TOOLS
                + web_tools.TOOLS
                + osint_tools.TOOLS
                + git_tools.TOOLS       # Version control
                + project_tools.TOOLS   # Project management
                + pentest_tools.TOOLS   # Shells, payloads, exploits
                + recon_tools.TOOLS     # Banner grab, headers, directory enum
                + privesc_tools.TOOLS   # SUID, cron, kernel exploits
                + network_tools.TOOLS   # TCP/UDP scan, traceroute, ARP
                + crypto_tools.TOOLS    # Hash crack, JWT, encoding
                + shadow_tools.TOOLS    # Shadow OSINT: username hunt, dorks, recon
                + common_tools
            )

        elif agent_type == AgentType.VISION:
            # Vision tasks: file reading for images, web for image URLs
            return file_tools.TOOLS + web_tools.TOOLS + common_tools

        else:  # GENERAL
            # Basic subset
            return [
                code_tools.read_file,
                file_tools.glob,
                web_tools.web_search,
            ] + common_tools

    def _get_tool_registry(self) -> Dict:
        """Get registry of available tools for tool chaining"""
        registry = {}

        # Safely add available tools
        for tool in code_tools.TOOLS:
            registry[f"code_tools.{tool.name}"] = tool

        for tool in file_tools.TOOLS:
            registry[f"file_tools.{tool.name}"] = tool

        for tool in system_tools.TOOLS:
            registry[f"system_tools.{tool.name}"] = tool

        for tool in web_tools.TOOLS:
            registry[f"web_tools.{tool.name}"] = tool

        for tool in osint_tools.TOOLS:
            registry[f"osint_tools.{tool.name}"] = tool

        for tool in memory_tools.TOOLS:
            registry[f"memory_tools.{tool.name}"] = tool

        for tool in scratchpad_tools.TOOLS:
            registry[f"scratchpad_tools.{tool.name}"] = tool

        for tool in workflow_tools.TOOLS:
            registry[f"workflow_tools.{tool.name}"] = tool

        for tool in git_tools.TOOLS:
            registry[f"git_tools.{tool.name}"] = tool

        for tool in project_tools.TOOLS:
            registry[f"project_tools.{tool.name}"] = tool

        # Security/Pentesting tools (Kali-style)
        for tool in pentest_tools.TOOLS:
            registry[f"pentest_tools.{tool.name}"] = tool

        for tool in recon_tools.TOOLS:
            registry[f"recon_tools.{tool.name}"] = tool

        for tool in privesc_tools.TOOLS:
            registry[f"privesc_tools.{tool.name}"] = tool

        for tool in network_tools.TOOLS:
            registry[f"network_tools.{tool.name}"] = tool

        for tool in crypto_tools.TOOLS:
            registry[f"crypto_tools.{tool.name}"] = tool

        # Shadow OSINT suite
        for tool in shadow_tools.TOOLS:
            registry[f"shadow_tools.{tool.name}"] = tool

        return registry

    def _make_json_safe(self, data):
        """Convert enums to their values for JSON serialization"""
        if isinstance(data, dict):
            return {k: self._make_json_safe(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._make_json_safe(item) for item in data]
        elif isinstance(data, (AgentType, TaskComplexity)):
            return data.value
        else:
            return data

    def classify_task(self, instruction: str) -> Dict[str, Any]:
        """Classify a task (delegates to classifier)"""
        return self.classifier.classify(instruction)

    def route_task(
        self, instruction: str, conversation_id: str = None
    ) -> Dict[str, Any]:
        """Route a task to appropriate agent (delegates to classifier)"""
        return self.classifier.route(instruction, conversation_id)

    async def execute_task(
        self, instruction: str, conversation_id: str = None
    ) -> Dict[str, Any]:
        """
        Execute a task using the appropriate agent(s).

        Args:
            instruction: The task to perform
            conversation_id: Optional conversation ID for context

        Returns:
            {
                'response': str,
                'agent_used': str,
                'execution_time': float,
                'tools_used': list,
                'status': 'success' | 'error'
            }
        """
        task_id = str(uuid.uuid4())
        start_time = time.time()

        # Route the task
        routing = self.route_task(instruction, conversation_id)
        agent_type = routing["agent"]
        agent_config = routing["agent_config"]

        # Track active task
        self.active_tasks[task_id] = {
            "instruction": instruction,
            "agent_type": agent_type.value,
            "status": "running",
            "start_time": start_time,
        }

        try:
            # Check if using cloud backend (Groq)
            if self.backend_mode == BackendType.CLOUD and agent_config.get("provider") == "groq":
                # Use Groq cloud for fast execution
                system_prompts = {
                    AgentType.CODER: "You are an expert code writer. Write clean, efficient code. Always respond in English.",
                    AgentType.GENERAL: "You are a helpful AI assistant. Always respond in English.",
                    AgentType.REASONER: "You are a reasoning expert. Think step by step. Always respond in English.",
                    AgentType.SECURITY: "You are a cybersecurity expert. Provide detailed security analysis. Always respond in English.",
                    AgentType.RESEARCHER: "You are a research expert. Provide accurate, well-sourced information. Always respond in English.",
                    AgentType.EXECUTOR: "You are a system administration expert. Provide clear commands and explanations. Always respond in English.",
                }
                system_prompt = system_prompts.get(agent_type, "You are a helpful AI assistant. Always respond in English.")

                result = groq_cloud.chat(
                    message=instruction,
                    system_prompt=system_prompt,
                    temperature=0.7,
                    max_tokens=2048,
                )

                if result["success"]:
                    response = result["response"]
                    tools_used = ["groq_cloud"]
                else:
                    # Fallback to local if cloud fails
                    response = f"⚠️ Cloud error: {result.get('error', 'Unknown')}\nFalling back to local..."
                    response = await self._call_chat_api(
                        instruction,
                        "http://127.0.0.1:11434",
                        "ollama:mistral:latest",
                        system_prompt,
                    )
                    tools_used = ["cloud_fallback_to_local"]

            # Execute based on agent type and tool requirements
            elif agent_config["model"] == "groq_vision" or agent_config.get("model", "").startswith("groq:"):
                # Use Groq cloud vision API
                from groq_vision import groq_vision

                if groq_vision.is_available():
                    # Groq vision with images
                    response_data = groq_vision.analyze_text(instruction)
                    if response_data["success"]:
                        response = response_data["response"]
                        tools_used = ["groq_cloud_vision"]
                    else:
                        response = f"⚠️ Groq Vision error: {response_data['error']}\nFalling back to local vision agent."
                        # Fallback to local vision
                        fallback_config = self.agents[AgentType.VISION]
                        response = await self._call_chat_api(
                            instruction,
                            fallback_config["endpoint"],
                            fallback_config["model"],
                            "You are a vision analyst. IMPORTANT: Always respond in English only.",
                        )
                        tools_used = ["fallback_to_local_vision"]
                else:
                    response = "⚠️ Groq API not configured. Get a free API key at https://console.groq.com\nSet GROQ_API_KEY in .env file.\n\nFalling back to local vision agent."
                    # Fallback to local vision
                    fallback_config = self.agents[AgentType.VISION]
                    response = await self._call_chat_api(
                        instruction,
                        fallback_config["endpoint"],
                        fallback_config["model"],
                        "You are a vision analyst. IMPORTANT: Always respond in English only.",
                    )
                    tools_used = ["fallback_to_local_vision"]
            elif agent_config["model"] == "claude_api":
                # Use Claude API for CONSULTANT agent (with all tools!)
                from claude_api import claude_api

                if claude_api.is_available():
                    # Claude API with tools
                    response, tools_used = await self._execute_claude_with_tools(
                        instruction, agent_type
                    )
                else:
                    # Fallback if Claude API not available
                    response = "⚠️ Claude API unavailable (set ANTHROPIC_API_KEY env variable)\nFalling back to local reasoning agent."
                    # Fallback to reasoner agent with tools
                    fallback_config = self.agents[AgentType.REASONER]
                    response, tools_used = await self._execute_with_tools(
                        instruction,
                        AgentType.REASONER,
                        fallback_config["endpoint"],
                        fallback_config["model"],
                    )
                    tools_used = ["fallback_to_reasoner"] + tools_used
            elif agent_config.get("tools_enabled", False) and agent_type in [
                AgentType.CODER,
                AgentType.EXECUTOR,
                AgentType.RESEARCHER,
                AgentType.REASONER,
                AgentType.GENERAL,
                AgentType.SECURITY,
                AgentType.VISION,
            ]:
                # Use tool-enhanced execution
                response, tools_used = await self._execute_with_tools(
                    instruction,
                    agent_type,
                    agent_config["endpoint"],
                    agent_config["model"],
                )
            elif agent_config["model"] == "enhanced_agent":
                # Fallback to local_parakleon_agent for backwards compatibility
                from local_parakleon_agent import run_agent

                response = run_agent(instruction)
                tools_used = ["enhanced_agent_tools"]
            elif agent_config["model"] == "external_api":
                # Legacy external LLM support (kept for backwards compatibility)
                from external_llm import external_llm

                result = await external_llm.query_best_available(
                    prompt=instruction,
                    system_prompt="You are an expert consultant providing thoughtful, well-reasoned advice.",
                )

                if result.get("available"):
                    response = result["response"]
                    tools_used = [f"external_llm_{result['provider']}"]
                else:
                    # Fallback if external LLM not available
                    response = f"External consultant unavailable: {result.get('error', 'Unknown error')}\nFalling back to local reasoning agent."
                    fallback_config = self.agents[AgentType.REASONER]
                    fallback_system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only."
                    response = await self._call_chat_api(
                        instruction,
                        fallback_config["endpoint"],
                        fallback_config["model"],
                        fallback_system_prompt,
                    )
                    tools_used = ["fallback_to_reasoner"]
            else:
                # Use regular chat completion with agent-specific system prompt
                # Build system prompt for this agent type
                if agent_type == AgentType.VISION:
                    agent_system_prompt = "You are a vision and image analysis expert. IMPORTANT: Always respond in English only. Never use Chinese or any other language. Analyze images, screenshots, UI elements, and visual content clearly."
                elif agent_type == AgentType.GENERAL:
                    agent_system_prompt = "You are a helpful general assistant. IMPORTANT: Always respond in English only."
                elif agent_type == AgentType.CODER:
                    agent_system_prompt = "You are an expert code writer. IMPORTANT: Always respond in English only."
                elif agent_type == AgentType.REASONER:
                    agent_system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only."
                else:
                    agent_system_prompt = None  # Use default English enforcement

                response = await self._call_chat_api(
                    instruction,
                    agent_config["endpoint"],
                    agent_config["model"],
                    agent_system_prompt,
                )
                tools_used = []

            execution_time = time.time() - start_time

            # Update task status
            self.active_tasks[task_id]["status"] = "completed"
            self.active_tasks[task_id]["execution_time"] = execution_time

            # Update agent stats
            if agent_type.value not in self.agent_stats:
                self.agent_stats[agent_type.value] = {
                    "tasks_completed": 0,
                    "total_time": 0,
                    "avg_time": 0,
                }

            stats = self.agent_stats[agent_type.value]
            stats["tasks_completed"] += 1
            stats["total_time"] += execution_time
            stats["avg_time"] = stats["total_time"] / stats["tasks_completed"]

            # Log execution to evaluator
            try:
                self.evaluator.log_execution(
                    agent_type=agent_type.value,
                    task=instruction[:200],  # Truncate long tasks
                    response=response[:500],  # Truncate long responses
                    duration_ms=int(execution_time * 1000),
                    success=True,
                    tools_used=tools_used,
                    session_id=conversation_id or task_id,
                )
            except Exception as e:
                # Don't fail the task if logging fails
                print(f"Warning: Failed to log execution: {e}")

            return {
                "response": response,
                "agent_used": agent_type.value,
                "agent_name": agent_config["name"],
                "execution_time": execution_time,
                "tools_used": tools_used,
                "status": "success",
                "task_id": task_id,
                "routing": self._make_json_safe(
                    routing
                ),  # Convert enums to strings for JSON
            }

        except Exception as e:
            execution_time = time.time() - start_time
            self.active_tasks[task_id]["status"] = "error"

            # Log failure to evaluator
            try:
                self.evaluator.log_execution(
                    agent_type=agent_type.value,
                    task=instruction[:200],
                    response="",
                    duration_ms=int(execution_time * 1000),
                    success=False,
                    error=str(e),
                    session_id=conversation_id or task_id,
                )
            except Exception as eval_error:
                print(f"Warning: Failed to log error: {eval_error}")

            return {
                "response": f"Error executing task: {str(e)}",
                "agent_used": agent_type.value,
                "execution_time": execution_time,
                "tools_used": [],
                "status": "error",
                "error": str(e),
                "task_id": task_id,
            }

    async def execute_task_streaming(
        self, instruction: str, conversation_id: str = None
    ):
        """
        Execute a task with streaming support.
        Yields chunks as they arrive from the LLM.

        Args:
            instruction: The task to perform
            conversation_id: Optional conversation ID for context

        Yields:
            dict: Event dictionaries with various types:
                - {'type': 'start', 'agent': str, 'routing': dict}
                - {'type': 'chunk', 'content': str}
                - {'type': 'done', 'execution_time': float, 'tools_used': list}
                - {'type': 'error', 'content': str}
        """
        task_id = str(uuid.uuid4())
        start_time = time.time()

        try:
            # Route the task
            routing = self.route_task(instruction, conversation_id)
            agent_type = routing["agent"]
            agent_config = routing["agent_config"]

            # Track active task
            self.active_tasks[task_id] = {
                "instruction": instruction,
                "agent_type": agent_type.value,
                "status": "running",
                "start_time": start_time,
            }

            # Send start event with routing info
            yield {
                "type": "start",
                "agent": agent_type.value,
                "agent_name": agent_config["name"],
                "routing": self._make_json_safe(routing),
                "task_id": task_id,
            }

            full_response = ""

            # Stream response based on agent type
            if agent_config["model"] == "enhanced_agent":
                # Enhanced agent doesn't support streaming yet, use regular execution
                from local_parakleon_agent import run_agent

                response = run_agent(instruction)
                yield {"type": "chunk", "content": response}
                full_response = response
                tools_used = ["enhanced_agent_tools"]

            elif agent_config["model"] == "external_api":
                # External LLM - use their streaming if available
                from external_llm import external_llm

                result = await external_llm.query_best_available(
                    prompt=instruction,
                    system_prompt="You are an expert consultant providing thoughtful, well-reasoned advice.",
                )
                if result.get("available"):
                    # External APIs typically return complete responses
                    # Send as single chunk for now
                    yield {"type": "chunk", "content": result["response"]}
                    full_response = result["response"]
                    tools_used = [f"external_llm_{result['provider']}"]
                else:
                    raise Exception(result.get("error", "External LLM unavailable"))

            else:
                # Use streaming chat API
                tools_used = []
                async for chunk in self._call_chat_api_streaming(
                    instruction, agent_config["endpoint"], agent_config["model"]
                ):
                    if chunk["type"] == "chunk":
                        full_response += chunk["content"]
                        yield chunk
                    elif chunk["type"] == "error":
                        raise Exception(chunk["content"])
                    elif chunk["type"] == "done":
                        break

            execution_time = time.time() - start_time

            # Update task status
            self.active_tasks[task_id]["status"] = "completed"
            self.active_tasks[task_id]["execution_time"] = execution_time

            # Update agent stats
            if agent_type.value not in self.agent_stats:
                self.agent_stats[agent_type.value] = {
                    "tasks_completed": 0,
                    "total_time": 0,
                    "avg_time": 0,
                }

            stats = self.agent_stats[agent_type.value]
            stats["tasks_completed"] += 1
            stats["total_time"] += execution_time
            stats["avg_time"] = stats["total_time"] / stats["tasks_completed"]

            # Send completion event
            yield {
                "type": "done",
                "execution_time": execution_time,
                "tools_used": tools_used,
                "response": full_response,
                "agent_used": agent_type.value,
                "agent_name": agent_config["name"],
            }

        except Exception as e:
            execution_time = time.time() - start_time
            self.active_tasks[task_id]["status"] = "error"
            yield {"type": "error", "content": str(e), "execution_time": execution_time}

    async def vote_on_decision(
        self,
        question: str,
        options: List[str],
        context: str = "",
        use_external: bool = True,
    ) -> Dict[str, Any]:
        """
        Voting mechanism for complex decisions.
        Queries multiple agents and/or external LLMs for consensus.

        Args:
            question: The decision question
            options: List of possible choices
            context: Additional context
            use_external: Whether to include external LLM (Claude/GPT) in voting

        Returns:
            {
                'choice': str,
                'votes': Dict[str, str],  # agent -> choice
                'reasoning': Dict[str, str],  # agent -> reason
                'consensus': float,  # 0-1, how much agreement
                'final_reasoning': str
            }
        """
        votes = {}
        reasoning = {}

        # Format the question
        prompt = f"{question}\n\nContext: {context}\n\nOptions:\n"
        for i, opt in enumerate(options):
            prompt += f"{i + 1}. {opt}\n"
        prompt += "\nChoose the best option and explain why."

        # Vote with external LLM if available and requested
        if use_external:
            try:
                from external_llm import external_llm

                if external_llm.is_available():
                    result = await external_llm.vote_on_decision(
                        question, options, context
                    )
                    votes["consultant"] = result["choice"]
                    reasoning["consultant"] = result["reasoning"]
            except Exception as e:
                print(f"External LLM vote failed: {e}")

        # Vote with local reasoner agent
        try:
            reasoner_config = self.agents[AgentType.REASONER]
            reasoner_system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only. Analyze options carefully and provide clear reasoning."
            reasoner_response = await self._call_chat_api(
                prompt,
                reasoner_config["endpoint"],
                reasoner_config["model"],
                reasoner_system_prompt,
            )

            # Parse response to find chosen option
            chosen = self._parse_choice_from_response(reasoner_response, options)
            votes["reasoner"] = chosen
            reasoning["reasoner"] = reasoner_response
        except Exception as e:
            print(f"Reasoner vote failed: {e}")

        # Tally votes
        if not votes:
            return {
                "choice": options[0],
                "votes": {},
                "reasoning": {},
                "consensus": 0.0,
                "final_reasoning": "No agents available for voting, defaulting to first option",
            }

        # Count votes for each option
        vote_counts = {opt: 0 for opt in options}
        for agent, choice in votes.items():
            if choice in vote_counts:
                vote_counts[choice] += 1

        # Get winner
        winner = max(vote_counts, key=vote_counts.get)
        consensus = vote_counts[winner] / len(votes)

        # Combine reasoning
        final_reasoning = "\n\n".join(
            [
                f"**{agent.upper()}**: {reason[:200]}..."
                for agent, reason in reasoning.items()
            ]
        )

        return {
            "choice": winner,
            "votes": votes,
            "reasoning": reasoning,
            "consensus": consensus,
            "final_reasoning": final_reasoning,
        }

    def _parse_choice_from_response(self, response: str, options: List[str]) -> str:
        """Extract the chosen option from an agent's response"""
        response_lower = response.lower()

        # Try to find exact matches
        for opt in options:
            if opt.lower() in response_lower:
                return opt

        # Try to find numbered choices (1., 2., etc.)
        for i, opt in enumerate(options):
            if f"{i + 1}." in response or f"option {i + 1}" in response_lower:
                return opt

        # Default to first option if can't parse
        return options[0]

    async def delegate_to_agent(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
        context: Optional[Dict] = None,
        parent_task_id: str = None,
    ) -> Dict[str, Any]:
        """Delegate a task from one agent to another"""
        try:
            from ..tools.delegation_tools import DelegationPriority

            delegation = self.delegation_manager.delegate_task(
                from_agent=from_agent,
                to_agent=to_agent,
                task=task,
                context=context or {},
                parent_task_id=parent_task_id or str(uuid.uuid4()),
                priority=DelegationPriority.NORMAL,
            )

            # Execute the delegation
            result = self.delegation_manager.execute_delegation(
                delegation.id, parent_task_id or str(uuid.uuid4())
            )

            return {
                "success": result.get("success", True),
                "delegation_id": delegation.id,
                **result,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def collaborate_agents(
        self,
        agents: List[str],
        task: str,
        session_id: str,
        coordinator: str = "reasoner",
    ) -> Dict[str, Any]:
        """Have multiple agents collaborate on a task"""
        try:
            result = self.delegation_manager.collaborate(
                agents=agents, task=task, session_id=session_id, coordinator=coordinator
            )

            return {"success": result.get("success", True), **result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_agent_metrics(self, agent_type: str, days: int = 30) -> Dict[str, Any]:
        """Get performance metrics for a specific agent"""
        try:
            metrics = self.evaluator.get_agent_metrics(agent_type, days=days)
            return {"success": True, **metrics}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_performance_report(self, days: int = 7) -> str:
        """Get a comprehensive performance report for all agents"""
        try:
            report = self.evaluator.get_summary_report(days=days)
            return report
        except Exception as e:
            return f"Error generating report: {str(e)}"

    async def _call_chat_api(
        self,
        instruction: str,
        endpoint: str,
        model: str,
        system_prompt: str = None,
    ) -> str:
        """
        Call a chat API endpoint (supports both Ollama and OpenAI-compatible).

        Args:
            instruction: User message/prompt
            endpoint: API endpoint URL (e.g., http://127.0.0.1:8000/v1)
            model: Model identifier
            system_prompt: Optional system message for the LLM

        Returns:
            str: The LLM's response text
        """
        import requests

        # Build messages array with system prompt
        messages = []

        # Add system message for English-only enforcement
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        else:
            # Default English-only enforcement
            messages.append(
                {
                    "role": "system",
                    "content": "IMPORTANT: You must respond ONLY in English. Never use Chinese, Spanish, or any other language. English only.",
                }
            )

        # Add user message
        messages.append({"role": "user", "content": instruction})

        # Determine if this is Ollama or OpenAI-compatible endpoint
        if model.startswith("ollama:"):
            # Ollama endpoint
            actual_model = model.replace("ollama:", "", 1)
            url = f"{endpoint}/api/chat"
            payload = {"model": actual_model, "messages": messages, "stream": False}
            headers = {}
        else:
            # OpenAI-compatible endpoint (llama.cpp, OpenAI API, etc.)
            url = f"{endpoint}/chat/completions"
            payload = {"model": model, "messages": messages}

            # Add OpenAI API key if using OpenAI endpoint
            headers = {}
            if "api.openai.com" in endpoint:
                api_key = os.environ.get("OPENAI_API_KEY", "")
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=120)
            response.raise_for_status()

            data = response.json()

            # Handle different response formats
            if "message" in data and "content" in data["message"]:
                # Ollama format
                return data["message"]["content"]
            elif "choices" in data and len(data["choices"]) > 0:
                # OpenAI format
                return data["choices"][0]["message"]["content"]
            else:
                return f"Error: Unexpected response format from {endpoint}"

        except requests.exceptions.Timeout:
            return "Error: LLM request timed out after 120 seconds"
        except requests.exceptions.ConnectionError:
            return f"Error: Could not connect to LLM at {endpoint}. Is the server running?"
        except requests.exceptions.HTTPError as e:
            return f"Error: LLM API returned error {e.response.status_code}: {e.response.text}"
        except Exception as e:
            return f"Error calling LLM API: {str(e)}"

    async def _execute_with_tools(
        self,
        instruction: str,
        agent_type: AgentType,
        endpoint: str,
        model: str,
    ) -> tuple:
        """
        Execute task with tool support for mobile agents (ollama).

        For now, implements basic tool awareness via system prompt.
        Full function calling will be added in future iteration.

        Returns:
            tuple: (response: str, tools_used: list)
        """
        import requests

        # Get tools for this agent type
        available_tools = self.get_tools_for_agent(agent_type)

        # Build tool descriptions for system prompt
        tool_descriptions = []
        for tool in available_tools:
            tool_desc = f"- {tool.name}: {tool.description}"
            tool_descriptions.append(tool_desc)

        tools_text = "\n".join(tool_descriptions) if tool_descriptions else "No specific tools available."

        # Enhanced system prompt with tool awareness
        system_prompt = f"""You are an expert AI assistant with access to the following tools:

{tools_text}

When you need to use a tool, mention it clearly in your response.
IMPORTANT: Always respond ONLY in English. Never use Chinese or any other language."""

        # Call LLM with tool-aware prompt
        response = await self._call_chat_api(
            instruction,
            endpoint,
            model,
            system_prompt
        )

        # For now, return response without actual tool execution
        # Full tool calling will be implemented in next iteration
        tools_used = ["tool_aware_prompt"]

        return response, tools_used

    async def _execute_claude_with_tools(
        self,
        instruction: str,
        agent_type: AgentType,
    ) -> tuple:
        """
        Execute task with Claude API and tool support.

        Returns:
            tuple: (response: str, tools_used: list)
        """
        # Get tools for this agent type
        available_tools = self.get_tools_for_agent(agent_type)

        # Build tool descriptions
        tool_descriptions = []
        for tool in available_tools:
            tool_desc = f"- {tool.name}: {tool.description}"
            tool_descriptions.append(tool_desc)

        tools_text = "\n".join(tool_descriptions) if tool_descriptions else "No specific tools available."

        # For now, use basic Claude API call with tool awareness
        # Full Claude tool calling will be implemented in next iteration
        system_prompt = f"""You are an expert consultant with access to these tools:

{tools_text}

Provide thoughtful, well-reasoned advice."""

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": instruction}]
            )

            response = message.content[0].text
            tools_used = ["claude_with_tools"]

            return response, tools_used

        except Exception as e:
            return f"Error calling Claude API: {str(e)}", []

    def get_agent_stats(self) -> Dict[str, Any]:
        """Get statistics about agent usage"""
        return {
            "agents": self.agent_stats,
            "active_tasks": len(
                [t for t in self.active_tasks.values() if t["status"] == "running"]
            ),
            "total_tasks": len(self.active_tasks),
        }

    def get_available_agents(self) -> List[Dict[str, Any]]:
        """Get list of available agents with their capabilities"""
        return [
            {
                "type": agent_type.value,
                "name": config["name"],
                "capabilities": config["capabilities"],
                "speed": config["speed"],
                "quality": config["quality"],
            }
            for agent_type, config in self.agents.items()
        ]
