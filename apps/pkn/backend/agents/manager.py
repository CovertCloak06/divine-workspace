#!/usr/bin/env python3
"""
Multi-Agent Coordination System
Manages and coordinates multiple specialized AI agents
ENHANCED with full tool integration
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
)

# Import advanced agent features
from ..tools.rag_tools import RAGMemory
from ..tools.planning_tools import TaskPlanner, PlanExecutor
from ..tools.delegation_tools import AgentDelegationManager
from ..tools.chain_tools import ToolChainExecutor
from ..tools.sandbox_tools import CodeSandbox
from ..tools.evaluation_tools import AgentEvaluator


# Import local modules
from .types import AgentType, TaskComplexity, AgentMessage
from .classifier import TaskClassifier


class AgentManager:
    """
    Coordinates multiple specialized agents.
    Routes tasks to the most appropriate agent based on task type and complexity.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        from pathlib import Path

        self.project_root = Path(project_root)
        self.agents = {}
        self.active_tasks = {}
        self.conversation_history = {}
        self.agent_stats = {}

        # Initialize classifier
        self.classifier = TaskClassifier()

        # Initialize available agents
        self._init_agents()

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

    def _init_agents(self):
        """Initialize available agent configurations"""

        # Coder Agent - Qwen2.5-Coder (best for code)
        self.agents[AgentType.CODER] = {
            "name": "Qwen Coder",
            "model": "llamacpp:local",
            "endpoint": "http://127.0.0.1:8000/v1",
            "capabilities": ["code_writing", "debugging", "refactoring", "code_review"],
            "speed": "slow",  # ~6s for simple tasks
            "quality": "high",  # Best code quality
            "tools_enabled": True,
        }

        # Reasoner Agent - Could use DeepSeek or same Qwen
        self.agents[AgentType.REASONER] = {
            "name": "Reasoning Agent",
            "model": "llamacpp:local",
            "endpoint": "http://127.0.0.1:8000/v1",
            "capabilities": ["planning", "logic", "problem_solving", "analysis"],
            "speed": "slow",
            "quality": "high",
            "tools_enabled": True,
        }

        # Researcher Agent - Enhanced agent with web tools
        self.agents[AgentType.RESEARCHER] = {
            "name": "Research Agent",
            "model": "enhanced_agent",
            "endpoint": None,  # Uses local_parakleon_agent directly
            "capabilities": ["web_search", "documentation", "fact_checking"],
            "speed": "very_slow",  # Includes web lookups
            "quality": "high",
            "tools_enabled": True,
        }

        # Executor Agent - For system commands (uses enhanced agent)
        self.agents[AgentType.EXECUTOR] = {
            "name": "Executor Agent",
            "model": "enhanced_agent",
            "endpoint": None,
            "capabilities": ["command_execution", "file_operations", "system_tasks"],
            "speed": "medium",
            "quality": "medium",
            "tools_enabled": True,
        }

        # General Agent - For simple Q&A (Ollama if available, else Qwen)
        self.agents[AgentType.GENERAL] = {
            "name": "General Assistant",
            "model": "ollama:mannix/llama3.1-8b-lexi:q4_0",  # Faster for simple tasks
            "endpoint": "http://127.0.0.1:11434",
            "capabilities": ["conversation", "simple_qa", "explanations"],
            "speed": "fast",  # ~2s for simple tasks
            "quality": "medium",
            "tools_enabled": False,
        }

        # Consultant Agent - Claude API for maximum intelligence
        self.agents[AgentType.CONSULTANT] = {
            "name": "Claude Consultant",
            "model": "claude_api",
            "endpoint": None,  # Uses claude_api module
            "capabilities": [
                "high_level_decisions",
                "voting",
                "expert_advice",
                "complex_reasoning",
            ],
            "speed": "medium",  # API latency ~3-5s
            "quality": "very_high",  # Maximum intelligence
            "tools_enabled": True,  # Claude can use ALL tools!
        }

        # Security Agent - UNCENSORED cybersecurity expert
        # Uses Qwen2.5-Coder-14B-Instruct-abliterated (uncensored model)
        self.agents[AgentType.SECURITY] = {
            "name": "Security Expert (Uncensored)",
            "model": "llamacpp:local",  # Uses your abliterated Qwen model
            "endpoint": "http://127.0.0.1:8000/v1",
            "capabilities": [
                "penetration_testing",
                "vulnerability_analysis",
                "exploit_development",
                "security_auditing",
                "malware_analysis",
                "network_security",
                "web_security",
                "cryptography",
                "reverse_engineering",
                "osint",
                "social_engineering",
                "red_teaming",
                "blue_teaming",
            ],
            "speed": "slow",  # ~8-15s for security analysis
            "quality": "high",  # Expert-level security knowledge
            "tools_enabled": True,  # Full access to OSINT, web, system tools
            "uncensored": True,  # NO content filtering
        }

        # Vision Agent - LLaVA for image/UI analysis (LOCAL)
        # Uses LLaVA-v1.6-Vicuna-7B for vision capabilities
        self.agents[AgentType.VISION] = {
            "name": "Vision Analyst (Local)",
            "model": "llamacpp:vision",  # LLaVA vision model
            "endpoint": "http://127.0.0.1:8001/v1",  # Separate port for vision
            "capabilities": [
                "image_analysis",
                "screenshot_analysis",
                "ui_understanding",
                "visual_debugging",
                "diagram_interpretation",
                "ocr",
                "visual_qa",
                "object_detection",
                "scene_understanding",
            ],
            "speed": "medium",  # ~5-8s for vision analysis
            "quality": "high",  # Good vision understanding
            "tools_enabled": True,  # Can use file tools to load images
            "vision": True,  # Supports image input
        }

        # Vision Cloud Agent - Groq Llama-3.2-90B-Vision (FREE, FAST, ENGLISH-ONLY)
        self.agents[AgentType.VISION_CLOUD] = {
            "name": "Vision Analyst (Cloud)",
            "model": "groq_vision",  # Groq cloud vision API
            "endpoint": None,  # Uses groq_vision module
            "capabilities": [
                "image_analysis",
                "screenshot_analysis",
                "ui_understanding",
                "visual_debugging",
                "diagram_interpretation",
                "ocr",
                "visual_qa",
                "object_detection",
                "scene_understanding",
            ],
            "speed": "fast",  # ~1-3s for vision analysis (cloud)
            "quality": "very_high",  # Llama-3.2-90B is extremely powerful
            "tools_enabled": False,  # Cloud API handles images directly
            "vision": True,  # Supports image input
            "cloud": True,  # Cloud-based (requires API key)
            "free": True,  # Completely free (no credit card needed)
        }

    def get_tools_for_agent(self, agent_type: AgentType) -> List:
        """
        Get appropriate tools for each agent type.

        Returns list of langchain tools that the agent can use.
        """
        # All agents can use memory tools
        common_tools = memory_tools.TOOLS

        if agent_type == AgentType.CODER:
            # Code operations + file search
            return code_tools.TOOLS + file_tools.TOOLS + common_tools

        elif agent_type == AgentType.EXECUTOR:
            # System control + file operations
            return system_tools.TOOLS + file_tools.TOOLS + common_tools

        elif agent_type == AgentType.RESEARCHER:
            # Web research + OSINT + file search
            return web_tools.TOOLS + osint_tools.TOOLS + file_tools.TOOLS + common_tools

        elif agent_type == AgentType.REASONER:
            # Pure reasoning, just memory
            return common_tools

        elif agent_type == AgentType.SECURITY:
            # Security & pentesting tools: OSINT, web, system, file access
            return (
                osint_tools.TOOLS  # Port scanning, DNS, IP lookup
                + web_tools.TOOLS  # Web reconnaissance
                + system_tools.TOOLS  # System analysis, command execution
                + file_tools.TOOLS  # File operations for analysis
                + code_tools.TOOLS  # Code review for vulnerabilities
                + common_tools
            )

        elif agent_type == AgentType.CONSULTANT:
            # ALL tools available
            return (
                code_tools.TOOLS
                + file_tools.TOOLS
                + system_tools.TOOLS
                + web_tools.TOOLS
                + osint_tools.TOOLS
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
            # Execute based on agent type and tool requirements
            if agent_config["model"] == "groq_vision":
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
