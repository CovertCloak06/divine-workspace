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
from tools import code_tools, file_tools, system_tools, web_tools, memory_tools, osint_tools

# Import advanced agent features
from tools.rag_tools import RAGMemory
from tools.planning_tools import TaskPlanner, PlanExecutor
from tools.delegation_tools import AgentDelegationManager
from tools.chain_tools import ToolChainExecutor
from tools.sandbox_tools import CodeSandbox
from tools.evaluation_tools import AgentEvaluator


class AgentType(Enum):
    """Types of specialized agents"""
    CODER = "coder"           # Code writing, debugging, refactoring
    REASONER = "reasoner"     # Planning, logic, problem solving
    RESEARCHER = "researcher" # Web research, documentation lookup
    EXECUTOR = "executor"     # Command execution, system tasks
    GENERAL = "general"       # General conversation, simple Q&A
    CONSULTANT = "consultant" # External LLM (Claude/GPT) for high-level decisions
    SECURITY = "security"     # Cybersecurity, pentesting, vulnerability analysis (UNCENSORED)
    VISION = "vision"         # Vision/image analysis, UI understanding, screenshot analysis (LOCAL)
    VISION_CLOUD = "vision_cloud"  # Cloud vision via Groq (FREE, fast, English-only)


class TaskComplexity(Enum):
    """Task complexity levels"""
    SIMPLE = "simple"         # Quick answers, basic operations
    MEDIUM = "medium"         # Requires some reasoning or tool use
    COMPLEX = "complex"       # Multi-step, requires multiple agents


class AgentMessage:
    """Message for agent-to-agent communication"""

    def __init__(self, from_agent: str, to_agent: str, task_id: str,
                 content: Dict[str, Any], requires_response: bool = False):
        self.id = str(uuid.uuid4())
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.task_id = task_id
        self.content = content
        self.requires_response = requires_response
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'from_agent': self.from_agent,
            'to_agent': self.to_agent,
            'task_id': self.task_id,
            'content': self.content,
            'requires_response': self.requires_response,
            'timestamp': self.timestamp
        }


class AgentManager:
    """
    Coordinates multiple specialized agents.
    Routes tasks to the most appropriate agent based on task type and complexity.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.agents = {}
        self.active_tasks = {}
        self.conversation_history = {}
        self.agent_stats = {}

        # Initialize available agents
        self._init_agents()

        # Initialize advanced features
        self.rag_memory = RAGMemory(str(project_root))
        self.task_planner = None  # Lazy init (requires LLM client)
        self.plan_executor = PlanExecutor(self)
        self.delegation_manager = AgentDelegationManager(self, str(project_root))
        self.tool_chain_executor = ToolChainExecutor(self._get_tool_registry())
        self.code_sandbox = CodeSandbox(str(project_root))
        self.evaluator = AgentEvaluator(str(project_root))

    def _init_agents(self):
        """Initialize available agent configurations"""

        # Coder Agent - Qwen2.5-Coder (best for code)
        self.agents[AgentType.CODER] = {
            'name': 'Qwen Coder',
            'model': 'llamacpp:local',
            'endpoint': 'http://127.0.0.1:8000/v1',
            'capabilities': ['code_writing', 'debugging', 'refactoring', 'code_review'],
            'speed': 'slow',      # ~6s for simple tasks
            'quality': 'high',    # Best code quality
            'tools_enabled': True,
        }

        # Reasoner Agent - Could use DeepSeek or same Qwen
        self.agents[AgentType.REASONER] = {
            'name': 'Reasoning Agent',
            'model': 'llamacpp:local',
            'endpoint': 'http://127.0.0.1:8000/v1',
            'capabilities': ['planning', 'logic', 'problem_solving', 'analysis'],
            'speed': 'slow',
            'quality': 'high',
            'tools_enabled': True,
        }

        # Researcher Agent - Enhanced agent with web tools
        self.agents[AgentType.RESEARCHER] = {
            'name': 'Research Agent',
            'model': 'enhanced_agent',
            'endpoint': None,  # Uses local_parakleon_agent directly
            'capabilities': ['web_search', 'documentation', 'fact_checking'],
            'speed': 'very_slow',  # Includes web lookups
            'quality': 'high',
            'tools_enabled': True,
        }

        # Executor Agent - For system commands (uses enhanced agent)
        self.agents[AgentType.EXECUTOR] = {
            'name': 'Executor Agent',
            'model': 'enhanced_agent',
            'endpoint': None,
            'capabilities': ['command_execution', 'file_operations', 'system_tasks'],
            'speed': 'medium',
            'quality': 'medium',
            'tools_enabled': True,
        }

        # General Agent - For simple Q&A (Ollama if available, else Qwen)
        self.agents[AgentType.GENERAL] = {
            'name': 'General Assistant',
            'model': 'ollama:mannix/llama3.1-8b-lexi:q4_0',  # Faster for simple tasks
            'endpoint': 'http://127.0.0.1:11434',
            'capabilities': ['conversation', 'simple_qa', 'explanations'],
            'speed': 'fast',      # ~2s for simple tasks
            'quality': 'medium',
            'tools_enabled': False,
        }

        # Consultant Agent - Claude API for maximum intelligence
        self.agents[AgentType.CONSULTANT] = {
            'name': 'Claude Consultant',
            'model': 'claude_api',
            'endpoint': None,  # Uses claude_api module
            'capabilities': ['high_level_decisions', 'voting', 'expert_advice', 'complex_reasoning'],
            'speed': 'medium',   # API latency ~3-5s
            'quality': 'very_high',  # Maximum intelligence
            'tools_enabled': True,  # Claude can use ALL tools!
        }

        # Security Agent - UNCENSORED cybersecurity expert
        # Uses Qwen2.5-Coder-14B-Instruct-abliterated (uncensored model)
        self.agents[AgentType.SECURITY] = {
            'name': 'Security Expert (Uncensored)',
            'model': 'llamacpp:local',  # Uses your abliterated Qwen model
            'endpoint': 'http://127.0.0.1:8000/v1',
            'capabilities': [
                'penetration_testing', 'vulnerability_analysis', 'exploit_development',
                'security_auditing', 'malware_analysis', 'network_security',
                'web_security', 'cryptography', 'reverse_engineering', 'osint',
                'social_engineering', 'red_teaming', 'blue_teaming'
            ],
            'speed': 'slow',      # ~8-15s for security analysis
            'quality': 'high',    # Expert-level security knowledge
            'tools_enabled': True,  # Full access to OSINT, web, system tools
            'uncensored': True,   # NO content filtering
        }

        # Vision Agent - LLaVA for image/UI analysis (LOCAL)
        # Uses LLaVA-v1.6-Vicuna-7B for vision capabilities
        self.agents[AgentType.VISION] = {
            'name': 'Vision Analyst (Local)',
            'model': 'llamacpp:vision',  # LLaVA vision model
            'endpoint': 'http://127.0.0.1:8001/v1',  # Separate port for vision
            'capabilities': [
                'image_analysis', 'screenshot_analysis', 'ui_understanding',
                'visual_debugging', 'diagram_interpretation', 'ocr',
                'visual_qa', 'object_detection', 'scene_understanding'
            ],
            'speed': 'medium',      # ~5-8s for vision analysis
            'quality': 'high',      # Good vision understanding
            'tools_enabled': True,  # Can use file tools to load images
            'vision': True,         # Supports image input
        }

        # Vision Cloud Agent - Groq Llama-3.2-90B-Vision (FREE, FAST, ENGLISH-ONLY)
        self.agents[AgentType.VISION_CLOUD] = {
            'name': 'Vision Analyst (Cloud)',
            'model': 'groq_vision',  # Groq cloud vision API
            'endpoint': None,  # Uses groq_vision module
            'capabilities': [
                'image_analysis', 'screenshot_analysis', 'ui_understanding',
                'visual_debugging', 'diagram_interpretation', 'ocr',
                'visual_qa', 'object_detection', 'scene_understanding'
            ],
            'speed': 'fast',        # ~1-3s for vision analysis (cloud)
            'quality': 'very_high', # Llama-3.2-90B is extremely powerful
            'tools_enabled': False, # Cloud API handles images directly
            'vision': True,         # Supports image input
            'cloud': True,          # Cloud-based (requires API key)
            'free': True,           # Completely free (no credit card needed)
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
            return (code_tools.TOOLS +
                   file_tools.TOOLS +
                   common_tools)

        elif agent_type == AgentType.EXECUTOR:
            # System control + file operations
            return (system_tools.TOOLS +
                   file_tools.TOOLS +
                   common_tools)

        elif agent_type == AgentType.RESEARCHER:
            # Web research + OSINT + file search
            return (web_tools.TOOLS +
                   osint_tools.TOOLS +
                   file_tools.TOOLS +
                   common_tools)

        elif agent_type == AgentType.REASONER:
            # Pure reasoning, just memory
            return common_tools

        elif agent_type == AgentType.SECURITY:
            # Security & pentesting tools: OSINT, web, system, file access
            return (osint_tools.TOOLS +       # Port scanning, DNS, IP lookup
                   web_tools.TOOLS +          # Web reconnaissance
                   system_tools.TOOLS +       # System analysis, command execution
                   file_tools.TOOLS +         # File operations for analysis
                   code_tools.TOOLS +         # Code review for vulnerabilities
                   common_tools)

        elif agent_type == AgentType.CONSULTANT:
            # ALL tools available
            return (code_tools.TOOLS +
                   file_tools.TOOLS +
                   system_tools.TOOLS +
                   web_tools.TOOLS +
                   osint_tools.TOOLS +
                   common_tools)

        elif agent_type == AgentType.VISION:
            # Vision tasks: file reading for images, web for image URLs
            return (file_tools.TOOLS +
                   web_tools.TOOLS +
                   common_tools)

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
            registry[f'code_tools.{tool.name}'] = tool

        for tool in file_tools.TOOLS:
            registry[f'file_tools.{tool.name}'] = tool

        for tool in system_tools.TOOLS:
            registry[f'system_tools.{tool.name}'] = tool

        for tool in web_tools.TOOLS:
            registry[f'web_tools.{tool.name}'] = tool

        for tool in osint_tools.TOOLS:
            registry[f'osint_tools.{tool.name}'] = tool

        for tool in memory_tools.TOOLS:
            registry[f'memory_tools.{tool.name}'] = tool

        return registry

    def classify_task(self, instruction: str) -> Dict[str, Any]:
        """
        Classify task by type, complexity, and required agent.

        Returns:
            {
                'agent_type': AgentType,
                'complexity': TaskComplexity,
                'confidence': float,
                'reasoning': str,
                'requires_tools': bool
            }
        """
        instruction_lower = instruction.lower()

        # Code-related keywords
        code_keywords = [
            'code', 'function', 'class', 'debug', 'bug', 'error', 'refactor',
            'implement', 'write code', 'python', 'javascript', 'script',
            'algorithm', 'optimize', 'fix', 'syntax', 'variable'
        ]

        # Research keywords
        research_keywords = [
            'search', 'find', 'lookup', 'research', 'what is', 'who is',
            'when did', 'how to', 'wikipedia', 'documentation', 'docs',
            'latest', 'current', 'news', 'github', 'library'
        ]

        # Execution keywords
        execute_keywords = [
            'run', 'execute', 'list files', 'read file', 'write file',
            'create file', 'delete', 'move', 'copy', 'command', 'bash',
            'shell', 'directory'
        ]

        # Planning/reasoning keywords
        planning_keywords = [
            'plan', 'strategy', 'approach', 'analyze', 'compare', 'evaluate',
            'pros and cons', 'should i', 'which', 'best way', 'explain why',
            'logic', 'reasoning'
        ]

        # Consultant keywords (complex decisions, voting, expert advice)
        consultant_keywords = [
            'vote', 'decide', 'choose between', 'which option', 'expert opinion',
            'deep thought', 'complex decision', 'consult', 'advise', 'recommend',
            'philosophical', 'ethical', 'strategic decision', 'critical choice'
        ]

        # Security/Cybersecurity keywords (UNCENSORED - pentesting, hacking, security)
        security_keywords = [
            'hack', 'hacking', 'exploit', 'vulnerability', 'vuln', 'penetration test',
            'pentest', 'security', 'cybersecurity', 'injection', 'xss', 'csrf',
            'sql injection', 'buffer overflow', 'reverse engineering', 'malware',
            'backdoor', 'rootkit', 'privilege escalation', 'brute force', 'crack',
            'password crack', 'hash', 'decrypt', 'encryption', 'cryptography',
            'nmap', 'metasploit', 'burp suite', 'wireshark', 'kali', 'red team',
            'blue team', 'threat', 'attack', 'payload', 'shellcode', 'zero day',
            'cve', 'security audit', 'web security', 'network security', 'firewall',
            'bypass', 'evade', 'stealth', 'osint', 'reconnaissance', 'footprint',
            'enumeration', 'port scan', 'directory traversal', 'lfi', 'rfi',
            'command injection', 'code injection', 'deserialization', 'xxe'
        ]

        # Vision/Image analysis keywords
        vision_keywords = [
            'image', 'screenshot', 'picture', 'photo', 'visual', 'see', 'look at',
            'what do you see', 'analyze image', 'describe image', 'ui', 'interface',
            'diagram', 'chart', 'graph', 'drawing', 'render', 'displayed', 'shown',
            'screen', 'display', 'visible', 'ocr', 'read text from', 'extract text',
            'recognize', 'detect', 'identify in image', 'what\'s in', 'show me'
        ]

        # Count keyword matches
        code_score = sum(1 for kw in code_keywords if kw in instruction_lower)
        research_score = sum(1 for kw in research_keywords if kw in instruction_lower)
        execute_score = sum(1 for kw in execute_keywords if kw in instruction_lower)
        planning_score = sum(1 for kw in planning_keywords if kw in instruction_lower)
        consultant_score = sum(1 for kw in consultant_keywords if kw in instruction_lower)
        security_score = sum(1 for kw in security_keywords if kw in instruction_lower)
        vision_score = sum(1 for kw in vision_keywords if kw in instruction_lower)

        # Determine agent type and complexity
        scores = {
            AgentType.CODER: code_score,
            AgentType.RESEARCHER: research_score,
            AgentType.EXECUTOR: execute_score,
            AgentType.REASONER: planning_score,
            AgentType.CONSULTANT: consultant_score * 2,  # Weight consultant higher
            AgentType.SECURITY: security_score * 2.5,  # Weight security highest for safety
            AgentType.VISION: vision_score * 2,  # Weight vision high for image tasks (local)
            AgentType.VISION_CLOUD: vision_score * 2,  # Same weight as local vision
            AgentType.GENERAL: 0  # Default agent, always has score 0
        }

        # Get highest scoring agent
        if max(scores.values()) > 0:
            agent_type = max(scores, key=scores.get)
            confidence = min(scores[agent_type] / 3.0, 1.0)  # Normalize to 0-1
        else:
            # Default to general for simple questions
            agent_type = AgentType.GENERAL
            confidence = 0.5

        # Determine complexity
        word_count = len(instruction.split())
        has_multi_steps = any(word in instruction_lower for word in ['and then', 'after that', 'next', 'also', 'additionally'])

        if word_count < 10 and not has_multi_steps:
            complexity = TaskComplexity.SIMPLE
        elif word_count < 30 and not has_multi_steps:
            complexity = TaskComplexity.MEDIUM
        else:
            complexity = TaskComplexity.COMPLEX

        # Determine if tools are needed
        requires_tools = agent_type in [AgentType.RESEARCHER, AgentType.EXECUTOR, AgentType.CODER, AgentType.SECURITY]

        return {
            'agent_type': agent_type,  # Keep as enum for internal use
            'complexity': complexity,  # Keep as enum for internal use
            'confidence': confidence,
            'reasoning': f"Matched {agent_type.value} keywords (score: {scores[agent_type]})",
            'requires_tools': requires_tools,
            'word_count': word_count,
            'has_multi_steps': has_multi_steps
        }

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

    def route_task(self, instruction: str, conversation_id: str = None) -> Dict[str, Any]:
        """
        Route a task to the most appropriate agent.

        Args:
            instruction: The task to perform
            conversation_id: Optional conversation ID for context

        Returns:
            {
                'agent': AgentType,
                'classification': dict,
                'strategy': 'single_agent' | 'multi_agent',
                'estimated_time': str
            }
        """
        classification = self.classify_task(instruction)

        # Determine strategy
        if classification['complexity'] == TaskComplexity.COMPLEX:
            strategy = 'multi_agent'
        else:
            strategy = 'single_agent'

        # Estimate time based on agent and complexity
        agent_config = self.agents[classification['agent_type']]
        speed = agent_config['speed']

        time_estimates = {
            'fast': '2-5 seconds',
            'medium': '5-15 seconds',
            'slow': '10-30 seconds',
            'very_slow': '30-120 seconds'
        }

        return {
            'agent': classification['agent_type'],  # Keep as enum for internal use
            'classification': classification,
            'strategy': strategy,
            'estimated_time': time_estimates.get(speed, 'unknown'),
            'agent_config': agent_config
        }

    async def execute_task(self, instruction: str, conversation_id: str = None) -> Dict[str, Any]:
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
        agent_type = routing['agent']
        agent_config = routing['agent_config']

        # Track active task
        self.active_tasks[task_id] = {
            'instruction': instruction,
            'agent_type': agent_type.value,
            'status': 'running',
            'start_time': start_time
        }

        try:
            # Execute based on agent type and tool requirements
            if agent_config['model'] == 'groq_vision':
                # Use Groq cloud vision API
                from groq_vision import groq_vision

                if groq_vision.is_available():
                    # Groq vision with images
                    response_data = groq_vision.analyze_text(instruction)
                    if response_data['success']:
                        response = response_data['response']
                        tools_used = ['groq_cloud_vision']
                    else:
                        response = f"⚠️ Groq Vision error: {response_data['error']}\nFalling back to local vision agent."
                        # Fallback to local vision
                        fallback_config = self.agents[AgentType.VISION]
                        response = await self._call_chat_api(
                            instruction,
                            fallback_config['endpoint'],
                            fallback_config['model'],
                            "You are a vision analyst. IMPORTANT: Always respond in English only."
                        )
                        tools_used = ['fallback_to_local_vision']
                else:
                    response = "⚠️ Groq API not configured. Get a free API key at https://console.groq.com\nSet GROQ_API_KEY in .env file.\n\nFalling back to local vision agent."
                    # Fallback to local vision
                    fallback_config = self.agents[AgentType.VISION]
                    response = await self._call_chat_api(
                        instruction,
                        fallback_config['endpoint'],
                        fallback_config['model'],
                        "You are a vision analyst. IMPORTANT: Always respond in English only."
                    )
                    tools_used = ['fallback_to_local_vision']
            elif agent_config['model'] == 'claude_api':
                # Use Claude API for CONSULTANT agent (with all tools!)
                from claude_api import claude_api

                if claude_api.is_available():
                    # Claude API with tools
                    response, tools_used = await self._execute_claude_with_tools(
                        instruction,
                        agent_type
                    )
                else:
                    # Fallback if Claude API not available
                    response = "⚠️ Claude API unavailable (set ANTHROPIC_API_KEY env variable)\nFalling back to local reasoning agent."
                    # Fallback to reasoner agent with tools
                    fallback_config = self.agents[AgentType.REASONER]
                    response, tools_used = await self._execute_with_tools(
                        instruction,
                        AgentType.REASONER,
                        fallback_config['endpoint'],
                        fallback_config['model']
                    )
                    tools_used = ['fallback_to_reasoner'] + tools_used
            elif agent_config.get('tools_enabled', False) and agent_type in [AgentType.CODER, AgentType.EXECUTOR, AgentType.RESEARCHER, AgentType.REASONER]:
                # Use tool-enhanced execution
                response, tools_used = await self._execute_with_tools(
                    instruction,
                    agent_type,
                    agent_config['endpoint'],
                    agent_config['model']
                )
            elif agent_config['model'] == 'enhanced_agent':
                # Fallback to local_parakleon_agent for backwards compatibility
                from local_parakleon_agent import run_agent
                response = run_agent(instruction)
                tools_used = ['enhanced_agent_tools']
            elif agent_config['model'] == 'external_api':
                # Legacy external LLM support (kept for backwards compatibility)
                from external_llm import external_llm

                result = await external_llm.query_best_available(
                    prompt=instruction,
                    system_prompt="You are an expert consultant providing thoughtful, well-reasoned advice."
                )

                if result.get('available'):
                    response = result['response']
                    tools_used = [f"external_llm_{result['provider']}"]
                else:
                    # Fallback if external LLM not available
                    response = f"External consultant unavailable: {result.get('error', 'Unknown error')}\nFalling back to local reasoning agent."
                    fallback_config = self.agents[AgentType.REASONER]
                    fallback_system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only."
                    response = await self._call_chat_api(
                        instruction,
                        fallback_config['endpoint'],
                        fallback_config['model'],
                        fallback_system_prompt
                    )
                    tools_used = ['fallback_to_reasoner']
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
                    agent_config['endpoint'],
                    agent_config['model'],
                    agent_system_prompt
                )
                tools_used = []

            execution_time = time.time() - start_time

            # Update task status
            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['execution_time'] = execution_time

            # Update agent stats
            if agent_type.value not in self.agent_stats:
                self.agent_stats[agent_type.value] = {
                    'tasks_completed': 0,
                    'total_time': 0,
                    'avg_time': 0
                }

            stats = self.agent_stats[agent_type.value]
            stats['tasks_completed'] += 1
            stats['total_time'] += execution_time
            stats['avg_time'] = stats['total_time'] / stats['tasks_completed']

            # Log execution to evaluator
            try:
                self.evaluator.log_execution(
                    agent_type=agent_type.value,
                    task=instruction[:200],  # Truncate long tasks
                    response=response[:500],  # Truncate long responses
                    duration_ms=int(execution_time * 1000),
                    success=True,
                    tools_used=tools_used,
                    session_id=conversation_id or task_id
                )
            except Exception as e:
                # Don't fail the task if logging fails
                print(f"Warning: Failed to log execution: {e}")

            return {
                'response': response,
                'agent_used': agent_type.value,
                'agent_name': agent_config['name'],
                'execution_time': execution_time,
                'tools_used': tools_used,
                'status': 'success',
                'task_id': task_id,
                'routing': self._make_json_safe(routing)  # Convert enums to strings for JSON
            }

        except Exception as e:
            execution_time = time.time() - start_time
            self.active_tasks[task_id]['status'] = 'error'

            # Log failure to evaluator
            try:
                self.evaluator.log_execution(
                    agent_type=agent_type.value,
                    task=instruction[:200],
                    response="",
                    duration_ms=int(execution_time * 1000),
                    success=False,
                    error=str(e),
                    session_id=conversation_id or task_id
                )
            except Exception as eval_error:
                print(f"Warning: Failed to log error: {eval_error}")

            return {
                'response': f"Error executing task: {str(e)}",
                'agent_used': agent_type.value,
                'execution_time': execution_time,
                'tools_used': [],
                'status': 'error',
                'error': str(e),
                'task_id': task_id
            }

    async def _execute_with_tools(self, instruction: str, agent_type: AgentType, endpoint: str, model: str) -> tuple[str, list]:
        """
        Execute task with tool support - works with ANY local model!
        Uses prompt-based tool calling (ReAct pattern) instead of function calling.

        Returns: (response, tools_used)
        """
        import re
        import json

        # Get tools for this agent
        tools = self.get_tools_for_agent(agent_type)

        if not tools:
            # No tools, just call API with agent-specific system prompt
            if agent_type == AgentType.VISION:
                system_prompt = "You are a vision and image analysis expert. IMPORTANT: Always respond in English only. Never use Chinese or any other language."
            elif agent_type == AgentType.GENERAL:
                system_prompt = "You are a helpful general assistant. IMPORTANT: Always respond in English only."
            elif agent_type == AgentType.CODER:
                system_prompt = "You are an expert code writer. IMPORTANT: Always respond in English only."
            elif agent_type == AgentType.REASONER:
                system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only."
            else:
                system_prompt = None  # Use default

            response = await self._call_chat_api(instruction, endpoint, model, system_prompt)
            return response, []

        # Build tool descriptions for the prompt
        tool_descriptions = []
        tool_map = {}

        for tool in tools:
            tool_map[tool.name] = tool
            # Get tool parameters
            params = []
            if hasattr(tool, 'args_schema') and tool.args_schema:
                schema = tool.args_schema.schema()
                props = schema.get('properties', {})
                required = schema.get('required', [])
                for param_name, param_info in props.items():
                    req_marker = " (required)" if param_name in required else ""
                    params.append(f"  - {param_name}: {param_info.get('description', 'no description')}{req_marker}")

            param_str = "\n".join(params) if params else "  (no parameters)"
            tool_descriptions.append(
                f"**{tool.name}**: {tool.description}\nParameters:\n{param_str}"
            )

        tools_text = "\n\n".join(tool_descriptions)

        # System prompt with tool instructions
        system_prompts = {
            AgentType.CODER: f"""You are an expert code writer with access to powerful tools.
IMPORTANT: Always respond in English only.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1", "param2": "value2"}}

After seeing tool results, either use another tool or provide your final answer.
Always use tools when they can help! For example:
- Use glob to find files
- Use read_file to read code
- Use edit_file for surgical edits (never rewrite entire files)
- Use grep to search code""",

            AgentType.EXECUTOR: f"""You are a system administrator with full access.
IMPORTANT: Always respond in English only.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1"}}

Use bash for commands, process_list to check processes, system_info for stats.""",

            AgentType.RESEARCHER: f"""You are a research specialist.
IMPORTANT: Always respond in English only.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1"}}

Use web_search, github_search, stack_overflow_search to find information.""",

            AgentType.REASONER: f"""You are a reasoning expert.
IMPORTANT: Always respond in English only.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1"}}

Use memory tools to save your findings.""",

            AgentType.VISION: f"""You are a vision and image analysis expert.
IMPORTANT: Always respond in English only. Never use Chinese or any other language.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1"}}

Analyze images, screenshots, UI elements, and visual content. Describe what you see clearly in English.""",

            AgentType.GENERAL: f"""You are a helpful general assistant.
IMPORTANT: Always respond in English only.

AVAILABLE TOOLS:
{tools_text}

To use a tool, respond with:
TOOL: tool_name
ARGS: {{"param1": "value1"}}

Answer questions clearly and concisely. Use tools when they can help provide better answers.""",
        }

        system_prompt = system_prompts.get(
            agent_type,
            f"You are a helpful AI assistant. IMPORTANT: Always respond in English only.\n\nAVAILABLE TOOLS:\n{tools_text}"
        )

        # Conversation history (without system prompt - that goes as parameter)
        conversation = f"User: {instruction}\n\nAssistant:"
        tools_used = []
        max_iterations = 5

        for iteration in range(max_iterations):
            # Call LLM with system prompt parameter
            response = await self._call_chat_api(conversation, endpoint, model, system_prompt)

            # Check if response contains a tool call
            tool_match = re.search(r'TOOL:\s*(\w+)', response, re.IGNORECASE)
            args_match = re.search(r'ARGS:\s*({[^}]+})', response, re.IGNORECASE | re.DOTALL)

            if tool_match:
                tool_name = tool_match.group(1)
                tools_used.append(tool_name)

                # Parse arguments
                try:
                    if args_match:
                        args_str = args_match.group(1)
                        # Clean up the JSON string
                        args_str = args_str.replace('\n', ' ').strip()
                        tool_args = json.loads(args_str)
                    else:
                        tool_args = {}
                except:
                    tool_args = {}

                # Execute tool
                tool_func = tool_map.get(tool_name)
                if tool_func:
                    try:
                        tool_result = tool_func.invoke(tool_args)
                    except Exception as e:
                        tool_result = f"Error: {str(e)}"
                else:
                    tool_result = f"Error: Tool '{tool_name}' not found"

                # Add to conversation
                conversation += f" {response}\n\nTOOL RESULT:\n{tool_result}\n\nAssistant:"
            else:
                # No tool call, this is the final answer
                return response, tools_used

        # Max iterations reached
        return response, tools_used

    async def _execute_claude_with_tools(self, instruction: str, agent_type: AgentType) -> tuple[str, list]:
        """
        Execute task with Claude API and tool support.

        Returns: (response, tools_used)
        """
        from claude_api import claude_api

        # Get tools for this agent
        tools = self.get_tools_for_agent(agent_type)

        if not tools:
            # No tools, just call Claude API
            result = await claude_api.query(instruction)
            return result.get('response', ''), []

        # Convert langchain tools to Anthropic format
        anthropic_tools = []
        tool_map = {}  # Map tool names to langchain tool objects

        for tool in tools:
            tool_map[tool.name] = tool

            # Convert to Anthropic tool schema
            anthropic_tools.append({
                'name': tool.name,
                'description': tool.description or tool.name,
                'input_schema': {
                    'type': 'object',
                    'properties': tool.args if hasattr(tool, 'args') else {},
                    'required': []
                }
            })

        # System prompts for each agent type
        system_prompts = {
            AgentType.CODER: "You are an expert code writer with access to powerful tools. IMPORTANT: Always respond in English only. Use tools to read, edit, and write code. Always use edit_file for surgical changes instead of rewriting entire files. Explain your reasoning.",
            AgentType.EXECUTOR: "You are a system administrator with full terminal access. IMPORTANT: Always respond in English only. Use bash and process tools to execute commands and manage systems. Always explain what you're doing before executing commands.",
            AgentType.RESEARCHER: "You are a research specialist with access to the web and documentation. IMPORTANT: Always respond in English only. Use web search, documentation lookup, and file search tools to find accurate information. Cite your sources.",
            AgentType.REASONER: "You are a reasoning expert. IMPORTANT: Always respond in English only. Think through problems logically, break them down into steps, and save your findings to memory for later use.",
            AgentType.CONSULTANT: "You are an expert consultant with access to ALL tools. IMPORTANT: Always respond in English only. Analyze the task, choose the right tools, and provide comprehensive solutions. You have maximum intelligence - use it wisely.",
            AgentType.VISION: "You are a vision and image analysis expert. IMPORTANT: Always respond in English only. Never use Chinese or any other language. Analyze images, screenshots, UI elements, and visual content clearly.",
            AgentType.GENERAL: "You are a helpful general assistant. IMPORTANT: Always respond in English only. Answer questions clearly and concisely.",
        }

        system_prompt = system_prompts.get(agent_type, "You are a helpful AI assistant. IMPORTANT: Always respond in English only.")

        # Tool execution loop
        messages = [{"role": "user", "content": instruction}]
        tools_used = []
        max_iterations = 5

        for iteration in range(max_iterations):
            # Call Claude API with tools
            response = claude_api.client.messages.create(
                model="claude-sonnet-4-20250514",  # Use Sonnet 4 for speed
                max_tokens=4096,
                temperature=0.2,
                system=system_prompt,
                messages=messages,
                tools=anthropic_tools
            )

            # Check if Claude wants to use tools
            if response.stop_reason == "tool_use":
                # Extract text response (if any)
                text_response = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        text_response += block.text

                # Execute tools
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        tool_name = block.name
                        tool_input = block.input
                        tools_used.append(tool_name)

                        # Find and execute the tool
                        tool_func = tool_map.get(tool_name)
                        if tool_func:
                            try:
                                tool_result = tool_func.invoke(tool_input)
                            except Exception as e:
                                tool_result = f"Error executing {tool_name}: {str(e)}"
                        else:
                            tool_result = f"Tool {tool_name} not found"

                        # Store tool result in Anthropic format
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": str(tool_result)
                        })

                # Add assistant response to messages
                messages.append({
                    "role": "assistant",
                    "content": response.content
                })

                # Add tool results to messages
                messages.append({
                    "role": "user",
                    "content": tool_results
                })

            else:
                # No more tool use, extract final response
                final_response = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_response += block.text

                return final_response, tools_used

        # Max iterations reached, return last response
        final_response = ""
        for block in response.content:
            if hasattr(block, 'text'):
                final_response += block.text

        return final_response, tools_used

    async def _call_chat_api(self, instruction: str, endpoint: str, model: str, system_prompt: str = None) -> str:
        """Call a chat API endpoint (supports both Ollama and OpenAI-compatible)"""
        import requests

        # Build messages array with system prompt for English enforcement
        messages = []

        # Add system message for English-only enforcement
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        else:
            # Default English-only enforcement
            messages.append({'role': 'system', 'content': 'IMPORTANT: You must respond ONLY in English. Never use Chinese, Spanish, or any other language. English only.'})

        # Add user message
        messages.append({'role': 'user', 'content': instruction})

        # Determine if this is Ollama or OpenAI-compatible endpoint
        if model.startswith('ollama:'):
            # Ollama endpoint
            actual_model = model.replace('ollama:', '', 1)
            url = f"{endpoint}/api/chat"
            payload = {
                'model': actual_model,
                'messages': messages,
                'stream': False
            }
        else:
            # OpenAI-compatible endpoint (llama.cpp, etc.)
            url = f"{endpoint}/chat/completions"
            payload = {
                'model': model,
                'messages': messages
            }

        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()

        data = response.json()

        # Handle different response formats
        if 'message' in data and 'content' in data['message']:
            # Ollama format
            return data['message']['content']
        elif 'choices' in data and len(data['choices']) > 0:
            # OpenAI format
            return data['choices'][0]['message']['content']

    async def _call_chat_api_streaming(self, instruction: str, endpoint: str, model: str):
        """
        Call a chat API endpoint with streaming support.
        Yields chunks of the response as they arrive.

        Args:
            instruction: The prompt/instruction
            endpoint: API endpoint URL
            model: Model identifier

        Yields:
            dict: Chunks with 'type', 'content', and optional metadata
        """
        import requests
        import json as json_lib

        # Determine if this is Ollama or OpenAI-compatible endpoint
        if model.startswith('ollama:'):
            # Ollama endpoint
            actual_model = model.replace('ollama:', '', 1)
            url = f"{endpoint}/api/chat"
            payload = {
                'model': actual_model,
                'messages': [{'role': 'user', 'content': instruction}],
                'stream': True
            }
        else:
            # OpenAI-compatible endpoint (llama.cpp, etc.)
            url = f"{endpoint}/chat/completions"
            payload = {
                'model': model,
                'messages': [{'role': 'user', 'content': instruction}],
                'stream': True
            }

        try:
            response = requests.post(url, json=payload, timeout=120, stream=True)
            response.raise_for_status()

            # Process streaming response
            for line in response.iter_lines():
                if not line:
                    continue

                line = line.decode('utf-8')

                # Handle SSE format (OpenAI-compatible)
                if line.startswith('data: '):
                    line = line[6:]  # Remove 'data: ' prefix

                if line == '[DONE]':
                    yield {'type': 'done', 'content': ''}
                    break

                try:
                    data = json_lib.loads(line)

                    # Handle different response formats
                    if 'message' in data and 'content' in data['message']:
                        # Ollama format
                        content = data['message'].get('content', '')
                        if content:
                            yield {'type': 'chunk', 'content': content}

                        if data.get('done', False):
                            yield {'type': 'done', 'content': ''}
                            break

                    elif 'choices' in data and len(data['choices']) > 0:
                        # OpenAI format
                        delta = data['choices'][0].get('delta', {})
                        content = delta.get('content', '')

                        if content:
                            yield {'type': 'chunk', 'content': content}

                        # Check if this is the final chunk
                        if data['choices'][0].get('finish_reason'):
                            yield {'type': 'done', 'content': ''}
                            break

                except json_lib.JSONDecodeError:
                    # Skip malformed JSON
                    continue

        except Exception as e:
            yield {'type': 'error', 'content': str(e)}

    async def execute_task_streaming(self, instruction: str, conversation_id: str = None):
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
            agent_type = routing['agent']
            agent_config = routing['agent_config']

            # Track active task
            self.active_tasks[task_id] = {
                'instruction': instruction,
                'agent_type': agent_type.value,
                'status': 'running',
                'start_time': start_time
            }

            # Send start event with routing info
            yield {
                'type': 'start',
                'agent': agent_type.value,
                'agent_name': agent_config['name'],
                'routing': self._make_json_safe(routing),
                'task_id': task_id
            }

            full_response = ""

            # Stream response based on agent type
            if agent_config['model'] == 'enhanced_agent':
                # Enhanced agent doesn't support streaming yet, use regular execution
                from local_parakleon_agent import run_agent
                response = run_agent(instruction)
                yield {'type': 'chunk', 'content': response}
                full_response = response
                tools_used = ['enhanced_agent_tools']

            elif agent_config['model'] == 'external_api':
                # External LLM - use their streaming if available
                from external_llm import external_llm
                result = await external_llm.query_best_available(
                    prompt=instruction,
                    system_prompt="You are an expert consultant providing thoughtful, well-reasoned advice."
                )
                if result.get('available'):
                    # External APIs typically return complete responses
                    # Send as single chunk for now
                    yield {'type': 'chunk', 'content': result['response']}
                    full_response = result['response']
                    tools_used = [f"external_llm_{result['provider']}"]
                else:
                    raise Exception(result.get('error', 'External LLM unavailable'))

            else:
                # Use streaming chat API
                tools_used = []
                async for chunk in self._call_chat_api_streaming(
                    instruction,
                    agent_config['endpoint'],
                    agent_config['model']
                ):
                    if chunk['type'] == 'chunk':
                        full_response += chunk['content']
                        yield chunk
                    elif chunk['type'] == 'error':
                        raise Exception(chunk['content'])
                    elif chunk['type'] == 'done':
                        break

            execution_time = time.time() - start_time

            # Update task status
            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['execution_time'] = execution_time

            # Update agent stats
            if agent_type.value not in self.agent_stats:
                self.agent_stats[agent_type.value] = {
                    'tasks_completed': 0,
                    'total_time': 0,
                    'avg_time': 0
                }

            stats = self.agent_stats[agent_type.value]
            stats['tasks_completed'] += 1
            stats['total_time'] += execution_time
            stats['avg_time'] = stats['total_time'] / stats['tasks_completed']

            # Send completion event
            yield {
                'type': 'done',
                'execution_time': execution_time,
                'tools_used': tools_used,
                'response': full_response,
                'agent_used': agent_type.value,
                'agent_name': agent_config['name']
            }

        except Exception as e:
            execution_time = time.time() - start_time
            self.active_tasks[task_id]['status'] = 'error'
            yield {
                'type': 'error',
                'content': str(e),
                'execution_time': execution_time
            }

    async def vote_on_decision(self, question: str, options: List[str],
                              context: str = "", use_external: bool = True) -> Dict[str, Any]:
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
            prompt += f"{i+1}. {opt}\n"
        prompt += "\nChoose the best option and explain why."

        # Vote with external LLM if available and requested
        if use_external:
            try:
                from external_llm import external_llm

                if external_llm.is_available():
                    result = await external_llm.vote_on_decision(question, options, context)
                    votes['consultant'] = result['choice']
                    reasoning['consultant'] = result['reasoning']
            except Exception as e:
                print(f"External LLM vote failed: {e}")

        # Vote with local reasoner agent
        try:
            reasoner_config = self.agents[AgentType.REASONER]
            reasoner_system_prompt = "You are a reasoning expert. IMPORTANT: Always respond in English only. Analyze options carefully and provide clear reasoning."
            reasoner_response = await self._call_chat_api(
                prompt,
                reasoner_config['endpoint'],
                reasoner_config['model'],
                reasoner_system_prompt
            )

            # Parse response to find chosen option
            chosen = self._parse_choice_from_response(reasoner_response, options)
            votes['reasoner'] = chosen
            reasoning['reasoner'] = reasoner_response
        except Exception as e:
            print(f"Reasoner vote failed: {e}")

        # Tally votes
        if not votes:
            return {
                'choice': options[0],
                'votes': {},
                'reasoning': {},
                'consensus': 0.0,
                'final_reasoning': 'No agents available for voting, defaulting to first option'
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
        final_reasoning = "\n\n".join([
            f"**{agent.upper()}**: {reason[:200]}..."
            for agent, reason in reasoning.items()
        ])

        return {
            'choice': winner,
            'votes': votes,
            'reasoning': reasoning,
            'consensus': consensus,
            'final_reasoning': final_reasoning
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
            if f"{i+1}." in response or f"option {i+1}" in response_lower:
                return opt

        # Default to first option if can't parse
        return options[0]

    async def search_codebase_with_rag(self, query: str, n_results: int = 5) -> Dict[str, Any]:
        """Search codebase using RAG semantic search"""
        try:
            result = self.rag_memory.search_code(query, n_results=n_results)
            return result
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'results': []
            }

    async def create_task_plan(self, task: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Create a structured execution plan for a complex task"""
        try:
            # Initialize task planner if not already done
            if not self.task_planner:
                # Create a simple LLM client wrapper
                class SimpleLLMClient:
                    def __init__(self, agent_manager):
                        self.agent_manager = agent_manager

                    async def call(self, prompt, temperature=0.3, max_tokens=2000):
                        # Use the reasoner agent to create the plan
                        config = self.agent_manager.agents[AgentType.REASONER]
                        return await self.agent_manager._call_chat_api(
                            prompt, config['endpoint'], config['model']
                        )

                self.task_planner = TaskPlanner(SimpleLLMClient(self), str(self.project_root))

            plan = self.task_planner.create_plan(task, context)

            return {
                'success': True,
                'plan_id': plan.id,
                'goal': plan.goal,
                'steps': [step.to_dict() for step in plan.steps],
                'estimated_duration': plan.estimated_total_duration
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def execute_plan(self, plan_id: str, session_id: str) -> Dict[str, Any]:
        """Execute a created plan step by step"""
        try:
            plan = self.task_planner.load_plan(plan_id)
            if not plan:
                return {
                    'success': False,
                    'error': f'Plan {plan_id} not found'
                }

            result = self.plan_executor.execute_plan(plan, session_id)
            return {
                'success': result.get('success', True),
                **result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def delegate_to_agent(self, from_agent: str, to_agent: str, task: str,
                               context: Optional[Dict] = None, parent_task_id: str = None) -> Dict[str, Any]:
        """Delegate a task from one agent to another"""
        try:
            from tools.delegation_tools import DelegationPriority

            delegation = self.delegation_manager.delegate_task(
                from_agent=from_agent,
                to_agent=to_agent,
                task=task,
                context=context or {},
                parent_task_id=parent_task_id or str(uuid.uuid4()),
                priority=DelegationPriority.NORMAL
            )

            # Execute the delegation
            result = self.delegation_manager.execute_delegation(
                delegation.id,
                parent_task_id or str(uuid.uuid4())
            )

            return {
                'success': result.get('success', True),
                'delegation_id': delegation.id,
                **result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def collaborate_agents(self, agents: List[str], task: str,
                                session_id: str, coordinator: str = 'reasoner') -> Dict[str, Any]:
        """Have multiple agents collaborate on a task"""
        try:
            result = self.delegation_manager.collaborate(
                agents=agents,
                task=task,
                session_id=session_id,
                coordinator=coordinator
            )

            return {
                'success': result.get('success', True),
                **result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def execute_code_safely(self, code: str, language: str = 'python',
                                  timeout: int = 30) -> Dict[str, Any]:
        """Execute code in a safe sandbox environment"""
        try:
            if language == 'python':
                result = self.code_sandbox.execute_python(code, timeout=timeout)
            elif language == 'javascript':
                result = self.code_sandbox.execute_javascript(code, timeout=timeout)
            elif language == 'shell':
                result = self.code_sandbox.execute_shell(code, timeout=timeout)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported language: {language}'
                }

            return result
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_agent_metrics(self, agent_type: str, days: int = 30) -> Dict[str, Any]:
        """Get performance metrics for a specific agent"""
        try:
            metrics = self.evaluator.get_agent_metrics(agent_type, days=days)
            return {
                'success': True,
                **metrics
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

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
            'agents': self.agent_stats,
            'active_tasks': len([t for t in self.active_tasks.values() if t['status'] == 'running']),
            'total_tasks': len(self.active_tasks)
        }

    def get_available_agents(self) -> List[Dict[str, Any]]:
        """Get list of available agents with their capabilities"""
        return [
            {
                'type': agent_type.value,
                'name': config['name'],
                'capabilities': config['capabilities'],
                'speed': config['speed'],
                'quality': config['quality']
            }
            for agent_type, config in self.agents.items()
        ]


# Global instance for API use
agent_manager = AgentManager()


if __name__ == '__main__':
    # Test the agent manager
    import asyncio

    print("=" * 60)
    print("MULTI-AGENT COORDINATION SYSTEM TEST")
    print("=" * 60)
    print()

    # Test task classification
    test_cases = [
        "Write a Python function to calculate fibonacci numbers",
        "Search Wikipedia for quantum computing",
        "List all Python files in the current directory",
        "Explain how async/await works in JavaScript",
        "What is 2+2?",
        "Plan an implementation strategy for adding dark mode to the UI"
    ]

    print("TASK CLASSIFICATION TESTS:")
    print("-" * 60)
    for instruction in test_cases:
        classification = agent_manager.classify_task(instruction)
        routing = agent_manager.route_task(instruction)

        print(f"\nTask: {instruction[:50]}...")
        print(f"  Agent: {routing['agent'].value}")
        print(f"  Complexity: {classification['complexity'].value}")
        print(f"  Confidence: {classification['confidence']:.2f}")
        print(f"  Strategy: {routing['strategy']}")
        print(f"  Est. Time: {routing['estimated_time']}")

    print("\n" + "=" * 60)
    print("AVAILABLE AGENTS:")
    print("-" * 60)
    for agent in agent_manager.get_available_agents():
        print(f"\n{agent['name']} ({agent['type']})")
        print(f"  Speed: {agent['speed']}, Quality: {agent['quality']}")
        print(f"  Capabilities: {', '.join(agent['capabilities'])}")

    print("\n" + "=" * 60)
