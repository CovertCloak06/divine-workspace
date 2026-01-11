"""
Agent Types and Data Structures
Enums and dataclasses for multi-agent system
"""

import uuid
import time
from typing import Dict, Any
from enum import Enum


class AgentType(Enum):
    """Types of specialized agents"""

    CODER = "coder"  # Code writing, debugging, refactoring
    REASONER = "reasoner"  # Planning, logic, problem solving
    RESEARCHER = "researcher"  # Web research, documentation lookup
    EXECUTOR = "executor"  # Command execution, system tasks
    GENERAL = "general"  # General conversation, simple Q&A
    CONSULTANT = "consultant"  # External LLM (Claude/GPT) for high-level decisions
    SECURITY = (
        "security"  # Cybersecurity, pentesting, vulnerability analysis (UNCENSORED)
    )
    VISION = (
        "vision"  # Vision/image analysis, UI understanding, screenshot analysis (LOCAL)
    )
    VISION_CLOUD = "vision_cloud"  # Cloud vision via Groq (FREE, fast, English-only)


class TaskComplexity(Enum):
    """Task complexity levels"""

    SIMPLE = "simple"  # Quick answers, basic operations
    MEDIUM = "medium"  # Requires some reasoning or tool use
    COMPLEX = "complex"  # Multi-step, requires multiple agents


class AgentMessage:
    """Message for agent-to-agent communication"""

    def __init__(
        self,
        from_agent: str,
        to_agent: str,
        task_id: str,
        content: Dict[str, Any],
        requires_response: bool = False,
    ):
        self.id = str(uuid.uuid4())
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.task_id = task_id
        self.content = content
        self.requires_response = requires_response
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "task_id": self.task_id,
            "content": self.content,
            "requires_response": self.requires_response,
            "timestamp": self.timestamp,
        }
