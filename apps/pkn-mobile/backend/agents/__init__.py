"""
Agent Management Module
Provides multi-agent coordination and routing
"""

from .manager import AgentManager
from .classifier import TaskClassifier
from .types import AgentType, TaskComplexity, AgentMessage

# Modules (not classes, import as modules)
from . import local_parakleon_agent
from . import external_llm

# Create singleton manager instance
manager = AgentManager()

__all__ = [
    "AgentManager",
    "TaskClassifier",
    "AgentType",
    "TaskComplexity",
    "AgentMessage",
    "local_parakleon_agent",
    "external_llm",
    "manager",
]
