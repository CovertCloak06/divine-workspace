"""
Agent Management Module
Provides multi-agent coordination and routing
"""

from .manager import AgentManager
from .classifier import TaskClassifier, TRIGGERS
from .types import AgentType, TaskComplexity, AgentMessage
from .workflows import WorkflowManager, Scratchpad, WORKFLOWS, workflow_manager

# Modules (not classes, import as modules)
from . import local_parakleon_agent
from . import external_llm

# Create singleton manager instance
manager = AgentManager()

# Link workflow manager to agent manager
workflow_manager.agent_manager = manager

__all__ = [
    "AgentManager",
    "TaskClassifier",
    "AgentType",
    "TaskComplexity",
    "AgentMessage",
    "WorkflowManager",
    "Scratchpad",
    "WORKFLOWS",
    "TRIGGERS",
    "local_parakleon_agent",
    "external_llm",
    "manager",
    "workflow_manager",
]
