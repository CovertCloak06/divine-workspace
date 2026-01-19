"""
Workflow System for Multi-Agent Chaining
Orchestrates sequences of agents for complex tasks
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from .types import AgentType

# === WORKFLOW DEFINITIONS ===
WORKFLOWS: Dict[str, List[AgentType]] = {
    # Development workflows
    "new-feature": [
        AgentType.REASONER,      # Plan the feature
        AgentType.CODER,         # Implement it
        AgentType.TESTER,        # Write tests
        AgentType.REVIEWER,      # Code review
        AgentType.DOCS_WRITER,   # Document it
    ],
    "bug-fix": [
        AgentType.CODER,         # Debug and find root cause
        AgentType.CODER,         # Fix the bug
        AgentType.TESTER,        # Write regression test
        AgentType.REVIEWER,      # Review the fix
    ],
    "refactor": [
        AgentType.REASONER,      # Plan refactor approach
        AgentType.REFACTORER,    # Execute refactor
        AgentType.TESTER,        # Ensure tests pass
        AgentType.REVIEWER,      # Review changes
    ],

    # Quality workflows
    "security-review": [
        AgentType.SECURITY,      # Security audit
        AgentType.REVIEWER,      # Code review
    ],
    "full-review": [
        AgentType.REVIEWER,      # Code quality
        AgentType.SECURITY,      # Security check
        AgentType.PERF_ANALYZER, # Performance check
        AgentType.A11Y,          # Accessibility check
    ],
    "performance": [
        AgentType.PERF_ANALYZER, # Identify bottlenecks
        AgentType.REFACTORER,    # Optimize code
        AgentType.TESTER,        # Benchmark tests
    ],

    # API workflows
    "api-design": [
        AgentType.API_DESIGNER,  # Design endpoints
        AgentType.SECURITY,      # Security review
        AgentType.DOCS_WRITER,   # API documentation
    ],
    "api-integration": [
        AgentType.REASONER,      # Plan integration
        AgentType.INTEGRATOR,    # Implement connection
        AgentType.SECURITY,      # Security check
        AgentType.DOCS_WRITER,   # Document usage
    ],

    # Infrastructure workflows
    "deployment": [
        AgentType.DEVOPS,        # Setup CI/CD
        AgentType.SECURITY,      # Security scan
        AgentType.DOCS_WRITER,   # Deployment docs
    ],
    "dependency-update": [
        AgentType.DEPS_AUDITOR,  # Audit dependencies
        AgentType.TESTER,        # Run tests
        AgentType.REVIEWER,      # Review changes
    ],
    "migration": [
        AgentType.MIGRATOR,      # Plan migration
        AgentType.TESTER,        # Test migration
        AgentType.REVIEWER,      # Review changes
    ],

    # Git workflows
    "git-cleanup": [
        AgentType.GIT_EXPERT,    # Git operations
        AgentType.REVIEWER,      # Review history
    ],

    # i18n workflow
    "i18n-setup": [
        AgentType.I18N,          # Setup internationalization
        AgentType.TESTER,        # Test translations
        AgentType.DOCS_WRITER,   # Document i18n process
    ],

    # Frontend workflows
    "ui-component": [
        AgentType.UI_DESIGNER,   # Design component
        AgentType.CODER,         # Implement
        AgentType.CSS_WIZARD,    # Style it
        AgentType.A11Y,          # Accessibility
        AgentType.TESTER,        # Tests
    ],
    "mobile-optimize": [
        AgentType.MOBILE_UI,     # Mobile-specific fixes
        AgentType.PERF_ANALYZER, # Performance
        AgentType.A11Y,          # Touch accessibility
    ],
}


class Scratchpad:
    """
    Shared context between agents in a workflow.
    Allows agents to pass findings to subsequent agents.
    """

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._workflow_state: Optional[Dict[str, Any]] = None

    def write(self, key: str, content: str, agent: str = "unknown") -> None:
        """Save content to scratchpad with metadata."""
        self._data[key] = {
            "content": content,
            "agent": agent,
            "timestamp": datetime.now().isoformat(),
        }

    def read(self, key: str = "") -> Optional[Dict[str, Any]]:
        """Read from scratchpad. Empty key returns all entries."""
        if not key:
            return {k: v for k, v in self._data.items() if not k.startswith("_")}
        return self._data.get(key)

    def clear(self) -> None:
        """Clear all scratchpad data."""
        self._data.clear()
        self._workflow_state = None

    def get_context_for_agent(self) -> str:
        """Get formatted context string for the next agent."""
        if not self._data:
            return ""

        lines = ["## Context from previous agents:\n"]
        for key, entry in self._data.items():
            if not key.startswith("_"):
                lines.append(f"### {key} (from {entry['agent']}):")
                lines.append(entry["content"][:500])  # Truncate long content
                lines.append("")
        return "\n".join(lines)

    def set_workflow_state(self, state: Dict[str, Any]) -> None:
        """Store active workflow state."""
        self._workflow_state = state

    def get_workflow_state(self) -> Optional[Dict[str, Any]]:
        """Get active workflow state."""
        return self._workflow_state


class WorkflowManager:
    """Manages multi-agent workflow execution."""

    def __init__(self, agent_manager=None):
        self.agent_manager = agent_manager
        self.scratchpad = Scratchpad()
        self.workflows = WORKFLOWS
        self.active_workflow: Optional[Dict[str, Any]] = None

    def list_workflows(self) -> Dict[str, List[str]]:
        """List all available workflows with their agent sequences."""
        return {
            name: [agent.value for agent in agents]
            for name, agents in self.workflows.items()
        }

    def start_workflow(self, workflow_name: str, task: str) -> Dict[str, Any]:
        """
        Start a new workflow.

        Returns the first agent to execute and workflow metadata.
        """
        if workflow_name not in self.workflows:
            return {
                "error": f"Unknown workflow: {workflow_name}",
                "available": list(self.workflows.keys()),
            }

        agents = self.workflows[workflow_name]
        self.active_workflow = {
            "name": workflow_name,
            "task": task,
            "agents": agents,
            "current_step": 0,
            "total_steps": len(agents),
            "started_at": datetime.now().isoformat(),
            "results": [],
        }
        self.scratchpad.set_workflow_state(self.active_workflow)
        self.scratchpad.clear()

        first_agent = agents[0]
        return {
            "workflow": workflow_name,
            "task": task,
            "current_step": 1,
            "total_steps": len(agents),
            "current_agent": first_agent.value,
            "agent_sequence": [a.value for a in agents],
            "status": "started",
        }

    def get_current_step(self) -> Optional[Dict[str, Any]]:
        """Get the current workflow step details."""
        if not self.active_workflow:
            return None

        step = self.active_workflow["current_step"]
        agents = self.active_workflow["agents"]

        if step >= len(agents):
            return {"status": "completed"}

        return {
            "step": step + 1,
            "total": len(agents),
            "agent": agents[step].value,
            "task": self.active_workflow["task"],
            "context": self.scratchpad.get_context_for_agent(),
        }

    def complete_step(self, result: str, agent_name: str = "") -> Dict[str, Any]:
        """
        Mark current step as complete and advance to next agent.

        Args:
            result: The output/findings from the current agent
            agent_name: Name of the agent that completed (for logging)
        """
        if not self.active_workflow:
            return {"error": "No active workflow"}

        step = self.active_workflow["current_step"]
        agents = self.active_workflow["agents"]

        # Save result to scratchpad
        agent = agents[step] if step < len(agents) else AgentType.GENERAL
        self.scratchpad.write(
            key=f"step_{step + 1}_{agent.value}",
            content=result,
            agent=agent_name or agent.value,
        )

        # Store result
        self.active_workflow["results"].append({
            "step": step + 1,
            "agent": agent.value,
            "result": result[:1000],  # Truncate for storage
            "completed_at": datetime.now().isoformat(),
        })

        # Advance to next step
        self.active_workflow["current_step"] = step + 1

        # Check if workflow is complete
        if step + 1 >= len(agents):
            return self._complete_workflow()

        # Return next agent info
        next_agent = agents[step + 1]
        return {
            "status": "advancing",
            "completed_step": step + 1,
            "next_step": step + 2,
            "total_steps": len(agents),
            "next_agent": next_agent.value,
            "context": self.scratchpad.get_context_for_agent(),
        }

    def _complete_workflow(self) -> Dict[str, Any]:
        """Finalize and return workflow results."""
        workflow = self.active_workflow
        summary = {
            "status": "completed",
            "workflow": workflow["name"],
            "task": workflow["task"],
            "total_steps": workflow["total_steps"],
            "started_at": workflow["started_at"],
            "completed_at": datetime.now().isoformat(),
            "results": workflow["results"],
            "scratchpad": self.scratchpad.read(),
        }

        # Clear active workflow
        self.active_workflow = None
        self.scratchpad.clear()

        return summary

    def cancel_workflow(self) -> Dict[str, Any]:
        """Cancel the active workflow."""
        if not self.active_workflow:
            return {"error": "No active workflow to cancel"}

        name = self.active_workflow["name"]
        step = self.active_workflow["current_step"]

        self.active_workflow = None
        self.scratchpad.clear()

        return {
            "status": "cancelled",
            "workflow": name,
            "cancelled_at_step": step + 1,
        }

    def get_workflow_status(self) -> Dict[str, Any]:
        """Get status of the active workflow."""
        if not self.active_workflow:
            return {"status": "idle", "active_workflow": None}

        return {
            "status": "active",
            "workflow": self.active_workflow["name"],
            "task": self.active_workflow["task"],
            "current_step": self.active_workflow["current_step"] + 1,
            "total_steps": self.active_workflow["total_steps"],
            "current_agent": (
                self.active_workflow["agents"][self.active_workflow["current_step"]].value
                if self.active_workflow["current_step"] < len(self.active_workflow["agents"])
                else "completed"
            ),
            "results_so_far": len(self.active_workflow["results"]),
        }


# Singleton instance
workflow_manager = WorkflowManager()
