"""
Workflow Tools - Multi-Agent Coordination
Manage multi-agent workflows with defined agent chains.

Tools:
- start_workflow: Begin a multi-agent workflow
- next_workflow_step: Advance to next agent
- list_workflows: Show available workflows
- get_workflow_status: Check current workflow state
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from langchain_core.tools import tool


SCRATCHPAD_FILE = Path.home() / ".pkn_scratchpad.json"

# 12 predefined workflows with agent chains
WORKFLOWS = {
    "new-feature": {
        "name": "New Feature",
        "description": "Plan, implement, test, review, and document a new feature",
        "agents": ["architect", "test-writer", "code-reviewer", "docs-writer"],
    },
    "bug-fix": {
        "name": "Bug Fix",
        "description": "Debug, fix, add regression test, and review",
        "agents": ["debugger", "test-writer", "code-reviewer"],
    },
    "security-review": {
        "name": "Security Review",
        "description": "Security audit followed by code review",
        "agents": ["security-auditor", "code-reviewer"],
    },
    "refactor": {
        "name": "Refactor",
        "description": "Plan refactoring, execute, test, and review",
        "agents": ["architect", "refactorer", "test-writer", "code-reviewer"],
    },
    "api-integration": {
        "name": "API Integration",
        "description": "Plan, integrate, security check, and document",
        "agents": ["architect", "tool-integrator", "security-auditor", "docs-writer"],
    },
    "performance": {
        "name": "Performance Optimization",
        "description": "Analyze performance, optimize, and test",
        "agents": ["performance-analyzer", "refactorer", "test-writer"],
    },
    "full-review": {
        "name": "Full Code Review",
        "description": "Comprehensive review: code, security, performance, accessibility",
        "agents": ["code-reviewer", "security-auditor", "performance-analyzer", "accessibility-checker"],
    },
    "api-design": {
        "name": "API Design",
        "description": "Design API, security review, and document",
        "agents": ["api-designer", "security-auditor", "docs-writer"],
    },
    "dependency-update": {
        "name": "Dependency Update",
        "description": "Audit dependencies, test, and review",
        "agents": ["dependency-auditor", "test-writer", "code-reviewer"],
    },
    "migration": {
        "name": "Migration",
        "description": "Plan migration, execute, test, and review",
        "agents": ["migration-expert", "test-writer", "code-reviewer"],
    },
    "git-cleanup": {
        "name": "Git Cleanup",
        "description": "Clean up git history and review",
        "agents": ["git-expert", "code-reviewer"],
    },
    "i18n-setup": {
        "name": "Internationalization Setup",
        "description": "Set up i18n, test, and document",
        "agents": ["i18n-expert", "test-writer", "docs-writer"],
    },
}


def _load_scratchpad() -> Dict[str, Any]:
    """Load scratchpad data"""
    if not SCRATCHPAD_FILE.exists():
        return {"entries": {}, "workflow": None}
    try:
        return json.loads(SCRATCHPAD_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"entries": {}, "workflow": None}


def _save_scratchpad(data: Dict[str, Any]) -> None:
    """Save scratchpad data"""
    SCRATCHPAD_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCRATCHPAD_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@tool
def start_workflow(name: str, task: str) -> str:
    """
    Start a multi-agent workflow.

    Workflows chain multiple specialized agents together for complex tasks.
    Each agent passes findings to the next via the scratchpad.

    Args:
        name: Workflow name (new-feature, bug-fix, security-review, etc.)
        task: Description of what you're working on

    Returns:
        Instructions for the first agent in the workflow

    Examples:
        start_workflow("bug-fix", "Login fails with invalid token error")
        start_workflow("new-feature", "Add dark mode toggle to settings")
        start_workflow("security-review", "Audit the authentication module")

    Available workflows:
        - new-feature: architect → test-writer → code-reviewer → docs-writer
        - bug-fix: debugger → test-writer → code-reviewer
        - security-review: security-auditor → code-reviewer
        - refactor: architect → refactorer → test-writer → code-reviewer
        - api-integration: architect → tool-integrator → security-auditor → docs-writer
        - performance: performance-analyzer → refactorer → test-writer
        - full-review: code-reviewer → security-auditor → performance-analyzer → accessibility-checker
        - api-design: api-designer → security-auditor → docs-writer
        - dependency-update: dependency-auditor → test-writer → code-reviewer
        - migration: migration-expert → test-writer → code-reviewer
        - git-cleanup: git-expert → code-reviewer
        - i18n-setup: i18n-expert → test-writer → docs-writer
    """
    try:
        if name not in WORKFLOWS:
            available = ", ".join(WORKFLOWS.keys())
            return f"Unknown workflow '{name}'. Available: {available}"

        workflow = WORKFLOWS[name]
        first_agent = workflow["agents"][0]

        # Save workflow state to scratchpad
        data = _load_scratchpad()
        data["workflow"] = {
            "name": name,
            "task": task,
            "step": 0,
            "agents": workflow["agents"],
            "started": datetime.now().isoformat(),
        }
        data["entries"]["workflow_task"] = {
            "content": task,
            "timestamp": datetime.now().isoformat(),
        }
        _save_scratchpad(data)

        agent_chain = " → ".join(workflow["agents"])
        return f"""Workflow '{workflow['name']}' started!

Task: {task}

Agent chain: {agent_chain}

Current step: 1/{len(workflow['agents'])} - {first_agent}

Instructions for {first_agent}:
1. Review the task above
2. Perform your specialized analysis/work
3. Save key findings with scratchpad_write()
4. When done, call next_workflow_step() to pass to the next agent"""

    except Exception as e:
        return f"Error starting workflow: {e}"


@tool
def next_workflow_step() -> str:
    """
    Advance to the next agent in the active workflow.

    Call this when you've completed your part of the workflow
    and saved your findings to the scratchpad.

    Returns:
        Instructions for the next agent, or completion message

    Examples:
        next_workflow_step()  # After completing current step
    """
    try:
        data = _load_scratchpad()
        workflow = data.get("workflow")

        if not workflow:
            return "No active workflow. Use start_workflow() to begin one."

        current_step = workflow.get("step", 0)
        agents = workflow.get("agents", [])
        total_steps = len(agents)

        # Move to next step
        next_step = current_step + 1

        if next_step >= total_steps:
            # Workflow complete
            task = workflow.get("task", "Unknown task")
            name = workflow.get("name", "Unknown")

            # Clear workflow state but keep findings
            data["workflow"] = None
            _save_scratchpad(data)

            return f"""Workflow '{name}' COMPLETE!

Task: {task}
Steps completed: {total_steps}
Agent chain: {' → '.join(agents)} ✓

All findings saved in scratchpad. Use scratchpad_read() to review.
Use scratchpad_clear() when done to reset for next workflow."""

        # Update to next step
        next_agent = agents[next_step]
        workflow["step"] = next_step
        data["workflow"] = workflow
        _save_scratchpad(data)

        return f"""Advancing workflow...

Step {next_step + 1}/{total_steps} - {next_agent}

Task: {workflow.get('task')}
Previous agents: {' → '.join(agents[:next_step])} ✓

Instructions for {next_agent}:
1. Read previous findings: scratchpad_read()
2. Perform your specialized analysis/work
3. Add your findings: scratchpad_write("your_key", "your findings")
4. When done: next_workflow_step()"""

    except Exception as e:
        return f"Error advancing workflow: {e}"


@tool
def list_workflows() -> str:
    """
    List all available multi-agent workflows.

    Shows workflow names, descriptions, and agent chains
    to help choose the right workflow for your task.

    Returns:
        Formatted list of available workflows

    Examples:
        list_workflows()  # See all options
    """
    try:
        result = ["Available Workflows:", "=" * 50]

        for key, wf in WORKFLOWS.items():
            agents = " → ".join(wf["agents"])
            result.append(f"\n{key}:")
            result.append(f"  {wf['description']}")
            result.append(f"  Agents: {agents}")

        result.append("\n" + "=" * 50)
        result.append("Usage: start_workflow('workflow-name', 'your task description')")

        return "\n".join(result)
    except Exception as e:
        return f"Error listing workflows: {e}"


@tool
def get_workflow_status() -> str:
    """
    Check the current workflow state.

    Shows active workflow, current step, and progress.

    Returns:
        Current workflow status or message if none active

    Examples:
        get_workflow_status()  # Check where we are
    """
    try:
        data = _load_scratchpad()
        workflow = data.get("workflow")

        if not workflow:
            return "No active workflow. Use start_workflow() to begin one."

        name = workflow.get("name", "Unknown")
        task = workflow.get("task", "Unknown")
        step = workflow.get("step", 0)
        agents = workflow.get("agents", [])
        started = workflow.get("started", "Unknown")

        current_agent = agents[step] if step < len(agents) else "Complete"

        # Show progress
        progress = []
        for i, agent in enumerate(agents):
            if i < step:
                progress.append(f"  ✓ {agent}")
            elif i == step:
                progress.append(f"  → {agent} (current)")
            else:
                progress.append(f"    {agent}")

        return f"""Workflow Status
==============
Name: {name}
Task: {task}
Started: {started}
Progress: {step + 1}/{len(agents)}

Steps:
{chr(10).join(progress)}

Next action: Complete {current_agent}'s work, then call next_workflow_step()"""

    except Exception as e:
        return f"Error getting workflow status: {e}"


# Export tools for registration
TOOLS = [start_workflow, next_workflow_step, list_workflows, get_workflow_status]

TOOL_DESCRIPTIONS = {
    "start_workflow": "Start a multi-agent workflow (new-feature, bug-fix, etc.)",
    "next_workflow_step": "Advance to next agent in active workflow",
    "list_workflows": "List all available workflows",
    "get_workflow_status": "Check current workflow state",
}
