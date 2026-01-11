#!/usr/bin/env python3
"""
Split agent_manager.py into modular files
Creates: types.py, classifier.py, manager.py (simplified)
"""

import re
from pathlib import Path


def extract_section(content, start_pattern, end_pattern=None):
    """Extract a section of code between two patterns"""
    lines = content.split("\n")
    result = []
    in_section = False

    for line in lines:
        if re.search(start_pattern, line):
            in_section = True

        if in_section:
            result.append(line)

        if end_pattern and re.search(end_pattern, line):
            break

    return "\n".join(result)


def extract_class(content, class_name):
    """Extract a complete class definition"""
    lines = content.split("\n")
    result = []
    in_class = False
    indent_level = 0

    for line in lines:
        # Start of class
        if re.match(f"^class {class_name}", line):
            in_class = True
            indent_level = len(line) - len(line.lstrip())

        if in_class:
            result.append(line)

            # End of class (next class or unindented line that's not empty/comment)
            if line.strip() and not line.strip().startswith("#"):
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and len(result) > 1:
                    # Remove the last line (it's the next class/section)
                    result.pop()
                    break

    return "\n".join(result)


def extract_method(content, method_name, is_async=False):
    """Extract a method definition"""
    prefix = "async def" if is_async else "def"
    pattern = f"    {prefix} {method_name}"

    lines = content.split("\n")
    result = []
    in_method = False
    method_indent = 0

    for i, line in enumerate(lines):
        if pattern in line:
            in_method = True
            method_indent = len(line) - len(line.lstrip())
            result.append(line)
            continue

        if in_method:
            if line.strip():
                current_indent = len(line) - len(line.lstrip())
                # Method ended (found another method or class-level code)
                if current_indent <= method_indent:
                    break
            result.append(line)

    return "\n".join(result)


def main():
    # Paths
    manager_file = Path(
        "/home/gh0st/dvn/divine-workspace/apps/pkn/backend/agents/manager.py"
    )
    agents_dir = manager_file.parent

    print(f"📖 Reading {manager_file}")
    content = manager_file.read_text()

    # ==========================================
    # 1. Create types.py (Enums and dataclasses)
    # ==========================================

    print("📝 Creating types.py...")

    types_content = '''"""
Agent Types and Data Structures
Enums and dataclasses for multi-agent system
"""

import uuid
import time
from typing import Dict, Any
from enum import Enum


'''

    # Extract enums
    types_content += extract_class(content, "AgentType") + "\n\n\n"
    types_content += extract_class(content, "TaskComplexity") + "\n\n\n"
    types_content += extract_class(content, "AgentMessage") + "\n"

    types_file = agents_dir / "types.py"
    types_file.write_text(types_content)
    print(f"✅ Created {types_file} ({len(types_content.splitlines())} lines)")

    # ==========================================
    # 2. Create classifier.py (Task classification)
    # ==========================================

    print("📝 Creating classifier.py...")

    classifier_content = '''"""
Task Classification Module
Analyzes tasks and routes to appropriate agents
"""

from typing import Dict, Any
from .types import AgentType, TaskComplexity


class TaskClassifier:
    """Classifies tasks and determines appropriate agent routing"""

    def __init__(self):
        pass

'''

    # Extract classify_task method
    classify_method = extract_method(content, "classify_task")
    # Convert to class method (adjust indentation)
    classify_method = classify_method.replace(
        "    def classify_task", "    def classify"
    )
    classifier_content += classify_method + "\n\n"

    # Extract route_task method
    route_method = extract_method(content, "route_task")
    route_method = route_method.replace("    def route_task", "    def route")
    classifier_content += route_method + "\n"

    classifier_file = agents_dir / "classifier.py"
    classifier_file.write_text(classifier_content)
    print(
        f"✅ Created {classifier_file} ({len(classifier_content.splitlines())} lines)"
    )

    # ==========================================
    # 3. Create simplified manager.py
    # ==========================================

    print("📝 Creating simplified manager.py...")

    # Extract header and imports
    imports_end = content.find("class AgentType")
    imports_section = content[:imports_end]

    # Update imports
    imports_section = imports_section.replace(
        "from tools import", "from ..tools import"
    )

    manager_content = (
        imports_section
        + '''
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

'''
    )

    # Extract _init_agents method
    init_agents = extract_method(content, "_init_agents")
    manager_content += init_agents + "\n\n"

    # Extract tool-related methods
    manager_content += extract_method(content, "get_tools_for_agent") + "\n\n"
    manager_content += extract_method(content, "_get_tool_registry") + "\n\n"
    manager_content += extract_method(content, "_make_json_safe") + "\n\n"

    # Add delegation methods (reference classifier)
    manager_content += '''
    def classify_task(self, instruction: str) -> Dict[str, Any]:
        """Classify a task (delegates to classifier)"""
        return self.classifier.classify(instruction)

    def route_task(self, instruction: str, conversation_id: str = None) -> Dict[str, Any]:
        """Route a task to appropriate agent (delegates to classifier)"""
        return self.classifier.route(instruction, conversation_id)

'''

    # Extract async methods (keep in manager)
    manager_content += extract_method(content, "execute_task", is_async=True) + "\n\n"
    manager_content += (
        extract_method(content, "execute_task_streaming", is_async=True) + "\n\n"
    )
    manager_content += (
        extract_method(content, "vote_on_decision", is_async=True) + "\n\n"
    )
    manager_content += extract_method(content, "_parse_choice_from_response") + "\n\n"
    manager_content += (
        extract_method(content, "delegate_to_agent", is_async=True) + "\n\n"
    )
    manager_content += (
        extract_method(content, "collaborate_agents", is_async=True) + "\n\n"
    )

    # Extract metrics methods
    manager_content += extract_method(content, "get_agent_metrics") + "\n\n"
    manager_content += extract_method(content, "get_performance_report") + "\n\n"
    manager_content += extract_method(content, "get_agent_stats") + "\n\n"
    manager_content += extract_method(content, "get_available_agents") + "\n"

    # Backup old file
    backup_file = manager_file.with_suffix(".py.bak")
    manager_file.rename(backup_file)
    print(f"💾 Backed up original to {backup_file}")

    # Write new manager.py
    manager_file.write_text(manager_content)
    print(
        f"✅ Created simplified {manager_file} ({len(manager_content.splitlines())} lines)"
    )

    # ==========================================
    # Summary
    # ==========================================

    print("\n📊 Summary:")
    print(f"  Original:          {len(content.splitlines()):4d} lines")
    print(f"  types.py:          {len(types_content.splitlines()):4d} lines")
    print(f"  classifier.py:     {len(classifier_content.splitlines()):4d} lines")
    print(f"  manager.py (new):  {len(manager_content.splitlines()):4d} lines")
    print(
        f"  Total:             {len(types_content.splitlines()) + len(classifier_content.splitlines()) + len(manager_content.splitlines()):4d} lines"
    )
    print("\n✅ Agent manager split complete!")


if __name__ == "__main__":
    main()
