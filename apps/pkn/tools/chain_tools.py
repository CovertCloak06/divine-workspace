#!/usr/bin/env python3
"""
Tool Chaining System
Allows sequential and conditional execution of multiple tools
"""

import time
import json
import uuid
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class ChainStepType(Enum):
    """Types of steps in a tool chain"""
    TOOL_CALL = "tool_call"          # Call a tool
    CONDITION = "condition"          # Conditional branch
    LOOP = "loop"                    # Repeat steps
    TRANSFORM = "transform"          # Transform data
    AGGREGATE = "aggregate"          # Combine results


@dataclass
class ChainStep:
    """A single step in a tool chain"""
    id: str
    step_type: ChainStepType
    tool_name: Optional[str]          # For TOOL_CALL
    parameters: Dict[str, Any]
    condition: Optional[str]          # For CONDITION
    transform_func: Optional[str]     # For TRANSFORM
    save_as: str                      # Variable name to save result
    depends_on: List[str]             # Variable dependencies
    status: str = "pending"           # pending, completed, failed, skipped
    result: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['step_type'] = self.step_type.value
        return d


@dataclass
class ToolChain:
    """A chain of tool executions"""
    id: str
    name: str
    steps: List[ChainStep]
    description: str
    created_at: float
    variables: Dict[str, Any]          # Shared variables across steps
    status: str = "pending"
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['steps'] = [step.to_dict() for step in self.steps]
        return d


class ToolChainExecutor:
    """
    Executes chains of tool calls with data flow between steps.
    Supports:
    - Sequential execution
    - Variable substitution ($variable)
    - Conditional branches
    - Loops
    - Data transformation
    """

    def __init__(self, tool_registry: Dict[str, Callable]):
        """
        Initialize with a registry of available tools

        Args:
            tool_registry: Dict mapping tool names to callable functions
        """
        self.tool_registry = tool_registry
        self.active_chains = {}
        self.chain_history = []

    def create_chain(self, name: str, description: str = "") -> ToolChain:
        """Create a new tool chain"""

        chain = ToolChain(
            id=str(uuid.uuid4()),
            name=name,
            steps=[],
            description=description,
            created_at=time.time(),
            variables={}
        )

        self.active_chains[chain.id] = chain
        return chain

    def add_tool_step(self, chain: ToolChain, tool_name: str,
                      parameters: Dict[str, Any], save_as: str,
                      depends_on: List[str] = None) -> ChainStep:
        """Add a tool call step to the chain"""

        step = ChainStep(
            id=f"step_{len(chain.steps) + 1}",
            step_type=ChainStepType.TOOL_CALL,
            tool_name=tool_name,
            parameters=parameters,
            condition=None,
            transform_func=None,
            save_as=save_as,
            depends_on=depends_on or []
        )

        chain.steps.append(step)
        return step

    def add_condition_step(self, chain: ToolChain, condition: str,
                           true_steps: List[ChainStep],
                           false_steps: List[ChainStep] = None) -> ChainStep:
        """Add a conditional branch step"""

        step = ChainStep(
            id=f"step_{len(chain.steps) + 1}",
            step_type=ChainStepType.CONDITION,
            tool_name=None,
            parameters={
                'true_steps': [s.to_dict() for s in true_steps],
                'false_steps': [s.to_dict() for s in (false_steps or [])]
            },
            condition=condition,
            transform_func=None,
            save_as=f"condition_result_{len(chain.steps)}",
            depends_on=[]
        )

        chain.steps.append(step)
        return step

    def add_transform_step(self, chain: ToolChain, transform_func: str,
                           input_var: str, save_as: str) -> ChainStep:
        """Add a data transformation step"""

        step = ChainStep(
            id=f"step_{len(chain.steps) + 1}",
            step_type=ChainStepType.TRANSFORM,
            tool_name=None,
            parameters={'input': input_var},
            condition=None,
            transform_func=transform_func,
            save_as=save_as,
            depends_on=[input_var]
        )

        chain.steps.append(step)
        return step

    def execute_chain(self, chain: ToolChain) -> Dict[str, Any]:
        """Execute a complete tool chain"""

        chain.status = "in_progress"
        chain.started_at = time.time()

        results = {
            'chain_id': chain.id,
            'name': chain.name,
            'steps_completed': 0,
            'steps_failed': 0,
            'step_results': [],
            'final_variables': {},
            'success': False,
            'error': None
        }

        try:
            for step in chain.steps:
                # Execute step
                step_result = self._execute_step(step, chain)

                results['step_results'].append({
                    'step_id': step.id,
                    'type': step.step_type.value,
                    'status': step.status,
                    'result': step.result,
                    'error': step.error
                })

                if step.status == 'completed':
                    results['steps_completed'] += 1
                elif step.status == 'failed':
                    results['steps_failed'] += 1

                    # Abort on failure (could add retry logic here)
                    chain.status = "failed"
                    results['error'] = f"Step {step.id} failed: {step.error}"
                    break

            # Mark as complete if no failures
            if chain.status != "failed":
                chain.status = "completed"
                results['success'] = True

            chain.completed_at = time.time()
            results['final_variables'] = chain.variables.copy()

        except Exception as e:
            chain.status = "failed"
            results['error'] = str(e)

        finally:
            self.chain_history.append(results)

        return results

    def _execute_step(self, step: ChainStep, chain: ToolChain) -> Any:
        """Execute a single step in the chain"""

        step.status = "in_progress"

        try:
            if step.step_type == ChainStepType.TOOL_CALL:
                result = self._execute_tool_call(step, chain)

            elif step.step_type == ChainStepType.CONDITION:
                result = self._execute_condition(step, chain)

            elif step.step_type == ChainStepType.TRANSFORM:
                result = self._execute_transform(step, chain)

            elif step.step_type == ChainStepType.AGGREGATE:
                result = self._execute_aggregate(step, chain)

            else:
                raise ValueError(f"Unknown step type: {step.step_type}")

            # Save result to chain variables
            chain.variables[step.save_as] = result
            step.result = result
            step.status = "completed"

            return result

        except Exception as e:
            step.status = "failed"
            step.error = str(e)
            raise

    def _execute_tool_call(self, step: ChainStep, chain: ToolChain) -> Any:
        """Execute a tool call with parameter substitution"""

        # Get tool function
        tool_func = self.tool_registry.get(step.tool_name)
        if not tool_func:
            raise ValueError(f"Tool not found: {step.tool_name}")

        # Substitute variables in parameters
        params = self._substitute_variables(step.parameters, chain.variables)

        # Call tool
        result = tool_func(**params)

        return result

    def _execute_condition(self, step: ChainStep, chain: ToolChain) -> Any:
        """Execute a conditional branch"""

        # Evaluate condition
        condition_result = self._evaluate_condition(step.condition, chain.variables)

        # Execute appropriate branch
        if condition_result:
            branch_steps = step.parameters.get('true_steps', [])
        else:
            branch_steps = step.parameters.get('false_steps', [])

        # Execute branch steps
        branch_results = []
        for branch_step_data in branch_steps:
            # Reconstruct step
            branch_step = ChainStep(**branch_step_data)
            result = self._execute_step(branch_step, chain)
            branch_results.append(result)

        return {
            'condition_met': condition_result,
            'branch_results': branch_results
        }

    def _execute_transform(self, step: ChainStep, chain: ToolChain) -> Any:
        """Execute a data transformation"""

        # Get input data
        input_var = step.parameters.get('input')
        input_data = chain.variables.get(input_var)

        if input_data is None:
            raise ValueError(f"Input variable not found: {input_var}")

        # Apply transformation
        transform_name = step.transform_func

        if transform_name == 'to_json':
            return json.dumps(input_data, indent=2)

        elif transform_name == 'from_json':
            return json.loads(input_data)

        elif transform_name == 'to_list':
            return list(input_data) if not isinstance(input_data, list) else input_data

        elif transform_name == 'count':
            return len(input_data)

        elif transform_name == 'first':
            return input_data[0] if input_data else None

        elif transform_name == 'last':
            return input_data[-1] if input_data else None

        elif transform_name == 'join':
            separator = step.parameters.get('separator', ', ')
            return separator.join(str(item) for item in input_data)

        elif transform_name == 'split':
            separator = step.parameters.get('separator', ',')
            return input_data.split(separator)

        else:
            raise ValueError(f"Unknown transform: {transform_name}")

    def _execute_aggregate(self, step: ChainStep, chain: ToolChain) -> Any:
        """Aggregate results from multiple previous steps"""

        input_vars = step.parameters.get('inputs', [])
        results = []

        for var_name in input_vars:
            if var_name in chain.variables:
                results.append(chain.variables[var_name])

        aggregate_func = step.parameters.get('function', 'collect')

        if aggregate_func == 'collect':
            return results

        elif aggregate_func == 'concat':
            return ''.join(str(r) for r in results)

        elif aggregate_func == 'merge':
            # Merge dictionaries
            merged = {}
            for r in results:
                if isinstance(r, dict):
                    merged.update(r)
            return merged

        else:
            raise ValueError(f"Unknown aggregate function: {aggregate_func}")

    def _substitute_variables(self, params: Dict[str, Any],
                              variables: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute $variable references in parameters"""

        substituted = {}

        for key, value in params.items():
            if isinstance(value, str) and value.startswith('$'):
                # Variable reference
                var_name = value[1:]  # Remove $
                substituted[key] = variables.get(var_name)

            elif isinstance(value, dict):
                # Recursively substitute in nested dicts
                substituted[key] = self._substitute_variables(value, variables)

            elif isinstance(value, list):
                # Substitute in lists
                substituted[key] = [
                    variables.get(item[1:]) if isinstance(item, str) and item.startswith('$') else item
                    for item in value
                ]

            else:
                substituted[key] = value

        return substituted

    def _evaluate_condition(self, condition: str, variables: Dict[str, Any]) -> bool:
        """Evaluate a condition string"""

        # Simple condition evaluation (could be enhanced with proper parser)
        # Supports: $var == value, $var != value, $var exists, etc.

        condition = condition.strip()

        # Check for "exists" condition
        if ' exists' in condition:
            var_name = condition.replace('exists', '').strip().lstrip('$')
            return var_name in variables

        # Check for comparison operators
        for op in ['==', '!=', '>', '<', '>=', '<=']:
            if op in condition:
                left, right = condition.split(op, 1)
                left = left.strip()
                right = right.strip()

                # Substitute variables
                if left.startswith('$'):
                    left_val = variables.get(left[1:])
                else:
                    left_val = left

                if right.startswith('$'):
                    right_val = variables.get(right[1:])
                else:
                    # Try to parse as number or keep as string
                    try:
                        right_val = json.loads(right)
                    except:
                        right_val = right.strip('"\'')

                # Perform comparison
                if op == '==':
                    return left_val == right_val
                elif op == '!=':
                    return left_val != right_val
                elif op == '>':
                    return left_val > right_val
                elif op == '<':
                    return left_val < right_val
                elif op == '>=':
                    return left_val >= right_val
                elif op == '<=':
                    return left_val <= right_val

        return False

    def get_chain_template(self, name: str) -> Optional[ToolChain]:
        """Get a predefined chain template"""

        templates = {
            'code_analysis': self._create_code_analysis_chain(),
            'file_search_and_modify': self._create_file_search_modify_chain(),
            'research_and_summarize': self._create_research_summarize_chain()
        }

        return templates.get(name)

    def _create_code_analysis_chain(self) -> ToolChain:
        """Template: Analyze code in a project"""

        chain = self.create_chain(
            name="code_analysis",
            description="Search for code patterns, analyze them, and generate report"
        )

        # Step 1: Find files
        self.add_tool_step(
            chain,
            tool_name="file_tools.glob",
            parameters={'pattern': '*.py', 'path': '$project_root'},
            save_as="python_files"
        )

        # Step 2: Search for specific pattern
        self.add_tool_step(
            chain,
            tool_name="file_tools.grep",
            parameters={'pattern': '$search_pattern', 'files': '$python_files'},
            save_as="matches"
        )

        # Step 3: Count results
        self.add_transform_step(
            chain,
            transform_func="count",
            input_var="matches",
            save_as="match_count"
        )

        return chain

    def _create_file_search_modify_chain(self) -> ToolChain:
        """Template: Find files and apply modifications"""

        chain = self.create_chain(
            name="file_search_and_modify",
            description="Search for files matching criteria and modify them"
        )

        # Steps would be added based on specific use case
        return chain

    def _create_research_summarize_chain(self) -> ToolChain:
        """Template: Research topic and create summary"""

        chain = self.create_chain(
            name="research_and_summarize",
            description="Research a topic and generate summary document"
        )

        # Steps would be added based on specific use case
        return chain


# Example usage demonstration
if __name__ == "__main__":
    print("Tool Chaining System loaded successfully!")
    print("\nExample: Creating a chain to find TODO comments")

    # Mock tools for demonstration
    def mock_glob(pattern, path):
        return [f"{path}/file1.py", f"{path}/file2.py"]

    def mock_grep(pattern, files):
        return [
            {"file": files[0], "line": 10, "content": "# TODO: Fix this"},
            {"file": files[1], "line": 25, "content": "# TODO: Optimize"}
        ]

    def mock_write_file(path, content):
        return {"success": True, "path": path}

    # Create executor with mock tools
    tool_registry = {
        'file_tools.glob': mock_glob,
        'file_tools.grep': mock_grep,
        'file_tools.write_file': mock_write_file
    }

    executor = ToolChainExecutor(tool_registry)

    # Create chain
    chain = executor.create_chain(
        name="find_todos",
        description="Find all TODO comments and create summary"
    )

    # Set initial variables
    chain.variables = {
        'project_root': '/home/gh0st/pkn',
        'search_pattern': 'TODO'
    }

    # Add steps
    executor.add_tool_step(
        chain,
        tool_name="file_tools.glob",
        parameters={'pattern': '*.py', 'path': '$project_root'},
        save_as="python_files"
    )

    executor.add_tool_step(
        chain,
        tool_name="file_tools.grep",
        parameters={'pattern': '$search_pattern', 'files': '$python_files'},
        save_as="todo_matches"
    )

    executor.add_transform_step(
        chain,
        transform_func="count",
        input_var="todo_matches",
        save_as="todo_count"
    )

    # Execute chain
    print("\nExecuting chain...")
    result = executor.execute_chain(chain)

    print(f"\n✓ Chain completed: {result['name']}")
    print(f"  Steps completed: {result['steps_completed']}")
    print(f"  Success: {result['success']}")
    print(f"  Final variables: {list(result['final_variables'].keys())}")
