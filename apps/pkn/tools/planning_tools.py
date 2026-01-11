#!/usr/bin/env python3
"""
Planning and Execution Separation System
Breaks complex tasks into structured plans before execution
"""

import json
import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class StepStatus(Enum):
    """Status of a plan step"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepPriority(Enum):
    """Priority levels for steps"""
    CRITICAL = "critical"      # Must succeed for plan to continue
    HIGH = "high"              # Important but not blocking
    MEDIUM = "medium"          # Nice to have
    LOW = "low"                # Optional


@dataclass
class PlanStep:
    """Individual step in an execution plan"""
    id: str
    action: str
    agent_type: str
    tools_required: List[str]
    depends_on: List[str]  # IDs of steps that must complete first
    priority: StepPriority
    estimated_duration: int  # seconds
    status: StepStatus = StepStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    actual_duration: Optional[int] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['priority'] = self.priority.value
        d['status'] = self.status.value
        return d


@dataclass
class ExecutionPlan:
    """Complete execution plan for a task"""
    id: str
    task: str
    goal: str
    steps: List[PlanStep]
    required_agents: List[str]
    required_tools: List[str]
    expected_output: str
    risks: List[str]
    estimated_total_duration: int
    created_at: float
    status: str = "pending"
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['steps'] = [step.to_dict() for step in self.steps]
        return d


class TaskPlanner:
    """
    Creates structured execution plans for complex tasks.
    Uses the Reasoner agent to break down tasks into actionable steps.
    """

    def __init__(self, llm_client, project_root: str = "/home/gh0st/pkn"):
        self.llm_client = llm_client
        self.project_root = Path(project_root)
        self.plans_dir = self.project_root / "memory" / "plans"
        self.plans_dir.mkdir(parents=True, exist_ok=True)

    def create_plan(self, task: str, context: Optional[Dict] = None) -> ExecutionPlan:
        """Create a detailed execution plan for a task"""

        # Build planning prompt
        plan_prompt = self._build_planning_prompt(task, context)

        # Call LLM to create plan
        response = self.llm_client.call(
            prompt=plan_prompt,
            temperature=0.3,  # Lower temp for structured planning
            max_tokens=2000
        )

        # Parse the structured plan
        plan_data = self._parse_plan_response(response, task)

        # Create ExecutionPlan object
        plan = ExecutionPlan(
            id=str(uuid.uuid4()),
            task=task,
            goal=plan_data['goal'],
            steps=plan_data['steps'],
            required_agents=plan_data['required_agents'],
            required_tools=plan_data['required_tools'],
            expected_output=plan_data['expected_output'],
            risks=plan_data['risks'],
            estimated_total_duration=plan_data.get('estimated_total_duration', plan_data.get('estimated_duration', 60)),
            created_at=time.time()
        )

        # Save plan
        self._save_plan(plan)

        return plan

    def _build_planning_prompt(self, task: str, context: Optional[Dict]) -> str:
        """Build the prompt for plan generation"""

        context_str = ""
        if context:
            context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"

        return f"""You are a task planning expert. Create a detailed execution plan for this task.

Task: {task}{context_str}

Create a structured plan with:

1. GOAL: Clear statement of what needs to be achieved

2. STEPS: Numbered list of specific actions
   For each step, specify:
   - Action: What to do
   - Agent: Which agent (coder/reasoner/researcher/executor/general)
   - Tools: Which tools are needed (e.g., file_tools.read_file, web_tools.search)
   - Priority: critical/high/medium/low
   - Estimated time: in seconds
   - Dependencies: Which previous steps must complete first (by step number)

3. REQUIRED_AGENTS: List all agents needed

4. REQUIRED_TOOLS: List all tools needed

5. EXPECTED_OUTPUT: Description of successful completion

6. RISKS: Potential issues to watch for

Format your response as JSON:
{{
  "goal": "...",
  "steps": [
    {{
      "action": "...",
      "agent": "coder",
      "tools": ["file_tools.read_file"],
      "priority": "critical",
      "estimated_duration": 30,
      "depends_on": []
    }}
  ],
  "required_agents": ["coder", "reasoner"],
  "required_tools": ["file_tools", "code_tools"],
  "expected_output": "...",
  "risks": ["..."],
  "estimated_total_duration": 120
}}

Plan:"""

    def _parse_plan_response(self, response: str, task: str) -> Dict:
        """Parse LLM response into structured plan data"""

        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                plan_data = json.loads(json_str)
            else:
                # Fallback: parse text format
                plan_data = self._parse_text_plan(response)

            # Convert steps to PlanStep objects
            steps = []
            for i, step_data in enumerate(plan_data.get('steps', [])):
                step = PlanStep(
                    id=f"step_{i+1}",
                    action=step_data.get('action', ''),
                    agent_type=step_data.get('agent', 'general'),
                    tools_required=step_data.get('tools', []),
                    depends_on=[f"step_{d}" for d in step_data.get('depends_on', [])],
                    priority=StepPriority(step_data.get('priority', 'medium')),
                    estimated_duration=step_data.get('estimated_duration', 30)
                )
                steps.append(step)

            plan_data['steps'] = steps

            # Ensure required fields exist
            if 'estimated_total_duration' not in plan_data:
                plan_data['estimated_total_duration'] = plan_data.get('estimated_duration', 60)

            return plan_data

        except Exception as e:
            # Fallback to basic plan
            return self._create_fallback_plan(task, str(e))

    def _parse_text_plan(self, text: str) -> Dict:
        """Parse text-format plan (fallback)"""

        # Simple text parsing
        lines = text.split('\n')
        plan = {
            'goal': '',
            'steps': [],
            'required_agents': ['general'],
            'required_tools': [],
            'expected_output': '',
            'risks': [],
            'estimated_total_duration': 60
        }

        current_section = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if 'GOAL:' in line.upper():
                current_section = 'goal'
                plan['goal'] = line.split(':', 1)[1].strip() if ':' in line else ''
            elif 'STEP' in line.upper() and (':' in line or '.' in line):
                action = line.split(':', 1)[1].strip() if ':' in line else line
                plan['steps'].append({
                    'action': action,
                    'agent': 'general',
                    'tools': [],
                    'priority': 'medium',
                    'estimated_duration': 30,
                    'depends_on': []
                })

        return plan

    def _create_fallback_plan(self, task: str, error: str) -> Dict:
        """Create a simple fallback plan if parsing fails"""

        return {
            'goal': f'Complete task: {task}',
            'steps': [
                {
                    'action': task,
                    'agent': 'general',
                    'tools': [],
                    'priority': 'critical',
                    'estimated_duration': 60,
                    'depends_on': []
                }
            ],
            'required_agents': ['general'],
            'required_tools': [],
            'expected_output': 'Task completed',
            'risks': [f'Plan parsing failed: {error}'],
            'estimated_total_duration': 60
        }

    def _save_plan(self, plan: ExecutionPlan):
        """Save plan to disk"""

        plan_file = self.plans_dir / f"plan_{plan.id}.json"
        with open(plan_file, 'w') as f:
            json.dump(plan.to_dict(), f, indent=2)

    def load_plan(self, plan_id: str) -> Optional[ExecutionPlan]:
        """Load a saved plan"""

        plan_file = self.plans_dir / f"plan_{plan_id}.json"
        if not plan_file.exists():
            return None

        with open(plan_file, 'r') as f:
            data = json.load(f)

        # Reconstruct PlanStep objects
        steps = []
        for step_data in data['steps']:
            step = PlanStep(
                id=step_data['id'],
                action=step_data['action'],
                agent_type=step_data['agent_type'],
                tools_required=step_data['tools_required'],
                depends_on=step_data['depends_on'],
                priority=StepPriority(step_data['priority']),
                estimated_duration=step_data['estimated_duration'],
                status=StepStatus(step_data['status']),
                result=step_data.get('result'),
                error=step_data.get('error'),
                actual_duration=step_data.get('actual_duration')
            )
            steps.append(step)

        data['steps'] = steps
        return ExecutionPlan(**data)


class PlanExecutor:
    """
    Executes structured plans step-by-step.
    Handles dependencies, error recovery, and progress tracking.
    """

    def __init__(self, agent_manager):
        self.agent_manager = agent_manager
        self.active_plans = {}

    def execute_plan(self, plan: ExecutionPlan, session_id: str) -> Dict[str, Any]:
        """Execute a plan step by step"""

        self.active_plans[plan.id] = plan
        plan.status = "in_progress"
        plan.started_at = time.time()

        results = {
            'plan_id': plan.id,
            'task': plan.task,
            'steps_completed': 0,
            'steps_failed': 0,
            'step_results': [],
            'success': False,
            'error': None
        }

        try:
            # Execute steps in order, respecting dependencies
            for step in plan.steps:
                # Check if dependencies are met
                if not self._dependencies_met(step, plan):
                    step.status = StepStatus.SKIPPED
                    results['step_results'].append({
                        'step_id': step.id,
                        'status': 'skipped',
                        'reason': 'Dependencies not met'
                    })
                    continue

                # Execute step
                step_result = self._execute_step(step, session_id, plan)

                results['step_results'].append(step_result)

                if step_result['status'] == 'completed':
                    results['steps_completed'] += 1
                elif step_result['status'] == 'failed':
                    results['steps_failed'] += 1

                    # If critical step fails, abort plan
                    if step.priority == StepPriority.CRITICAL:
                        results['error'] = f"Critical step failed: {step.action}"
                        plan.status = "failed"
                        break

            # Mark plan as complete if no critical failures
            if plan.status != "failed":
                plan.status = "completed"
                results['success'] = True

            plan.completed_at = time.time()

        except Exception as e:
            results['error'] = str(e)
            plan.status = "failed"

        finally:
            # Save updated plan
            self._save_plan_state(plan)

        return results

    def _dependencies_met(self, step: PlanStep, plan: ExecutionPlan) -> bool:
        """Check if all step dependencies have completed"""

        if not step.depends_on:
            return True

        for dep_id in step.depends_on:
            dep_step = next((s for s in plan.steps if s.id == dep_id), None)
            if not dep_step or dep_step.status != StepStatus.COMPLETED:
                return False

        return True

    def _execute_step(self, step: PlanStep, session_id: str, plan: ExecutionPlan) -> Dict:
        """Execute a single step"""

        step.status = StepStatus.IN_PROGRESS
        start_time = time.time()

        try:
            # Build context from previous steps
            context = self._build_step_context(step, plan)

            # Select agent and execute
            agent_type = self._map_agent_type(step.agent_type)

            result = self.agent_manager.execute_task(
                agent_type=agent_type,
                task=step.action,
                session_id=session_id,
                context=context,
                tools_hint=step.tools_required
            )

            step.status = StepStatus.COMPLETED
            step.result = result
            step.actual_duration = int(time.time() - start_time)

            return {
                'step_id': step.id,
                'status': 'completed',
                'action': step.action,
                'agent_used': step.agent_type,
                'duration': step.actual_duration,
                'result': result
            }

        except Exception as e:
            step.status = StepStatus.FAILED
            step.error = str(e)
            step.actual_duration = int(time.time() - start_time)

            return {
                'step_id': step.id,
                'status': 'failed',
                'action': step.action,
                'error': str(e),
                'duration': step.actual_duration
            }

    def _build_step_context(self, step: PlanStep, plan: ExecutionPlan) -> Dict:
        """Build context for step execution from previous steps"""

        context = {
            'plan_goal': plan.goal,
            'current_step': step.id,
            'previous_results': []
        }

        # Include results from dependency steps
        for dep_id in step.depends_on:
            dep_step = next((s for s in plan.steps if s.id == dep_id), None)
            if dep_step and dep_step.result:
                context['previous_results'].append({
                    'step_id': dep_id,
                    'action': dep_step.action,
                    'result': dep_step.result
                })

        return context

    def _map_agent_type(self, agent_str: str) -> str:
        """Map plan agent string to AgentType enum"""

        mapping = {
            'coder': 'coder',
            'reasoner': 'reasoner',
            'researcher': 'researcher',
            'executor': 'executor',
            'general': 'general',
            'consultant': 'consultant'
        }

        return mapping.get(agent_str.lower(), 'general')

    def _save_plan_state(self, plan: ExecutionPlan):
        """Save current plan state"""

        plan_file = Path(f"/home/gh0st/pkn/memory/plans/plan_{plan.id}.json")
        with open(plan_file, 'w') as f:
            json.dump(plan.to_dict(), f, indent=2)

    def get_plan_status(self, plan_id: str) -> Optional[Dict]:
        """Get current status of a plan"""

        plan = self.active_plans.get(plan_id)
        if not plan:
            return None

        return {
            'plan_id': plan.id,
            'status': plan.status,
            'steps_total': len(plan.steps),
            'steps_completed': sum(1 for s in plan.steps if s.status == StepStatus.COMPLETED),
            'steps_failed': sum(1 for s in plan.steps if s.status == StepStatus.FAILED),
            'steps_pending': sum(1 for s in plan.steps if s.status == StepStatus.PENDING),
            'started_at': plan.started_at,
            'completed_at': plan.completed_at
        }


if __name__ == "__main__":
    print("Planning Tools module loaded successfully!")
    print("Use TaskPlanner to create execution plans")
    print("Use PlanExecutor to execute plans step-by-step")
