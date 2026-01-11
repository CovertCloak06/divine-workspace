#!/usr/bin/env python3
"""
Agent-to-Agent Delegation System
Allows agents to collaborate and delegate subtasks to specialized agents
"""

import time
import uuid
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class MessageType(Enum):
    """Types of inter-agent messages"""
    REQUEST = "request"          # Request for help
    RESPONSE = "response"        # Response to request
    QUERY = "query"              # Question to another agent
    RESULT = "result"            # Result of delegated task
    ERROR = "error"              # Error notification


class DelegationPriority(Enum):
    """Priority of delegation request"""
    URGENT = "urgent"            # Must be handled immediately
    HIGH = "high"                # Important, handle soon
    NORMAL = "normal"            # Standard priority
    LOW = "low"                  # Can wait


@dataclass
class AgentMessage:
    """Message for agent-to-agent communication"""
    id: str
    from_agent: str
    to_agent: str
    message_type: MessageType
    content: Dict[str, Any]
    task_id: str
    priority: DelegationPriority
    requires_response: bool
    timestamp: float
    response_id: Optional[str] = None  # ID of message this responds to

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['message_type'] = self.message_type.value
        d['priority'] = self.priority.value
        return d


@dataclass
class DelegationTask:
    """A task delegated from one agent to another"""
    id: str
    parent_task_id: str
    from_agent: str
    to_agent: str
    task_description: str
    context: Dict[str, Any]
    priority: DelegationPriority
    status: str  # pending, in_progress, completed, failed
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['priority'] = self.priority.value
        return d


class AgentDelegationManager:
    """
    Manages agent-to-agent delegation and collaboration.
    Tracks delegation requests, routes messages, and coordinates multi-agent workflows.
    """

    def __init__(self, agent_manager, project_root: str = "/home/gh0st/pkn"):
        self.agent_manager = agent_manager
        self.project_root = Path(project_root)
        self.delegation_dir = self.project_root / "memory" / "delegations"
        self.delegation_dir.mkdir(parents=True, exist_ok=True)

        # Active delegations
        self.active_delegations: Dict[str, DelegationTask] = {}

        # Message queue for inter-agent communication
        self.message_queue: List[AgentMessage] = []

        # Agent capabilities (what each agent can help with)
        self.agent_capabilities = {
            'coder': [
                'write code',
                'debug code',
                'refactor code',
                'review code',
                'explain code',
                'optimize code'
            ],
            'reasoner': [
                'create plan',
                'analyze problem',
                'make decision',
                'evaluate options',
                'find solution',
                'explain logic'
            ],
            'researcher': [
                'find information',
                'search documentation',
                'compare alternatives',
                'gather context',
                'verify facts'
            ],
            'executor': [
                'run command',
                'execute script',
                'test code',
                'deploy changes',
                'manage files'
            ],
            'general': [
                'answer question',
                'have conversation',
                'explain concept',
                'summarize text'
            ]
        }

    def delegate_task(self, from_agent: str, to_agent: str, task: str,
                      context: Dict[str, Any], parent_task_id: str,
                      priority: DelegationPriority = DelegationPriority.NORMAL) -> DelegationTask:
        """Delegate a task from one agent to another"""

        delegation = DelegationTask(
            id=str(uuid.uuid4()),
            parent_task_id=parent_task_id,
            from_agent=from_agent,
            to_agent=to_agent,
            task_description=task,
            context=context,
            priority=priority,
            status="pending",
            created_at=time.time()
        )

        self.active_delegations[delegation.id] = delegation

        # Create message
        message = AgentMessage(
            id=str(uuid.uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.REQUEST,
            content={
                'task': task,
                'context': context,
                'delegation_id': delegation.id
            },
            task_id=parent_task_id,
            priority=priority,
            requires_response=True,
            timestamp=time.time()
        )

        self.message_queue.append(message)
        self._save_delegation(delegation)

        return delegation

    def execute_delegation(self, delegation_id: str, session_id: str) -> Dict[str, Any]:
        """Execute a delegated task"""

        delegation = self.active_delegations.get(delegation_id)
        if not delegation:
            return {'error': 'Delegation not found'}

        delegation.status = "in_progress"
        delegation.started_at = time.time()

        try:
            # Execute task with the target agent
            result = self.agent_manager.execute_task(
                agent_type=delegation.to_agent,
                task=delegation.task_description,
                session_id=session_id,
                context=delegation.context
            )

            delegation.status = "completed"
            delegation.completed_at = time.time()
            delegation.result = result

            # Send result message back to requesting agent
            self._send_result_message(delegation, result)

            self._save_delegation(delegation)

            return {
                'success': True,
                'delegation_id': delegation_id,
                'result': result,
                'duration': delegation.completed_at - delegation.started_at
            }

        except Exception as e:
            delegation.status = "failed"
            delegation.completed_at = time.time()
            delegation.error = str(e)

            self._send_error_message(delegation, str(e))
            self._save_delegation(delegation)

            return {
                'success': False,
                'delegation_id': delegation_id,
                'error': str(e)
            }

    def request_help(self, requesting_agent: str, help_needed: str,
                     context: Dict[str, Any], task_id: str) -> Dict[str, Any]:
        """Request help from the most appropriate agent"""

        # Determine which agent can best help
        best_agent = self._select_helper_agent(help_needed, requesting_agent)

        if not best_agent:
            return {
                'success': False,
                'error': 'No suitable agent found for this request'
            }

        # Delegate to the selected agent
        delegation = self.delegate_task(
            from_agent=requesting_agent,
            to_agent=best_agent,
            task=help_needed,
            context=context,
            parent_task_id=task_id,
            priority=DelegationPriority.HIGH
        )

        return {
            'success': True,
            'delegation_id': delegation.id,
            'helper_agent': best_agent,
            'message': f'Delegated to {best_agent} agent'
        }

    def _select_helper_agent(self, task: str, exclude_agent: str) -> Optional[str]:
        """Select the best agent to help with a task"""

        task_lower = task.lower()
        best_match = None
        best_score = 0

        for agent, capabilities in self.agent_capabilities.items():
            if agent == exclude_agent:
                continue

            # Score based on keyword matching
            score = 0
            for capability in capabilities:
                if any(word in task_lower for word in capability.split()):
                    score += 1

            if score > best_score:
                best_score = score
                best_match = agent

        # If no match, use reasoner as default helper
        if not best_match or best_score == 0:
            best_match = 'reasoner' if exclude_agent != 'reasoner' else 'general'

        return best_match

    def collaborate(self, agents: List[str], task: str, session_id: str,
                    coordinator: str = 'reasoner') -> Dict[str, Any]:
        """Multiple agents collaborate on a complex task"""

        collaboration_id = str(uuid.uuid4())

        # Step 1: Coordinator creates plan
        plan_request = f"""Create a collaboration plan for this task involving these agents: {', '.join(agents)}

Task: {task}

For each agent, specify:
1. What they should do
2. What information they need from other agents
3. In what order they should work

Format as JSON with agent roles and dependencies."""

        plan_result = self.agent_manager.execute_task(
            agent_type=coordinator,
            task=plan_request,
            session_id=session_id,
            context={'collaboration_id': collaboration_id}
        )

        # Step 2: Execute plan with each agent
        results = {
            'collaboration_id': collaboration_id,
            'coordinator': coordinator,
            'participants': agents,
            'task': task,
            'agent_results': []
        }

        for agent in agents:
            # Build context from previous agent results
            agent_context = {
                'collaboration_id': collaboration_id,
                'previous_results': results['agent_results'],
                'full_task': task
            }

            # Delegate specific subtask to this agent
            subtask = f"Your part in this collaboration: {task}\n\nCoordinator's plan: {plan_result}"

            delegation = self.delegate_task(
                from_agent=coordinator,
                to_agent=agent,
                task=subtask,
                context=agent_context,
                parent_task_id=collaboration_id,
                priority=DelegationPriority.HIGH
            )

            # Execute delegation
            agent_result = self.execute_delegation(delegation.id, session_id)

            results['agent_results'].append({
                'agent': agent,
                'delegation_id': delegation.id,
                'result': agent_result.get('result'),
                'success': agent_result.get('success', False)
            })

        # Step 3: Coordinator synthesizes results
        synthesis_task = f"""Synthesize these collaboration results into a final answer:

Original task: {task}

Agent results:
{json.dumps(results['agent_results'], indent=2)}

Provide a unified, coherent response that combines the best of each agent's contribution."""

        final_result = self.agent_manager.execute_task(
            agent_type=coordinator,
            task=synthesis_task,
            session_id=session_id,
            context={'collaboration_id': collaboration_id}
        )

        results['final_result'] = final_result
        results['success'] = True

        return results

    def _send_result_message(self, delegation: DelegationTask, result: Any):
        """Send result message back to requesting agent"""

        message = AgentMessage(
            id=str(uuid.uuid4()),
            from_agent=delegation.to_agent,
            to_agent=delegation.from_agent,
            message_type=MessageType.RESULT,
            content={
                'delegation_id': delegation.id,
                'result': result
            },
            task_id=delegation.parent_task_id,
            priority=delegation.priority,
            requires_response=False,
            timestamp=time.time()
        )

        self.message_queue.append(message)

    def _send_error_message(self, delegation: DelegationTask, error: str):
        """Send error message back to requesting agent"""

        message = AgentMessage(
            id=str(uuid.uuid4()),
            from_agent=delegation.to_agent,
            to_agent=delegation.from_agent,
            message_type=MessageType.ERROR,
            content={
                'delegation_id': delegation.id,
                'error': error
            },
            task_id=delegation.parent_task_id,
            priority=delegation.priority,
            requires_response=False,
            timestamp=time.time()
        )

        self.message_queue.append(message)

    def _save_delegation(self, delegation: DelegationTask):
        """Save delegation to disk"""

        delegation_file = self.delegation_dir / f"delegation_{delegation.id}.json"
        with open(delegation_file, 'w') as f:
            json.dump(delegation.to_dict(), f, indent=2)

    def get_delegation_status(self, delegation_id: str) -> Optional[Dict]:
        """Get status of a delegation"""

        delegation = self.active_delegations.get(delegation_id)
        if not delegation:
            return None

        return {
            'id': delegation.id,
            'from_agent': delegation.from_agent,
            'to_agent': delegation.to_agent,
            'task': delegation.task_description,
            'status': delegation.status,
            'created_at': delegation.created_at,
            'completed_at': delegation.completed_at,
            'duration': delegation.completed_at - delegation.created_at if delegation.completed_at else None
        }

    def get_active_delegations(self, agent: Optional[str] = None) -> List[Dict]:
        """Get all active delegations, optionally filtered by agent"""

        delegations = []
        for delegation in self.active_delegations.values():
            if delegation.status in ['pending', 'in_progress']:
                if agent is None or delegation.to_agent == agent or delegation.from_agent == agent:
                    delegations.append(delegation.to_dict())

        return delegations

    def get_message_queue(self, agent: Optional[str] = None) -> List[Dict]:
        """Get messages in queue, optionally filtered by recipient"""

        if agent:
            return [msg.to_dict() for msg in self.message_queue if msg.to_agent == agent]
        return [msg.to_dict() for msg in self.message_queue]

    def clear_message_queue(self):
        """Clear processed messages"""

        self.message_queue.clear()


if __name__ == "__main__":
    print("Agent Delegation Tools module loaded successfully!")
    print("Features:")
    print("  - Agent-to-agent task delegation")
    print("  - Request help from specialized agents")
    print("  - Multi-agent collaboration")
    print("  - Inter-agent messaging")
