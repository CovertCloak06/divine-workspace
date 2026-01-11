#!/usr/bin/env python3
"""
Conversation Memory System
Manages conversation context, history, and session persistence
"""

import os
import json
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict


class ConversationMemory:
    """
    Manages conversation history and context for multi-agent interactions.
    Provides both in-memory (session) and persistent (file-based) storage.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.memory_dir = self.project_root / "memory"
        self.memory_dir.mkdir(exist_ok=True)

        # Session memory (in-memory, cleared on restart)
        self.sessions = {}  # {session_id: session_data}
        self.active_files = defaultdict(set)  # {session_id: set of file paths}

        # Persistent memory paths
        self.conversations_file = self.memory_dir / "conversations.json"
        self.workspace_file = self.memory_dir / "workspace_state.json"

        # Load persistent data
        self._load_persistent_data()

    def _load_persistent_data(self):
        """Load persistent conversation data from disk"""
        try:
            if self.conversations_file.exists():
                with open(self.conversations_file, 'r') as f:
                    self.persistent_conversations = json.load(f)
            else:
                self.persistent_conversations = {}

            if self.workspace_file.exists():
                with open(self.workspace_file, 'r') as f:
                    self.workspace_state = json.load(f)
            else:
                self.workspace_state = {}

        except Exception as e:
            print(f"Warning: Could not load persistent data: {e}")
            self.persistent_conversations = {}
            self.workspace_state = {}

    def _save_persistent_data(self):
        """Save persistent conversation data to disk"""
        try:
            with open(self.conversations_file, 'w') as f:
                json.dump(self.persistent_conversations, f, indent=2)

            with open(self.workspace_file, 'w') as f:
                json.dump(self.workspace_state, f, indent=2)

        except Exception as e:
            print(f"Warning: Could not save persistent data: {e}")

    def create_session(self, user_id: str = "default") -> str:
        """
        Create a new conversation session.

        Args:
            user_id: Optional user identifier

        Returns:
            session_id: Unique session identifier
        """
        session_id = str(uuid.uuid4())

        self.sessions[session_id] = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': time.time(),
            'last_active': time.time(),
            'messages': [],
            'context': {
                'current_project': None,
                'active_files': [],
                'last_agent': None,
                'task_history': []
            },
            'metadata': {
                'total_messages': 0,
                'agents_used': set(),
                'tools_used': set()
            }
        }

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID"""
        return self.sessions.get(session_id)

    def add_message(self, session_id: str, role: str, content: str,
                    agent: str = None, tools_used: List[str] = None) -> bool:
        """
        Add a message to the conversation history.

        Args:
            session_id: Session identifier
            role: 'user' or 'assistant'
            content: Message content
            agent: Agent that generated the message (if assistant)
            tools_used: List of tools used (if any)

        Returns:
            success: True if message was added
        """
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        message = {
            'id': str(uuid.uuid4()),
            'role': role,
            'content': content,
            'timestamp': time.time(),
            'agent': agent,
            'tools_used': tools_used or []
        }

        session['messages'].append(message)
        session['last_active'] = time.time()
        session['metadata']['total_messages'] += 1

        if agent:
            session['metadata']['agents_used'].add(agent)
            session['context']['last_agent'] = agent

        if tools_used:
            session['metadata']['tools_used'].update(tools_used)

        return True

    def get_conversation_history(self, session_id: str,
                                 limit: int = None) -> List[Dict[str, Any]]:
        """
        Get conversation history for a session.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return (most recent)

        Returns:
            messages: List of messages
        """
        if session_id not in self.sessions:
            return []

        messages = self.sessions[session_id]['messages']

        if limit:
            return messages[-limit:]
        return messages

    def get_context(self, session_id: str) -> Dict[str, Any]:
        """Get current context for a session"""
        if session_id not in self.sessions:
            return {}

        return self.sessions[session_id]['context']

    def update_context(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update session context.

        Args:
            session_id: Session identifier
            updates: Dictionary of context updates

        Returns:
            success: True if context was updated
        """
        if session_id not in self.sessions:
            return False

        self.sessions[session_id]['context'].update(updates)
        self.sessions[session_id]['last_active'] = time.time()

        return True

    def add_active_file(self, session_id: str, file_path: str):
        """Track a file that's being worked on in this session"""
        if session_id in self.sessions:
            context = self.sessions[session_id]['context']
            if 'active_files' not in context:
                context['active_files'] = []
            if file_path not in context['active_files']:
                context['active_files'].append(file_path)
                self.active_files[session_id].add(file_path)

    def get_active_files(self, session_id: str) -> List[str]:
        """Get list of files being worked on in this session"""
        if session_id in self.sessions:
            return self.sessions[session_id]['context'].get('active_files', [])
        return []

    def save_session(self, session_id: str, name: str = None) -> bool:
        """
        Save session to persistent storage.

        Args:
            session_id: Session identifier
            name: Optional name for the saved session

        Returns:
            success: True if session was saved
        """
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id].copy()

        # Convert sets to lists for JSON serialization
        session['metadata']['agents_used'] = list(session['metadata']['agents_used'])
        session['metadata']['tools_used'] = list(session['metadata']['tools_used'])

        # Add name if provided
        if name:
            session['name'] = name
        else:
            session['name'] = f"Session {session_id[:8]}"

        self.persistent_conversations[session_id] = session
        self._save_persistent_data()

        return True

    def load_session(self, session_id: str) -> bool:
        """
        Load a saved session from persistent storage.

        Args:
            session_id: Session identifier

        Returns:
            success: True if session was loaded
        """
        if session_id not in self.persistent_conversations:
            return False

        session = self.persistent_conversations[session_id].copy()

        # Convert lists back to sets
        session['metadata']['agents_used'] = set(session['metadata']['agents_used'])
        session['metadata']['tools_used'] = set(session['metadata']['tools_used'])

        self.sessions[session_id] = session

        return True

    def list_saved_sessions(self) -> List[Dict[str, Any]]:
        """Get list of all saved sessions"""
        return [
            {
                'session_id': sid,
                'name': data.get('name', f"Session {sid[:8]}"),
                'created_at': data.get('created_at'),
                'message_count': len(data.get('messages', [])),
                'last_active': data.get('last_active')
            }
            for sid, data in self.persistent_conversations.items()
        ]

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get a summary of a session"""
        if session_id not in self.sessions:
            return {}

        session = self.sessions[session_id]
        messages = session['messages']

        return {
            'session_id': session_id,
            'created_at': session['created_at'],
            'last_active': session['last_active'],
            'duration': session['last_active'] - session['created_at'],
            'total_messages': len(messages),
            'user_messages': sum(1 for m in messages if m['role'] == 'user'),
            'assistant_messages': sum(1 for m in messages if m['role'] == 'assistant'),
            'agents_used': list(session['metadata']['agents_used']),
            'tools_used': list(session['metadata']['tools_used']),
            'active_files': session['context'].get('active_files', [])
        }

    def clear_session(self, session_id: str) -> bool:
        """Clear a session from memory (does not delete saved sessions)"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            if session_id in self.active_files:
                del self.active_files[session_id]
            return True
        return False

    def get_workspace_state(self) -> Dict[str, Any]:
        """Get current workspace state (open files, cursor positions, etc.)"""
        return self.workspace_state.copy()

    def update_workspace_state(self, updates: Dict[str, Any]):
        """Update workspace state"""
        self.workspace_state.update(updates)
        self._save_persistent_data()

    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Clean up sessions older than max_age_hours"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600

        to_remove = []
        for session_id, session in self.sessions.items():
            age = current_time - session['last_active']
            if age > max_age_seconds:
                to_remove.append(session_id)

        for session_id in to_remove:
            self.clear_session(session_id)

        return len(to_remove)


# Global instance for API use
conversation_memory = ConversationMemory()


if __name__ == '__main__':
    # Test conversation memory
    print("=" * 60)
    print("CONVERSATION MEMORY SYSTEM TEST")
    print("=" * 60)
    print()

    # Create a test session
    session_id = conversation_memory.create_session(user_id="test_user")
    print(f"Created session: {session_id[:8]}...")

    # Add some messages
    conversation_memory.add_message(
        session_id,
        'user',
        'Write a function to calculate fibonacci numbers'
    )
    conversation_memory.add_message(
        session_id,
        'assistant',
        'Here is a Python function...',
        agent='coder',
        tools_used=['write_file']
    )
    conversation_memory.add_message(
        session_id,
        'user',
        'Now add unit tests'
    )

    # Update context
    conversation_memory.update_context(session_id, {
        'current_project': 'fibonacci_calculator',
        'task_history': ['write_function', 'add_tests']
    })
    conversation_memory.add_active_file(session_id, '/home/gh0st/pkn/fibonacci.py')

    # Get conversation history
    history = conversation_memory.get_conversation_history(session_id)
    print(f"\nConversation history: {len(history)} messages")
    for msg in history:
        print(f"  [{msg['role']}] {msg['content'][:50]}...")
        if msg['agent']:
            print(f"    Agent: {msg['agent']}, Tools: {msg['tools_used']}")

    # Get summary
    summary = conversation_memory.get_session_summary(session_id)
    print(f"\nSession Summary:")
    print(f"  Total messages: {summary['total_messages']}")
    print(f"  User messages: {summary['user_messages']}")
    print(f"  Assistant messages: {summary['assistant_messages']}")
    print(f"  Agents used: {summary['agents_used']}")
    print(f"  Tools used: {summary['tools_used']}")
    print(f"  Active files: {summary['active_files']}")

    # Save session
    conversation_memory.save_session(session_id, name="Fibonacci Test Session")
    print(f"\n✓ Session saved to disk")

    # List saved sessions
    saved = conversation_memory.list_saved_sessions()
    print(f"\nSaved sessions: {len(saved)}")
    for s in saved:
        print(f"  - {s['name']} ({s['message_count']} messages)")

    print("\n" + "=" * 60)
