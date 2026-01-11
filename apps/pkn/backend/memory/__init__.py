"""
Memory Management Module
Provides conversation memory and code context management
"""

from .conversation_memory import ConversationMemory
from .code_context import CodeContext

# Create singleton instances
conversation_memory = ConversationMemory()
code_context = CodeContext()

__all__ = ["ConversationMemory", "CodeContext", "conversation_memory", "code_context"]
