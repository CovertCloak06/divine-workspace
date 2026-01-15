"""
Tool Execution Framework for PKN Agents
Handles tool call parsing, execution, and multi-turn conversations
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from ..tools import TOOL_REGISTRY, execute_tool

logger = logging.getLogger(__name__)


class ToolExecutor:
    """
    Manages tool execution for agents with multi-turn conversation support.

    Features:
    - Parses agent responses for tool call requests
    - Executes tools using the universal registry
    - Handles multi-turn conversations (agent → tool → agent)
    - Tracks tool usage and errors
    """

    # Tool call patterns that agents might use
    TOOL_CALL_PATTERNS = [
        # JSON format: {"tool": "file_tools.glob", "args": {"pattern": "*.py"}}
        r'\{["\']tool["\']:\s*["\']([^"\']+)["\'],\s*["\']args["\']:\s*\{([^\}]+)\}\}',
        # Function call format: tool_name(arg1=value1, arg2=value2)
        r'([a-z_]+\.[a-z_]+)\(([^\)]+)\)',
        # XML format: <tool_call><tool>name</tool><args>...</args></tool_call>
        r'<tool_call><tool>([^<]+)</tool><args>([^<]+)</args></tool_call>',
        # Natural language: "use file_tools.glob with pattern=*.py"
        r'use\s+([a-z_]+\.[a-z_]+)\s+with\s+(.+)',
        # Simple format: TOOL: name ARGS: {...}
        r'TOOL:\s*([a-z_]+\.[a-z_]+)\s+ARGS:\s*\{([^\}]+)\}',
    ]

    def __init__(self, max_tool_turns: int = 3):
        """
        Initialize tool executor.

        Args:
            max_tool_turns: Maximum number of tool execution rounds per query
        """
        self.max_tool_turns = max_tool_turns
        self.tool_history: List[Dict[str, Any]] = []

    def parse_tool_call(self, agent_response: str) -> Optional[Dict[str, Any]]:
        """
        Parse agent response for tool call requests.

        Args:
            agent_response: Agent's text response

        Returns:
            Tool call dict with 'tool' and 'args' keys, or None if no tool call
        """
        for pattern in self.TOOL_CALL_PATTERNS:
            match = re.search(pattern, agent_response, re.IGNORECASE | re.DOTALL)
            if match:
                try:
                    tool_name = match.group(1)
                    args_str = match.group(2)

                    # Parse arguments
                    args = self._parse_args(args_str)

                    return {
                        "tool": tool_name,
                        "args": args,
                        "raw_response": agent_response
                    }
                except Exception as e:
                    logger.warning(f"Failed to parse tool call: {e}")
                    continue

        return None

    def _parse_args(self, args_str: str) -> Dict[str, Any]:
        """
        Parse tool arguments from string.

        Handles formats:
        - JSON: {"key": "value"}
        - Key-value pairs: key1=value1, key2=value2
        - XML: <key>value</key>
        """
        args = {}

        # Try JSON parsing first
        try:
            # Handle partial JSON (just the content, not wrapped in {})
            if not args_str.strip().startswith('{'):
                args_str = '{' + args_str + '}'
            args = json.loads(args_str)
            return args
        except json.JSONDecodeError:
            pass

        # Try key=value parsing
        pairs = re.findall(r'(\w+)\s*=\s*(["\']?)([^"\',]+)\2', args_str)
        for key, _, value in pairs:
            # Convert types
            if value.lower() == 'true':
                args[key] = True
            elif value.lower() == 'false':
                args[key] = False
            elif value.isdigit():
                args[key] = int(value)
            else:
                args[key] = value.strip()

        return args

    def execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call and return results.

        Args:
            tool_call: Dict with 'tool' and 'args' keys

        Returns:
            Tool execution result
        """
        tool_name = tool_call["tool"]
        args = tool_call["args"]

        logger.info(f"Executing tool: {tool_name} with args: {args}")

        try:
            result = execute_tool(tool_name, **args)

            # Track in history
            self.tool_history.append({
                "tool": tool_name,
                "args": args,
                "result": result,
                "status": result.get("status", "unknown")
            })

            return result

        except Exception as e:
            error_result = {
                "tool": tool_name,
                "status": "error",
                "error": str(e)
            }
            self.tool_history.append(error_result)
            return error_result

    def format_tool_result_for_agent(self, tool_result: Dict[str, Any]) -> str:
        """
        Format tool execution result for agent consumption.

        Args:
            tool_result: Tool execution result

        Returns:
            Formatted string for agent
        """
        if tool_result["status"] == "success":
            return f"""Tool execution successful:
Tool: {tool_result['tool']}
Result: {tool_result['result']}

Please provide a final response to the user based on this tool output."""
        else:
            return f"""Tool execution failed:
Tool: {tool_result['tool']}
Error: {tool_result.get('error', 'Unknown error')}

Please provide an alternative response or try a different approach."""

    def needs_tool_execution(self, agent_response: str) -> bool:
        """
        Check if agent response contains a tool call request.

        Args:
            agent_response: Agent's text response

        Returns:
            True if tool execution needed
        """
        return self.parse_tool_call(agent_response) is not None

    def get_tool_history(self) -> List[Dict[str, Any]]:
        """Get tool execution history for this session."""
        return self.tool_history.copy()

    def clear_history(self):
        """Clear tool execution history."""
        self.tool_history.clear()

    def build_tool_context_prompt(self, available_tools: List[str]) -> str:
        """
        Build a system prompt that teaches the agent how to call tools.

        Args:
            available_tools: List of tool names available to the agent

        Returns:
            System prompt with tool calling instructions
        """
        tools_list = "\n".join([f"- {tool}" for tool in available_tools])

        return f"""You have access to the following tools:

{tools_list}

To use a tool, format your response like this:
TOOL: tool_name ARGS: {{"arg1": "value1", "arg2": "value2"}}

For example:
TOOL: file_tools.glob ARGS: {{"pattern": "*.py", "path": "/home/user"}}

After using a tool, you'll receive the results and can provide a final answer to the user.

Always use tools when they can help answer the user's question more accurately."""


def create_tool_executor(max_turns: int = 3) -> ToolExecutor:
    """
    Factory function to create a ToolExecutor instance.

    Args:
        max_turns: Maximum tool execution rounds

    Returns:
        ToolExecutor instance
    """
    return ToolExecutor(max_tool_turns=max_turns)
