"""
PKN Tools Package - Universal Tool Execution Framework
Modular tool system for PKN agents, inspired by Claude Code.

Architecture:
- All tool modules use LangChain @tool decorator
- Central registry auto-discovers and registers all tools
- Universal execution interface for agent tool calls
- Standard result formatting across all tools

Tool modules (22 total):
- code_tools: Edit, Write, Read (surgical code operations)
- file_tools: Glob, Grep, Find (file search and discovery)
- system_tools: Bash, Process, TodoWrite (execution and monitoring)
- web_tools: Search, Fetch (web research)
- memory_tools: Context, Recall (persistent memory)
- osint_tools: WHOIS, DNS, IP lookup (OSINT)
- rag_tools: Document retrieval, vector search
- planning_tools: Task breakdown, dependency analysis
- delegation_tools: Agent-to-agent communication
- chain_tools: Multi-step workflows
- sandbox_tools: Safe code execution
- evaluation_tools: Agent performance tracking
- scratchpad_tools: Agent handoff storage for workflows
- workflow_tools: Multi-agent workflow coordination (12 workflows)
- git_tools: Version control operations
- project_tools: Project management and health checks
- pentest_tools: Offensive security utilities (shells, payloads, exploits)
- recon_tools: Banner grab, HTTP headers, directory enum, CORS testing
- privesc_tools: SUID finder, cron enum, kernel exploits, docker escape
- network_tools: TCP/UDP scan, traceroute, ARP scan, zone transfer
- crypto_tools: Hash cracking, JWT decode/forge, base decode, XOR
- Advanced: RAGMemory, TaskPlanner, CodeSandbox, etc.
"""

from typing import Dict, Any, List, Optional, Callable
import inspect
import json

# Import all tool modules
from . import code_tools
from . import file_tools
from . import system_tools
from . import web_tools
from . import memory_tools
from . import osint_tools
from . import rag_tools
from . import planning_tools
from . import delegation_tools
from . import chain_tools
from . import sandbox_tools
from . import evaluation_tools
# New tools from MCP integration (2026-01-18)
from . import scratchpad_tools
from . import workflow_tools
from . import git_tools
from . import project_tools
from . import pentest_tools
# Kali-style security tools (2026-01-18)
from . import recon_tools
from . import privesc_tools
from . import network_tools
from . import crypto_tools

__all__ = [
    "code_tools",
    "file_tools",
    "system_tools",
    "web_tools",
    "memory_tools",
    "osint_tools",
    "rag_tools",
    "planning_tools",
    "delegation_tools",
    "chain_tools",
    "sandbox_tools",
    "evaluation_tools",
    # New tools from MCP integration
    "scratchpad_tools",
    "workflow_tools",
    "git_tools",
    "project_tools",
    "pentest_tools",
    # Kali-style security tools
    "recon_tools",
    "privesc_tools",
    "network_tools",
    "crypto_tools",
    # Registry and helpers
    "TOOL_REGISTRY",
    "get_tool_schemas",
    "execute_tool",
    "list_available_tools",
]


class ToolRegistry:
    """
    Universal tool registry for automatic tool discovery and execution.

    Features:
    - Auto-discovers @tool decorated functions from all modules
    - Provides tool schemas for agent awareness
    - Universal execution interface
    - Validates tool arguments
    - Tracks tool usage
    """

    def __init__(self):
        self.tools: Dict[str, Callable] = {}  # tool_name -> function
        self.schemas: Dict[str, Dict[str, Any]] = {}  # tool_name -> schema
        self.usage_counts: Dict[str, int] = {}  # tool_name -> call count
        self._discover_tools()

    def _discover_tools(self):
        """Auto-discover all @tool decorated functions from tool modules."""
        modules = [
            ("code_tools", code_tools),
            ("file_tools", file_tools),
            ("system_tools", system_tools),
            ("web_tools", web_tools),
            ("memory_tools", memory_tools),
            ("osint_tools", osint_tools),
            ("rag_tools", rag_tools),
            ("planning_tools", planning_tools),
            ("delegation_tools", delegation_tools),
            ("chain_tools", chain_tools),
            ("sandbox_tools", sandbox_tools),
            ("evaluation_tools", evaluation_tools),
            # New tools from MCP integration (2026-01-18)
            ("scratchpad_tools", scratchpad_tools),
            ("workflow_tools", workflow_tools),
            ("git_tools", git_tools),
            ("project_tools", project_tools),
            ("pentest_tools", pentest_tools),
            # Kali-style security tools
            ("recon_tools", recon_tools),
            ("privesc_tools", privesc_tools),
            ("network_tools", network_tools),
            ("crypto_tools", crypto_tools),
        ]

        for module_name, module in modules:
            for attr_name in dir(module):
                # Skip private attributes
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)

                # Check if it's a LangChain StructuredTool (has name, description, and invoke method)
                if (
                    hasattr(attr, "name")
                    and hasattr(attr, "description")
                    and hasattr(attr, "invoke")
                    and attr.__class__.__name__ == "StructuredTool"
                ):
                    tool_name = f"{module_name}.{attr.name}"
                    self.tools[tool_name] = attr
                    self.schemas[tool_name] = self._extract_schema(attr)
                    self.usage_counts[tool_name] = 0

    def _extract_schema(self, tool_func: Callable) -> Dict[str, Any]:
        """Extract tool schema from LangChain StructuredTool."""
        schema = {
            "name": tool_func.name,
            "description": tool_func.description,
            "parameters": {}
        }

        # LangChain StructuredTool has args_schema (Pydantic model)
        if hasattr(tool_func, "args_schema") and tool_func.args_schema:
            # Get field info from Pydantic model
            if hasattr(tool_func.args_schema, "model_fields"):
                # Pydantic v2
                fields = tool_func.args_schema.model_fields
                for field_name, field_info in fields.items():
                    schema["parameters"][field_name] = {
                        "type": str(field_info.annotation) if hasattr(field_info, "annotation") else "string",
                        "required": field_info.is_required() if hasattr(field_info, "is_required") else True,
                        "default": field_info.default if hasattr(field_info, "default") else None,
                        "description": field_info.description if hasattr(field_info, "description") else ""
                    }
            elif hasattr(tool_func.args_schema, "__fields__"):
                # Pydantic v1
                fields = tool_func.args_schema.__fields__
                for field_name, field_info in fields.items():
                    schema["parameters"][field_name] = {
                        "type": str(field_info.annotation) if hasattr(field_info, "annotation") else "string",
                        "required": field_info.required,
                        "default": field_info.default,
                        "description": field_info.field_info.description if hasattr(field_info, "field_info") else ""
                    }

        return schema

    def get_tool(self, tool_name: str) -> Optional[Callable]:
        """Get tool function by name."""
        return self.tools.get(tool_name)

    def list_tools(self, module_filter: Optional[str] = None) -> List[str]:
        """List all available tools, optionally filtered by module."""
        if module_filter:
            return [name for name in self.tools.keys() if name.startswith(f"{module_filter}.")]
        return list(self.tools.keys())

    def get_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get tool schema for agent awareness."""
        return self.schemas.get(tool_name)

    def get_all_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Get schemas for all tools."""
        return self.schemas.copy()

    def execute(self, tool_name: str, **kwargs) -> Any:
        """
        Universal tool execution interface.

        Args:
            tool_name: Tool identifier (e.g., "file_tools.glob")
            **kwargs: Tool arguments

        Returns:
            Tool execution result

        Raises:
            ValueError: If tool not found
            TypeError: If invalid arguments
        """
        tool_func = self.get_tool(tool_name)
        if not tool_func:
            raise ValueError(f"Tool not found: {tool_name}")

        try:
            # Track usage
            self.usage_counts[tool_name] += 1

            # Execute tool using LangChain's invoke method
            result = tool_func.invoke(kwargs)

            return {
                "tool": tool_name,
                "status": "success",
                "result": result,
                "usage_count": self.usage_counts[tool_name]
            }

        except TypeError as e:
            return {
                "tool": tool_name,
                "status": "error",
                "error": f"Invalid arguments: {e}",
                "usage_count": self.usage_counts[tool_name]
            }

        except Exception as e:
            return {
                "tool": tool_name,
                "status": "error",
                "error": str(e),
                "usage_count": self.usage_counts[tool_name]
            }

    def get_tools_for_agent(self, agent_capabilities: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Get relevant tools based on agent capabilities.

        Args:
            agent_capabilities: List of capabilities (e.g., ["code_writing", "debugging"])

        Returns:
            Dictionary of tool schemas filtered by capabilities
        """
        # Capability to tool module mapping
        capability_map = {
            "code_writing": ["code_tools", "file_tools", "git_tools"],
            "debugging": ["code_tools", "file_tools", "system_tools"],
            "research": ["web_tools", "rag_tools", "osint_tools"],
            "planning": ["planning_tools", "workflow_tools"],
            "system_operations": ["system_tools", "file_tools", "project_tools"],
            "security": ["osint_tools", "web_tools", "system_tools", "pentest_tools"],
            # New capabilities from MCP integration
            "workflow": ["scratchpad_tools", "workflow_tools"],
            "version_control": ["git_tools"],
            "project_management": ["project_tools"],
            "pentesting": ["pentest_tools", "osint_tools", "recon_tools", "privesc_tools", "network_tools"],
            "reconnaissance": ["recon_tools", "osint_tools", "network_tools"],
            "cryptography": ["crypto_tools"],
            "privilege_escalation": ["privesc_tools"],
        }

        # Collect relevant modules
        relevant_modules = set()
        for capability in agent_capabilities:
            modules = capability_map.get(capability, [])
            relevant_modules.update(modules)

        # Filter tools
        filtered_schemas = {}
        for tool_name, schema in self.schemas.items():
            module_name = tool_name.split(".")[0]
            if module_name in relevant_modules:
                filtered_schemas[tool_name] = schema

        return filtered_schemas


# Global tool registry instance
TOOL_REGISTRY = ToolRegistry()


# Convenience functions for external use
def get_tool_schemas(agent_capabilities: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Get tool schemas for agent awareness.

    Args:
        agent_capabilities: Optional list to filter tools by agent capabilities

    Returns:
        Dictionary of tool schemas
    """
    if agent_capabilities:
        return TOOL_REGISTRY.get_tools_for_agent(agent_capabilities)
    return TOOL_REGISTRY.get_all_schemas()


def execute_tool(tool_name: str, **kwargs) -> Dict[str, Any]:
    """
    Execute a tool by name with given arguments.

    Args:
        tool_name: Tool identifier (e.g., "file_tools.glob")
        **kwargs: Tool arguments

    Returns:
        Tool execution result with status

    Examples:
        >>> execute_tool("file_tools.glob", pattern="*.py")
        {'tool': 'file_tools.glob', 'status': 'success', 'result': '...'}

        >>> execute_tool("web_tools.search", query="Python tutorial")
        {'tool': 'web_tools.search', 'status': 'success', 'result': '...'}
    """
    return TOOL_REGISTRY.execute(tool_name, **kwargs)


def list_available_tools(module_filter: Optional[str] = None) -> List[str]:
    """
    List all available tools.

    Args:
        module_filter: Optional module name to filter by (e.g., "file_tools")

    Returns:
        List of tool names

    Examples:
        >>> list_available_tools()
        ['file_tools.glob', 'file_tools.grep', 'code_tools.edit', ...]

        >>> list_available_tools(module_filter="file_tools")
        ['file_tools.glob', 'file_tools.grep', 'file_tools.find_definition']
    """
    return TOOL_REGISTRY.list_tools(module_filter)


def get_tool_usage_stats() -> Dict[str, int]:
    """
    Get tool usage statistics.

    Returns:
        Dictionary mapping tool names to usage counts
    """
    return TOOL_REGISTRY.usage_counts.copy()
