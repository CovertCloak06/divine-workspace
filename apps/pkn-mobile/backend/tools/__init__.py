"""
PKN Tools Package
Modular tool system for PKN agents, inspired by Claude Code.

Tool modules (21 total):
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
- workflow_tools: Multi-agent workflow coordination
- git_tools: Version control operations
- project_tools: Project management and health checks
- pentest_tools: Shells, payloads, webshells, exploits
- recon_tools: Banner grab, headers, directory enum, CORS
- privesc_tools: SUID, cron, kernel exploits, docker escape
- network_tools: TCP/UDP scan, traceroute, ARP, zone transfer
- crypto_tools: Hash crack, JWT, base decode, XOR
"""

from . import code_tools
from . import file_tools
from . import system_tools
from . import web_tools
from . import memory_tools
# Core agent tools (required by manager.py)
from . import osint_tools
from . import rag_tools
from . import planning_tools
from . import delegation_tools
from . import chain_tools
from . import sandbox_tools
from . import evaluation_tools
# MCP integration tools
from . import scratchpad_tools
from . import workflow_tools
from . import git_tools
from . import project_tools
# Security/Pentesting tools (Kali-style)
from . import pentest_tools
from . import recon_tools
from . import privesc_tools
from . import network_tools
from . import crypto_tools

from typing import Dict, Any, List, Optional, Callable

__all__ = [
    "code_tools",
    "file_tools",
    "system_tools",
    "web_tools",
    "memory_tools",
    # Core agent tools
    "osint_tools",
    "rag_tools",
    "planning_tools",
    "delegation_tools",
    "chain_tools",
    "sandbox_tools",
    "evaluation_tools",
    # MCP integration tools
    "scratchpad_tools",
    "workflow_tools",
    "git_tools",
    "project_tools",
    # Security tools
    "pentest_tools",
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
    Ported from PKN Desktop for mobile compatibility.
    """

    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.usage_counts: Dict[str, int] = {}
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
            ("scratchpad_tools", scratchpad_tools),
            ("workflow_tools", workflow_tools),
            ("git_tools", git_tools),
            ("project_tools", project_tools),
            ("pentest_tools", pentest_tools),
            ("recon_tools", recon_tools),
            ("privesc_tools", privesc_tools),
            ("network_tools", network_tools),
            ("crypto_tools", crypto_tools),
        ]

        for module_name, module in modules:
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue
                attr = getattr(module, attr_name)
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
        if hasattr(tool_func, "args_schema") and tool_func.args_schema:
            if hasattr(tool_func.args_schema, "model_fields"):
                fields = tool_func.args_schema.model_fields
                for field_name, field_info in fields.items():
                    schema["parameters"][field_name] = {
                        "type": str(field_info.annotation) if hasattr(field_info, "annotation") else "string",
                        "required": field_info.is_required() if hasattr(field_info, "is_required") else True,
                    }
            elif hasattr(tool_func.args_schema, "__fields__"):
                fields = tool_func.args_schema.__fields__
                for field_name, field_info in fields.items():
                    schema["parameters"][field_name] = {
                        "type": str(field_info.annotation) if hasattr(field_info, "annotation") else "string",
                        "required": field_info.required,
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
        """Universal tool execution interface."""
        tool_func = self.get_tool(tool_name)
        if not tool_func:
            raise ValueError(f"Tool not found: {tool_name}")
        try:
            self.usage_counts[tool_name] += 1
            result = tool_func.invoke(kwargs)
            return {"tool": tool_name, "status": "success", "result": result}
        except Exception as e:
            return {"tool": tool_name, "status": "error", "error": str(e)}

    def get_tools_for_agent(self, agent_capabilities: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get relevant tools based on agent capabilities."""
        capability_map = {
            "code_writing": ["code_tools", "file_tools", "git_tools"],
            "debugging": ["code_tools", "file_tools", "system_tools"],
            "research": ["web_tools", "rag_tools", "osint_tools"],
            "planning": ["planning_tools", "workflow_tools"],
            "system_operations": ["system_tools", "file_tools", "project_tools"],
            "security": ["osint_tools", "pentest_tools", "recon_tools", "privesc_tools", "network_tools"],
            "pentesting": ["pentest_tools", "recon_tools", "privesc_tools", "network_tools", "crypto_tools"],
        }
        relevant_modules = set()
        for capability in agent_capabilities:
            relevant_modules.update(capability_map.get(capability, []))
        return {name: schema for name, schema in self.schemas.items()
                if name.split(".")[0] in relevant_modules}


# Global tool registry instance
TOOL_REGISTRY = ToolRegistry()


def get_tool_schemas(agent_capabilities: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Get tool schemas for agent awareness."""
    if agent_capabilities:
        return TOOL_REGISTRY.get_tools_for_agent(agent_capabilities)
    return TOOL_REGISTRY.get_all_schemas()


def execute_tool(tool_name: str, **kwargs) -> Dict[str, Any]:
    """Execute a tool by name with given arguments."""
    return TOOL_REGISTRY.execute(tool_name, **kwargs)


def list_available_tools(module_filter: Optional[str] = None) -> List[str]:
    """List all available tools."""
    return TOOL_REGISTRY.list_tools(module_filter)


def get_tool_usage_stats() -> Dict[str, int]:
    """Get tool usage statistics."""
    return TOOL_REGISTRY.usage_counts.copy()
