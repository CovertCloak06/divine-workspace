#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

import requests
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import (
    HumanMessage,
    SystemMessage,
    ToolMessage,
    AIMessage,
)

# Import web tools for enhanced agent capabilities
try:
    from web_tools import search, fetch, wiki, github, web_tools
    WEB_TOOLS_AVAILABLE = True
except ImportError:
    WEB_TOOLS_AVAILABLE = False
    print("Warning: web_tools module not available. Web search features disabled.")

# ============================================================================
# LLM setup: llama.cpp OpenAI-compatible server (chat_format=qwen)
# ============================================================================

LLAMA_SERVER_URL = os.getenv("LLAMA_SERVER_URL", "http://127.0.0.1:8000/v1")
LLAMA_MODEL_NAME = os.getenv(
    "LLAMA_MODEL_NAME",
    "/home/gh0st/pkn/llama.cpp/models/"
    "Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf",
)

os.environ.setdefault("OPENAI_API_KEY", "local")

llm = ChatOpenAI(
    model=LLAMA_MODEL_NAME,
    base_url=LLAMA_SERVER_URL,
    temperature=0.2,
)

# ============================================================================
# Paths / memory
# ============================================================================

PROJECT_ROOT = Path("/home/gh0st/pkn")
GLOBAL_MEMORY_PATH = Path.home() / ".parakleon_memory.json"
PROJECT_MEMORY_PATH = PROJECT_ROOT / "pkn_memory.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_json(path: Path, data: Dict[str, Any]) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return f"Memory updated at {path}. Keys: {list(data.keys())}"
    except Exception as e:
        return f"Error writing memory {path}: {e}"


# ============================================================================
# Tools
# ============================================================================

@tool
def list_project_files(path: str) -> List[str]:
    """List files (non-recursive) in the given directory path."""
    p = Path(path)
    if not p.exists() or not p.is_dir():
        return [f"Directory not found: {path}"]
    try:
        return sorted([str(child.name) for child in p.iterdir()])
    except Exception as e:
        return [f"Error listing directory {path}: {e}"]


@tool
def read_file(path: str) -> str:
    """Read and return the text content of a UTF-8 file (under project root for safety)."""
    try:
        p = Path(path)
        p = p if p.is_absolute() else PROJECT_ROOT / p
        p = p.resolve()
        root = PROJECT_ROOT.resolve()
        if not str(p).startswith(str(root)):
            return f"Refused to read outside project root: {p}"
    except Exception as e:
        return f"Error resolving path {path}: {e}"

    if not p.is_file():
        return f"File not found: {p}"
    try:
        return p.read_text(encoding="utf-8")
    except Exception as e:
        return f"Error reading {p}: {e}"


@tool
def run_command(cmd: str, cwd: str = str(PROJECT_ROOT)) -> str:
    """Run a shell command in the project directory and return stdout/stderr."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=120,
        )
        return (
            f"EXIT {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
    except Exception as e:
        return f"Error running command '{cmd}': {e}"


@tool
def http_get(url: str) -> str:
    """Fetch the raw text content of a URL for the agent to read."""
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        return resp.text[:8000]
    except Exception as e:
        return f"Error fetching {url}: {e}"


@tool
def read_global_memory() -> str:
    """Read global Parakleon memory as JSON text."""
    data = _load_json(GLOBAL_MEMORY_PATH)
    if not data:
        return "Global memory empty."
    return json.dumps(data, indent=2)


@tool
def write_global_memory(key: str, value: str) -> str:
    """Write or update a global memory entry under the given key."""
    data = _load_json(GLOBAL_MEMORY_PATH)
    data[key] = value
    return _save_json(GLOBAL_MEMORY_PATH, data)


@tool
def read_project_memory() -> str:
    """Read project-specific memory as JSON text."""
    data = _load_json(PROJECT_MEMORY_PATH)
    if not data:
        return "Project memory empty."
    return json.dumps(data, indent=2)


@tool
def write_project_memory(key: str, value: str) -> str:
    """Write or update a project memory entry under the given key."""
    data = _load_json(PROJECT_MEMORY_PATH)
    data[key] = value
    return _save_json(PROJECT_MEMORY_PATH, data)


@tool
def write_file_with_backup(path: str, content: str) -> str:
    """
    Write text content to a file under the project root, creating/overwriting
    a single backup file (<path>.bak) first.
    """
    try:
        p = Path(path)
        p = p if p.is_absolute() else PROJECT_ROOT / p
        p = p.resolve()
        root = PROJECT_ROOT.resolve()

        if not str(p).startswith(str(root)):
            return f"Refused to write outside project root: {p}"

        backup_path = p.with_suffix(p.suffix + ".bak")
        p.parent.mkdir(parents=True, exist_ok=True)

        if p.is_file():
            try:
                backup_path.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
            except Exception as e:
                return f"Error writing backup {backup_path}: {e}"

        try:
            p.write_text(content, encoding="utf-8")
        except Exception as e:
            return f"Error writing to {p}: {e}"

        return f"Wrote {len(content)} characters to {p} (backup at {backup_path})"

    except Exception as e:
        return f"Error in write_file_with_backup for {path}: {e}"


# ============================================================================
# Web Access Tools (Enhanced Capabilities)
# ============================================================================

if WEB_TOOLS_AVAILABLE:
    @tool
    def web_search(query: str, max_results: int = 5) -> str:
        """
        Search the web using DuckDuckGo (privacy-focused).
        Returns JSON with list of {title, url, snippet}.
        Use this when you need current information, documentation, or research.
        """
        return search(query)

    @tool
    def fetch_url(url: str) -> str:
        """
        Fetch a URL and extract its text content (HTML to markdown).
        Returns JSON with {url, title, content}.
        Use this to read documentation, blog posts, or any web page.
        """
        return fetch(url)

    @tool
    def wikipedia_search(topic: str) -> str:
        """
        Look up a topic on Wikipedia.
        Returns JSON with {title, summary, url}.
        Use this for quick factual lookups and topic overviews.
        """
        return wiki(topic)

    @tool
    def search_github(query: str, max_results: int = 5) -> str:
        """
        Search GitHub repositories.
        Returns JSON with list of {name, url, description, stars, language}.
        Use this to find code examples, libraries, and open source projects.
        """
        return github(query)


# ============================================================================
# Tool Registration
# ============================================================================

tools = [
    list_project_files,
    read_file,
    run_command,
    http_get,
    read_global_memory,
    write_global_memory,
    read_project_memory,
    write_project_memory,
    write_file_with_backup,
]

# Add web tools if available
if WEB_TOOLS_AVAILABLE:
    tools.extend([
        web_search,
        fetch_url,
        wikipedia_search,
        search_github,
    ])
llm_with_tools = llm.bind_tools(tools)
tool_map = {t.name: t for t in tools}

# ============================================================================
# Core agent runner
# ============================================================================

def run_agent(user_instruction: str) -> str:
    """
    Run a one-shot tool-using agent on the local Qwen model.
    """
    system = SystemMessage(
        content=(
            "You are Parakleon, a master local AI agent specializing in software development, "
            "tool use, and system assistance.\n\n"
            "Style:\n"
            "- Explain things in a natural, conversational way.\n"
            "- Prefer short paragraphs and bullet points over dense walls of text.\n"
            "- Avoid overusing headings and boilerplate like 'Step 1' unless asked.\n"
            "- When you propose code, briefly explain what it does and why in plain language.\n\n"
            "Capabilities:\n"
            "- Understand and navigate project directories.\n"
            "- Read and write code across languages (Python, JavaScript/TypeScript, HTML/CSS, Bash).\n"
            "- Use tools to inspect files, run commands, access persistent memory (global and project).\n"
            "- Web access: Search DuckDuckGo, fetch URLs, look up Wikipedia articles, search GitHub repos.\n"
            "- Use web tools to find documentation, research libraries, check current best practices.\n"
            "- Ask precise clarifying questions when instructions are ambiguous.\n\n"
            "Editing behavior:\n"
            "- You can propose both small, incremental edits and large, full-file rewrites.\n"
            "- Prefer small, precise edits when they are sufficient to solve the problem.\n"
            "- Propose full rewrites only when the existing code is fundamentally flawed, "
            "unmaintainable, or when the user explicitly requests a complete script from scratch.\n"
            "- When suggesting large changes, clearly separate old vs new structure and explain the "
            "rationale briefly.\n\n"
            "Self-improvement:\n"
            "- You may analyze your own behavior, prompts, and tools and propose improvements.\n"
            "- When changing your own Python agent code, always use write_file_with_backup so a single "
            "backup exists.\n"
            "- Before large self-changes, explain the intended benefits and possible risks.\n\n"
            "General behavior:\n"
            "- Use tools (filesystem, commands, memory, web) before guessing about the code or environment.\n"
            "- Be explicit and concrete about which files and sections to change.\n"
        )
    )

    messages = [
        system,
        HumanMessage(content=user_instruction),
    ]

    # First model call: may request tools
    ai_resp: AIMessage = llm_with_tools.invoke(messages)
    messages.append(ai_resp)

    # Execute requested tools
    for tc in ai_resp.tool_calls or []:
        tool_name = tc["name"]
        tool_args = tc["args"]
        tool_id = tc["id"]

        tool_fn = tool_map.get(tool_name)
        if tool_fn is None:
            tool_output = f"Tool '{tool_name}' not found."
        else:
            tool_output = tool_fn.invoke(tool_args)

        messages.append(
            ToolMessage(
                content=str(tool_output),
                name=tool_name,
                tool_call_id=tool_id,
            )
        )

    # Final reasoning / answer
    final_resp: AIMessage = llm_with_tools.invoke(messages)
    return final_resp.content


# ============================================================================
# Simple CLI usage
# ============================================================================

if __name__ == "__main__":
    import textwrap

    default_instruction = (
        "Read global and project memory to refresh context. Then focus on the Divine Node / Parakleon project "
        "at /home/gh0st/pkn. List top-level files, read the real pkn.html and the primary JS/backend entry file, "
        "and propose concise, actionable code changes to stabilize and improve the UI. "
        "Focus on only a small number of key files."
    )

    print("=" * 80)
    print("PARAKLEON LOCAL CODING AGENT")
    print("=" * 80)
    print("llama.cpp server: 127.0.0.1:8000")
    print("Model: Qwen2.5-Coder-14B-Instruct (Q4_K_M)")
    print("=" * 80)
    print()

    print("Press Enter to use the default instruction, or type your own.\n")
    user_instruction = input("Instruction> ").strip()
    if not user_instruction:
        user_instruction = default_instruction

    print("\n" + "=" * 80)
    print("Running agent...\n")
    result = run_agent(user_instruction)
    print(textwrap.fill(result, width=100))
    print("\n" + "=" * 80)
