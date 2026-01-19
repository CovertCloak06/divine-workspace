# Tools Reference

Complete reference for all agent tools in PKN.

**Related Docs:**
- [Agents Reference](./AGENTS.md) - Which agents use which tools
- [Shadow OSINT](./SHADOW_OSINT.md) - Detailed OSINT documentation (35 tools)
- [Architecture](./ARCHITECTURE.md) - How tools integrate

## Tool Modules Overview

| Module | Tools | Purpose | Location |
|--------|-------|---------|----------|
| code_tools | 4 | Code editing, AST parsing | `backend/tools/code_tools.py` |
| file_tools | 5 | File search, glob, grep | `backend/tools/file_tools.py` |
| system_tools | 7 | Shell commands, process mgmt | `backend/tools/system_tools.py` |
| web_tools | 6 | HTTP requests, scraping | `backend/tools/web_tools.py` |
| memory_tools | 7 | Conversation persistence | `backend/tools/memory_tools.py` |
| osint_tools | 12 | Basic OSINT | `backend/tools/osint_tools.py` |
| rag_tools | 3 | Retrieval augmented generation | `backend/tools/rag_tools.py` |
| planning_tools | 4 | Task planning, breakdown | `backend/tools/planning_tools.py` |
| delegation_tools | 3 | Agent-to-agent messaging | `backend/tools/delegation_tools.py` |
| chain_tools | 3 | Multi-step workflows | `backend/tools/chain_tools.py` |
| sandbox_tools | 2 | Safe code execution | `backend/tools/sandbox_tools.py` |
| evaluation_tools | 3 | Response quality checks | `backend/tools/evaluation_tools.py` |
| shadow_tools | 35 | Advanced OSINT → [Shadow OSINT](./SHADOW_OSINT.md) | `backend/tools/shadow/` |

**Total: 90+ tools**

---

## Tool Modules Detail

### code_tools
Location: `backend/tools/code_tools.py`

Surgical code operations inspired by Claude Code's Edit, Write, and Read tools.

| Tool | Description | Parameters |
|------|-------------|------------|
| `read_file` | Read file with cat -n format, optional line ranges | file_path, offset, limit |
| `edit_file` | Surgical string replacement (exact match required) | file_path, old_string, new_string, replace_all |
| `write_file` | Create or overwrite files (creates backups) | file_path, content |
| `append_file` | Append content to end of file | file_path, content |

**Example: Edit a bug**
```python
edit_file(
    "app.js",
    old_string="if (x = 5)",
    new_string="if (x === 5)"
)
```

**Safety Features:**
- Automatic backups (.bak files)
- Path validation (must be within project root)
- Uniqueness check (prevents ambiguous replacements)

---

### file_tools
Location: `backend/tools/file_tools.py`

File search and discovery inspired by Claude Code's Glob and Grep.

| Tool | Description | Parameters |
|------|-------------|------------|
| `glob` | Find files by pattern (e.g., `**/*.py`) | pattern, path |
| `grep` | Search file contents with regex | pattern, path, output_mode, context_lines, case_insensitive |
| `find_definition` | Find function/class definitions by name | name, path |
| `tree` | Show directory tree structure | path, depth |
| `file_info` | Get detailed file statistics | file_path |

**Output Modes:**
- `files_with_matches` - Just list files (default)
- `content` - Show matching lines with context
- `count` - Show match counts per file

**Example: Find TODO comments**
```python
grep(
    pattern="TODO",
    output_mode="content",
    context_lines=2
)
```

---

### system_tools
Location: `backend/tools/system_tools.py`

Terminal and system control with maximum power.

| Tool | Description | Parameters |
|------|-------------|------------|
| `bash` | Execute any shell command | command, cwd, timeout, description |
| `bash_background` | Execute command in background | command, cwd, description |
| `process_list` | List running processes | filter_pattern |
| `process_kill` | Kill process by PID or name | pid_or_name, force |
| `read_logs` | Tail log files | file_path, lines, follow |
| `todo_write` | Create visual task lists for user | todos |
| `system_info` | Get CPU, memory, disk usage | - |

**Safety Notes:**
- Commands run with current user permissions
- Timeout prevents infinite loops (default 120s, max 600s)
- `bash_background` returns PID for tracking

**Example: Install package**
```python
bash(
    "pip install flask",
    description="Install Flask package",
    timeout=60
)
```

---

### web_tools
Location: `backend/tools/web_tools.py`

Internet research and data retrieval with privacy focus.

| Tool | Description | Parameters |
|------|-------------|------------|
| `web_search` | DuckDuckGo search (privacy-focused) | query, max_results |
| `fetch_url` | Get webpage content as markdown | url, extract_text |
| `wiki_lookup` | Wikipedia article summaries | topic |
| `github_search` | Find GitHub repositories | query, max_results |
| `stack_overflow_search` | Search Stack Overflow Q&A | query, max_results |
| `docs_search` | Search library documentation | library, query |

**Example: Research Flask SSE**
```python
result = web_search("Flask server-sent events example", max_results=5)
# Returns JSON with {title, url, snippet}

# Then fetch detailed content
content = fetch_url(result["results"][0]["url"])
# Returns markdown-formatted text
```

**Supported Documentation Sites:**
- Python, Flask, Django, FastAPI
- JavaScript, React, Vue, Node.js
- NumPy, Pandas

---

### memory_tools
Location: `backend/tools/memory_tools.py`

Persistent memory and context management for agents.

| Tool | Description | Parameters |
|------|-------------|------------|
| `save_context` | Store information for later retrieval | key, value, scope, tags |
| `recall_context` | Retrieve saved information | key, scope |
| `save_snippet` | Save reusable code snippets | name, code, language, description, tags |
| `get_snippet` | Retrieve saved code snippet | name |
| `search_memory` | Search through saved memories | query, scope |
| `list_memories` | List all saved contexts/snippets | scope |
| `clear_memory` | Clear specific or all memories | key, scope |

**Scopes:**
- `project` - This project only (default)
- `global` - All projects
- `snippets` - Code snippets collection

**Example: Remember API pattern**
```python
save_context(
    key="api_pattern",
    value="Use Flask-CORS for cross-origin requests",
    tags=["api", "cors", "flask"]
)

# Later retrieve
pattern = recall_context("api_pattern")
```

**Storage Locations:**
- Global: `~/.parakleon_memory.json`
- Project: `~/pkn/pkn_memory.json`
- Snippets: `~/pkn/code_snippets.json`

---

### osint_tools
Location: `backend/tools/osint_tools.py`

Basic OSINT (Open Source Intelligence) for ethical reconnaissance.

**Legal Notice:** These tools are for AUTHORIZED and LEGAL use only. Users must comply with applicable laws and respect privacy.

| Tool | Description | Use Case |
|------|-------------|----------|
| `whois_lookup` | Domain registration info | Find registrar, creation date, nameservers |
| `dns_lookup` | DNS records (A, MX, TXT, NS, CNAME) | Discover mail servers, subdomains |
| `reverse_dns` | IP to hostname lookup | Identify server ownership |
| `subdomain_enum` | Common subdomain enumeration | Find dev, staging, api subdomains |
| `ip_geolocation` | IP address location data | Country, city, ISP, coordinates |
| `port_scan` | Basic port scan (common ports) | Check open services (AUTHORIZED ONLY) |
| `email_validate` | Email format and MX record check | Verify email deliverability |
| `haveibeenpwned_check` | Check email in breach databases | Security awareness |
| `username_search` | Find username on social platforms | Profile discovery |
| `wayback_check` | Check Wayback Machine archives | Historical website data |
| `web_technologies` | Detect website technologies | CMS, frameworks, libraries |
| `ssl_certificate` | SSL/TLS certificate information | Certificate validation |

**Example: Domain investigation**
```python
# Step 1: WHOIS lookup
whois_data = whois_lookup("example.com")

# Step 2: DNS records
dns_data = dns_lookup("example.com")

# Step 3: Find subdomains
subdomains = subdomain_enum("example.com")

# Step 4: Check SSL certificate
ssl_info = ssl_certificate("example.com")
```

For advanced OSINT, see [Shadow OSINT](./SHADOW_OSINT.md) (35 specialized tools).

---

### rag_tools
Location: `backend/tools/rag_tools.py`

Retrieval Augmented Generation - Semantic search over codebase.

**Dependencies:** `chromadb`, `sentence-transformers`

| Tool | Description | Parameters |
|------|-------------|------------|
| `index_codebase` | Index all code files for semantic search | extensions |
| `search_code` | Search codebase for relevant snippets | query, n_results, file_type |
| `search_docs` | Search documentation | query, n_results |

**Features:**
- Semantic search using embeddings (all-MiniLM-L6-v2)
- ChromaDB for vector storage
- Automatic chunking for large files (500 lines per chunk)
- Separate collections for code and docs

**Example: Find multi-agent coordination code**
```python
# First, index codebase (one-time)
rag = RAGMemory()
rag.index_codebase()

# Search for relevant code
results = search_code("multi-agent coordination", n_results=5)
# Returns: [{"content": "...", "file": "...", "relevance_score": 0.85}, ...]
```

**Storage:** `.chroma_db/` in project root

---

### planning_tools
Location: `backend/tools/planning_tools.py`

Breaks complex tasks into structured plans before execution.

**Classes:**
- `TaskPlanner` - Creates execution plans
- `PlanExecutor` - Executes plans step-by-step

**Step Types:**
- `TOOL_CALL` - Call a tool
- `CONDITION` - Conditional branch
- `LOOP` - Repeat steps
- `TRANSFORM` - Transform data
- `AGGREGATE` - Combine results

**Example: Create plan for code analysis**
```python
planner = TaskPlanner(llm_client)
plan = planner.create_plan(
    task="Find all TODO comments and create summary report",
    context={"project_root": "/home/gh0st/pkn"}
)

# Plan structure:
# {
#   "goal": "...",
#   "steps": [
#     {"action": "Find Python files", "agent": "executor", ...},
#     {"action": "Search for TODO", "agent": "coder", ...},
#     {"action": "Generate report", "agent": "general", ...}
#   ],
#   "estimated_total_duration": 120
# }

# Execute plan
executor = PlanExecutor(agent_manager)
result = executor.execute_plan(plan, session_id)
```

**Saved Plans:** `memory/plans/plan_{id}.json`

---

### delegation_tools
Location: `backend/tools/delegation_tools.py`

Agent-to-agent collaboration and delegation.

**Classes:**
- `AgentDelegationManager` - Manages delegation and messaging

**Message Types:**
- `REQUEST` - Request for help
- `RESPONSE` - Response to request
- `QUERY` - Question to another agent
- `RESULT` - Result of delegated task
- `ERROR` - Error notification

**Example: Delegate task**
```python
manager = AgentDelegationManager(agent_manager)

# Coder asks Reasoner for help
delegation = manager.delegate_task(
    from_agent="coder",
    to_agent="reasoner",
    task="Create a plan for optimizing this function",
    context={"code": "def slow_func(): ..."},
    parent_task_id="task_123"
)

# Execute delegation
result = manager.execute_delegation(delegation.id, session_id)
```

**Agent Capabilities Map:**
```python
{
    "coder": ["write code", "debug code", "refactor code"],
    "reasoner": ["create plan", "analyze problem", "make decision"],
    "researcher": ["find information", "search documentation"],
    "executor": ["run command", "execute script", "test code"],
    "general": ["answer question", "explain concept"]
}
```

**Multi-Agent Collaboration:**
```python
result = manager.collaborate(
    agents=["coder", "reasoner", "researcher"],
    task="Build a web scraper with error handling",
    session_id=session_id,
    coordinator="reasoner"
)
```

---

### chain_tools
Location: `backend/tools/chain_tools.py`

Sequential and conditional execution of multiple tools.

**Classes:**
- `ToolChainExecutor` - Executes tool chains

**Features:**
- Variable substitution (`$variable`)
- Conditional branches
- Data transformations
- Tool result aggregation

**Example: Chain tools together**
```python
executor = ToolChainExecutor(tool_registry)

# Create chain
chain = executor.create_chain(
    name="find_todos",
    description="Find all TODO comments and create summary"
)

# Set initial variables
chain.variables = {
    "project_root": "/home/gh0st/pkn",
    "search_pattern": "TODO"
}

# Add steps
executor.add_tool_step(
    chain,
    tool_name="file_tools.glob",
    parameters={"pattern": "*.py", "path": "$project_root"},
    save_as="python_files"
)

executor.add_tool_step(
    chain,
    tool_name="file_tools.grep",
    parameters={"pattern": "$search_pattern", "files": "$python_files"},
    save_as="todo_matches"
)

executor.add_transform_step(
    chain,
    transform_func="count",
    input_var="todo_matches",
    save_as="todo_count"
)

# Execute
result = executor.execute_chain(chain)
# result["final_variables"]["todo_count"] = 42
```

**Transform Functions:**
- `to_json`, `from_json`
- `to_list`, `count`
- `first`, `last`
- `join`, `split`

---

### sandbox_tools
Location: `backend/tools/sandbox_tools.py`

Safely execute code in Docker containers.

**Classes:**
- `CodeSandbox` - Isolated code execution

**Supported Languages:**
- Python (python:3.11-slim)
- JavaScript (node:18-slim)
- Shell (with command whitelist)

**Resource Limits:**
- Memory: 512MB
- CPU: 50% of one core
- Timeout: 30 seconds
- Network: None (isolated)

**Example: Execute Python code**
```python
sandbox = CodeSandbox()

code = """
import math
result = math.sqrt(16)
print(f"Square root of 16 is {result}")
"""

result = sandbox.execute_python(code)
# {
#   "success": True,
#   "output": "Square root of 16 is 4.0\n",
#   "language": "python"
# }
```

**Example: Test code with assertions**
```python
code = """
def add(a, b):
    return a + b
"""

tests = [
    "assert add(2, 3) == 5",
    "assert add(-1, 1) == 0",
    "assert add(0, 0) == 0"
]

result = sandbox.test_code(code, "python", tests)
```

**Fallback:** If Docker unavailable, uses subprocess (less secure, with warning).

---

### evaluation_tools
Location: `backend/tools/evaluation_tools.py`

Monitors agent performance and provides improvement insights.

**Classes:**
- `AgentEvaluator` - Tracks and evaluates agent performance

**Tracked Metrics:**
- Execution count
- Success rate
- Average duration
- User feedback ratings (1-5 stars)
- Performance by task category

**Example: Track agent execution**
```python
evaluator = AgentEvaluator()

# Log execution
evaluator.log_execution(
    agent_type="coder",
    task="Write a Python function to parse CSV",
    response="def parse_csv(file_path): ...",
    duration_ms=8500,
    success=True,
    tools_used=["file_tools.read_file", "code_tools.write_file"],
    session_id="session_123"
)

# Get metrics
metrics = evaluator.get_agent_metrics("coder", days=30)
# {
#   "total_executions": 150,
#   "success_rate": 94.7,
#   "avg_duration_ms": 7200,
#   "avg_user_rating": 4.2,
#   "by_category": [...]
# }
```

**Identify Weak Areas:**
```python
weak = evaluator.get_weak_areas("coder", min_failures=3)
# [
#   {
#     "category": "code_debugging",
#     "failure_rate": 35.2,
#     "example_failures": [...]
#   }
# ]
```

**Generate Improvement Suggestions:**
```python
suggestions = evaluator.generate_improvement_suggestions("coder")
# [
#   {
#     "priority": "high",
#     "issue": "High failure rate (35.2%) in code_debugging tasks",
#     "suggestions": [
#       "Review and improve system prompt for code_debugging tasks",
#       "Add specialized tools for code_debugging operations"
#     ]
#   }
# ]
```

**Export Report:**
```python
# Get summary
report = evaluator.get_summary_report(days=7)
print(report)

# Export JSON
json_file = evaluator.export_metrics()
```

**Storage:** `memory/agent_performance.db` (SQLite)

---

### shadow_tools (Advanced OSINT)
Location: `backend/tools/shadow/`

**35 specialized OSINT tools** organized into 8 categories.

See [Shadow OSINT Documentation](./SHADOW_OSINT.md) for complete details.

**Quick Overview:**

| Category | Tools | Examples |
|----------|-------|----------|
| Person Recon | 3 | Username hunt, email recon, phone lookup |
| People Search | 4 | Find by name, birthdate, location, relatives |
| Profiler | 6 | Build profiles, track confidence, cross-reference |
| Domain Recon | 4 | Certificate transparency, historical DNS, subdomains |
| Network Recon | 4 | IP ASN lookup, BGP routes, shodan integration |
| Dork Generation | 3 | Google dorks, GitHub dorks, Shodan queries |
| Orchestration | 3 | Multi-tool workflows, batch processing |
| Image Recon | 8 | EXIF, GPS, OCR, reverse image search |

**Example: Complete person investigation**
```python
# Step 1: Hunt for username
profiles = shadow_username_hunt("johndoe", quick=False)

# Step 2: Check email
email_data = shadow_email_recon("john@example.com")

# Step 3: Build profile
profile = shadow_profile_create("johndoe_investigation")
shadow_profile_add_data(profile["profile_id"], "social", profiles)
shadow_profile_add_data(profile["profile_id"], "email", email_data)

# Step 4: Find more people with same name
relatives = shadow_find_by_name("John Doe", state="CA")
```

---

## Tool Configuration

Tools are registered in `backend/agents/manager.py`:

```python
def _get_tool_registry(self):
    """Register all tools for agents"""

    tools = []

    # Code tools
    from tools.code_tools import TOOLS as code_tools
    tools.extend(code_tools)

    # File tools
    from tools.file_tools import TOOLS as file_tools
    tools.extend(file_tools)

    # ... and so on for all modules

    # Shadow tools (added to SECURITY and CONSULTANT agents)
    from tools.shadow.tools import SHADOW_TOOLS
    if agent_type in ["security", "consultant"]:
        tools.extend(SHADOW_TOOLS)

    return tools
```

## Agent Tool Access

Different agents have access to different tool subsets:

| Agent | Tool Access |
|-------|-------------|
| CODER | code_tools, file_tools, system_tools, sandbox_tools |
| REASONER | planning_tools, delegation_tools, chain_tools, evaluation_tools |
| RESEARCHER | web_tools, rag_tools, osint_tools |
| EXECUTOR | system_tools, file_tools, sandbox_tools |
| GENERAL | memory_tools, basic tools |
| SECURITY | All tools + shadow_tools |
| CONSULTANT | All tools + shadow_tools |

See [Agents Reference](./AGENTS.md) for complete agent tool mappings.

## Adding New Tools

1. **Create tool in appropriate module:**

```python
from langchain_core.tools import tool

@tool
def my_new_tool(param1: str, param2: int) -> str:
    """
    Description of what the tool does.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Examples:
        my_new_tool("test", 42)
    """
    # Implementation
    return result

# Export
TOOLS = [my_new_tool]
```

2. **Register in `manager.py`:**

```python
from tools.my_module import TOOLS as my_tools
tools.extend(my_tools)
```

3. **Document in this file**

4. **Write tests** (see `tests/` directory)

See [Contributing](./CONTRIBUTING.md) for full guidelines.

## Best Practices

**Tool Design:**
- Single responsibility principle
- Clear, descriptive names
- Detailed docstrings with examples
- Error handling with informative messages
- Return structured data (JSON/dicts)

**Usage:**
- Check tool availability before use
- Validate parameters
- Handle errors gracefully
- Log important operations
- Clean up resources (files, connections)

**Security:**
- Validate file paths (prevent directory traversal)
- Sandbox untrusted code execution
- Limit resource usage (timeout, memory)
- Check permissions before operations
- Log security-sensitive actions

## Troubleshooting

**Tool not found:**
```python
# Check registration
print(agent_manager._get_tool_registry())

# Verify import
from tools.my_module import TOOLS
print(TOOLS)
```

**Permission errors:**
- Check file paths are within project root
- Verify user has required permissions
- Use `bash` tool for privileged operations

**Timeout errors:**
- Increase timeout parameter
- Optimize slow operations
- Use background execution for long tasks

**Memory errors:**
- Reduce chunk sizes (RAG tools)
- Clear caches between operations
- Use streaming for large files

## Performance Tips

**File Operations:**
- Use `glob` before `grep` to filter files
- Limit `grep` context lines to reduce output
- Use `file_info` to check size before reading

**Web Operations:**
- Cache frequently accessed URLs
- Use `fetch_url` with `extract_text=True` for text-only
- Respect rate limits (built into tools)

**Code Execution:**
- Use sandbox for untrusted code
- Set appropriate timeouts
- Clean up temp files

**Memory:**
- Tag contexts for easy searching
- Use scopes (project vs global)
- Periodically clear old memories

## Related Documentation

- [Agents](./AGENTS.md) - Agent tool access and workflows
- [Shadow OSINT](./SHADOW_OSINT.md) - Advanced OSINT tools
- [Architecture](./ARCHITECTURE.md) - System integration
- [Contributing](./CONTRIBUTING.md) - Adding new tools

---

**Last Updated:** 2026-01-18
**Version:** 1.0
**Total Tools:** 90+
