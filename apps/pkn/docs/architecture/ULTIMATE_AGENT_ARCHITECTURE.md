# 🚀 Ultimate PKN Agent Architecture

**Date:** December 29, 2025
**Goal:** Make PKN agents as powerful as Claude Code
**Status:** 🔨 Implementation Plan

---

## 🎯 Vision: Best Possible Agent Capabilities

Your agents will have:
- ✅ **Full terminal/command execution** (like Claude Code's Bash tool)
- ✅ **Surgical file editing** (like Claude Code's Edit tool)
- ✅ **Advanced file operations** (Glob, Grep, Find, Read, Write)
- ✅ **Task tracking** (TodoWrite for visual progress)
- ✅ **Web research** (Search, fetch, Wikipedia, GitHub)
- ✅ **Code generation** (Write complete files, edit snippets)
- ✅ **System monitoring** (Process management, logs, resources)
- ✅ **Memory & context** (Project and global memory)
- ✅ **Optional Claude API** (For ultimate reasoning when needed)

**Nothing held back. Maximum power.** 💪

---

## 🏗️ Architecture: Modular Tool System

### Current Structure (Limited):
```
local_parakleon_agent.py
  ├─ run_command (basic)
  ├─ read_file
  ├─ write_file_with_backup
  └─ web_tools (if available)

agent_manager.py
  ├─ Routes to agents
  └─ Calls local_parakleon_agent
```

### New Structure (Ultimate):
```
pkn/
├─ tools/                          # NEW: Specialized tool modules
│   ├─ __init__.py
│   ├─ code_tools.py               # Edit, Write, Read (surgical editing)
│   ├─ file_tools.py               # Glob, Grep, Find (search/pattern)
│   ├─ system_tools.py             # Bash, Process, TodoWrite (execution)
│   ├─ web_tools.py                # Search, Fetch (already exists, improve)
│   └─ memory_tools.py             # Enhanced memory/context
│
├─ agents/                         # NEW: Specialized agents
│   ├─ __init__.py
│   ├─ coder_agent.py              # Code generation + code_tools
│   ├─ executor_agent.py           # Command execution + system_tools
│   ├─ researcher_agent.py         # Web search + file_tools
│   └─ reasoner_agent.py           # Pure reasoning (no tools)
│
├─ agent_manager.py                # ENHANCED: Smart tool routing
└─ divinenode_server.py            # API endpoints
```

---

## 🛠️ Tool Modules Design

### 1. **code_tools.py** - Surgical Code Operations

**Tools:**
- `read_file(path, offset, limit)` - Read with line ranges (like Claude Code)
- `edit_file(path, old_string, new_string)` - Replace exact strings
- `write_file(path, content)` - Create/overwrite files
- `grep_code(pattern, path, context_lines)` - Search with context
- `format_code(path, language)` - Auto-format code

**Use cases:**
- "Fix the bug in divinenode_server.py line 340"
- "Add error handling to this function"
- "Refactor this class"

**Agent:** CODER

---

### 2. **file_tools.py** - File Search & Management

**Tools:**
- `glob(pattern, path)` - Find files by pattern (`**/*.py`)
- `grep(pattern, path, output_mode)` - Search file contents
- `find_definition(name, path)` - Find function/class definitions
- `tree(path, depth)` - Directory tree view
- `file_info(path)` - Get file stats, size, modified time

**Use cases:**
- "Find all Python files"
- "Search for 'TODO' in codebase"
- "Where is the User class defined?"

**Agents:** RESEARCHER, CODER, EXECUTOR

---

### 3. **system_tools.py** - Terminal & System Control

**Tools:**
- `bash(command, timeout, cwd)` - Execute shell commands (unrestricted)
- `bash_stream(command)` - Stream output for long commands
- `process_list(filter)` - List running processes
- `process_kill(pid_or_name)` - Kill processes
- `read_logs(path, lines, follow)` - Tail logs
- `todo_write(todos)` - Visual task tracking for user
- `system_info()` - CPU, memory, disk usage

**Use cases:**
- "Start the server"
- "Check if llama.cpp is running"
- "Monitor resource usage"
- "Create a todo list for this task"

**Agent:** EXECUTOR (primary), all agents can use `todo_write`

---

### 4. **web_tools.py** - Enhanced Web Research

**Existing + New:**
- `search(query, max_results)` - DuckDuckGo search (existing)
- `fetch(url)` - Get webpage content (existing)
- `wiki(topic)` - Wikipedia lookup (existing)
- `github(query)` - Search GitHub (existing)
- **NEW:** `docs_search(library, query)` - Search library docs
- **NEW:** `stack_overflow(query)` - Search Stack Overflow
- **NEW:** `youtube_search(query)` - Find tutorials

**Use cases:**
- "How do I use Flask-CORS?"
- "Find examples of SSE in Python"
- "Search for Termux Python tutorials"

**Agent:** RESEARCHER

---

### 5. **memory_tools.py** - Context & Learning

**Enhanced Memory:**
- `save_context(key, value, scope)` - Project, global, or session
- `recall_context(key, scope)` - Retrieve saved info
- `save_code_snippet(name, code, tags)` - Save reusable snippets
- `search_memory(query)` - Semantic search in memory
- `conversation_history(limit)` - Access chat history

**Use cases:**
- "Remember this API pattern for later"
- "What did we decide about the database?"
- "Show me snippets tagged 'flask'"

**Agents:** All agents

---

## 🤖 Agent Specializations

### **1. CODER Agent** 🔧
**Primary Tools:** code_tools, file_tools, memory_tools
**Capabilities:**
- Write complete files
- Edit existing code surgically
- Format and lint code
- Generate tests
- Refactor safely

**Example prompts:**
- "Write a Python class for user management"
- "Fix the TypeError in app.js line 234"
- "Add type hints to all functions"

---

### **2. EXECUTOR Agent** ⚡
**Primary Tools:** system_tools, file_tools, memory_tools
**Capabilities:**
- Run any shell command
- Manage processes
- Monitor system resources
- Install packages
- Start/stop services
- Stream command output

**Example prompts:**
- "Start the DivineNode server"
- "Install Flask via pip"
- "Check if port 8010 is in use"
- "Kill the stuck Python process"

**NEW FEATURE:** Actually executes instead of just routing!

---

### **3. RESEARCHER Agent** 🔍
**Primary Tools:** web_tools, file_tools, memory_tools
**Capabilities:**
- Web search (DuckDuckGo, Google)
- Documentation lookup
- GitHub/Stack Overflow search
- Wikipedia/knowledge bases
- Code example finding
- File content search

**Example prompts:**
- "Find Flask SSE examples on GitHub"
- "How does asyncio.run() work?"
- "Search for CORS issues in Flask"

---

### **4. REASONER Agent** 🧠
**Primary Tools:** memory_tools only
**Capabilities:**
- Pure reasoning (no external actions)
- Planning and strategy
- Analysis and comparison
- Pros/cons evaluation
- Architectural decisions

**Example prompts:**
- "What's the best approach for handling timeouts?"
- "Compare SQLite vs PostgreSQL for this use case"
- "Plan the implementation strategy"

---

### **5. CONSULTANT Agent** 👔
**Primary Tools:** ALL tools + optional Claude API
**Capabilities:**
- Complex multi-step tasks
- Expert-level decisions
- Uses Claude API when available
- Falls back to local LLM
- Can invoke other agents

**Example prompts:**
- "Design a complete authentication system"
- "Review this architecture and suggest improvements"
- "Debug this complex async issue"

---

## 🔌 Optional: Claude API Integration

For **ultimate power**, add Anthropic Claude as the Consultant agent:

### Benefits:
- **Most advanced reasoning** (Opus 4.5)
- **Longer context** (200k tokens)
- **Better code understanding**
- **Computer use API** (future: screen control)

### Setup:
```python
# In agent_manager.py:
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

if ANTHROPIC_API_KEY and agent_type == AgentType.CONSULTANT:
    # Use Claude API for consultant
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    response = client.messages.create(...)
else:
    # Fall back to local llama.cpp
    response = llm.invoke(...)
```

### Cost:
- **Sonnet:** $3 per million input tokens (~$0.003 per 1000)
- **Opus:** $15 per million input tokens (~$0.015 per 1000)
- Typical query: 1000-5000 tokens = $0.003-$0.075

**Totally worth it for complex tasks!**

---

## 📊 Tool Routing Strategy

**Smart routing based on task:**

| Agent Type | Primary Tools | Use Cases |
|------------|---------------|-----------|
| **CODER** | code_tools, file_tools | "Write code", "Fix bug", "Refactor" |
| **EXECUTOR** | system_tools, file_tools | "Run command", "Install", "Start server" |
| **RESEARCHER** | web_tools, file_tools | "Search", "Find docs", "Research" |
| **REASONER** | memory_tools | "Plan", "Analyze", "Compare" |
| **CONSULTANT** | ALL tools | Complex, multi-agent tasks |
| **GENERAL** | Basic tools | Simple Q&A, chat |

**All agents can use:**
- `memory_tools` (save/recall context)
- `todo_write` (track progress)

---

## 🚀 Implementation Plan

### Phase 1: Create Tool Modules (2-3 hours)
1. ✅ Create `tools/` directory
2. ✅ Build `code_tools.py` with Edit, Write, Read
3. ✅ Build `file_tools.py` with Glob, Grep, Find
4. ✅ Build `system_tools.py` with Bash, Process, TodoWrite
5. ✅ Enhance `web_tools.py` with new searches
6. ✅ Create `memory_tools.py` with enhanced memory

### Phase 2: Create Specialized Agents (1-2 hours)
1. ✅ Extract `coder_agent.py` from local_parakleon_agent
2. ✅ Create `executor_agent.py` with full execution
3. ✅ Extract `researcher_agent.py`
4. ✅ Create `reasoner_agent.py`
5. ✅ Keep `consultant_agent` in agent_manager

### Phase 3: Update Agent Manager (1 hour)
1. ✅ Add tool routing logic
2. ✅ Load tools dynamically per agent
3. ✅ Add streaming support for all tools
4. ✅ Update agent selection keywords

### Phase 4: Testing (1 hour)
1. ✅ Test each tool individually
2. ✅ Test agent routing
3. ✅ Test on real tasks
4. ✅ Create test suite

### Phase 5: Documentation (30 mins)
1. ✅ Update BUILD_README.md
2. ✅ Create TOOLS_REFERENCE.md
3. ✅ Update TERMUX_SETUP.md

**Total time:** 5-7 hours
**Result:** Agent capabilities matching or exceeding Claude Code

---

## 🎮 Usage Examples

### Example 1: Code Generation + Execution
```
User: "Create a Flask endpoint for file upload and test it"

1. Routes to CODER agent
2. CODER uses write_file() to create endpoint
3. CODER uses edit_file() to add to divinenode_server.py
4. Routes to EXECUTOR agent
5. EXECUTOR uses bash() to restart server
6. EXECUTOR uses bash() to test with curl
7. Returns results to user
```

### Example 2: Research + Implementation
```
User: "Find the best Flask SSE library and implement streaming"

1. Routes to RESEARCHER agent
2. RESEARCHER uses web_search() for Flask SSE
3. RESEARCHER uses github() to find examples
4. Routes to CODER agent
5. CODER uses edit_file() to add SSE support
6. Routes to EXECUTOR to test
7. All agents use todo_write() to show progress
```

### Example 3: System Administration
```
User: "Install Python packages, start services, monitor logs"

1. Routes to EXECUTOR agent
2. EXECUTOR uses bash("pip install -r requirements.txt")
3. EXECUTOR uses bash("./pkn_control.sh start-all")
4. EXECUTOR uses process_list() to verify
5. EXECUTOR uses read_logs() to check startup
6. Returns status to user
```

---

## 🔒 Safety & Sandboxing

### Command Execution Safety:
1. **Whitelist** safe commands (ls, cat, grep, etc.)
2. **Blacklist** dangerous commands (rm -rf, sudo, etc.)
3. **Timeout** all commands (default 120s, max 600s)
4. **Working directory** restricted to ~/pkn/ by default
5. **User confirmation** for destructive operations

### File Operation Safety:
1. **Path validation** - Stay within project directory
2. **Backups** - Auto-backup before destructive edits
3. **Read-only mode** for sensitive files
4. **Size limits** - Prevent reading/writing huge files

### Web Safety:
1. **Rate limiting** on API calls
2. **URL validation** - Block malicious URLs
3. **Content filtering** - Strip scripts from fetched pages

---

## 📱 Termux Compatibility

All tools work on Termux:

✅ **code_tools** - Same Python, works identically
✅ **file_tools** - Same file system structure
✅ **system_tools** - Full Termux command access
✅ **web_tools** - Same APIs
✅ **memory_tools** - LocalStorage + file-based

**No special handling needed!** `~/pkn` works everywhere.

---

## 💡 Key Benefits

### For You:
- **Faster development** - Agents do the heavy lifting
- **Better code quality** - Surgical edits, no rewrites
- **Learning tool** - See how experts would solve problems
- **Multi-tasking** - Agents work in parallel
- **Offline capable** - Local LLM for privacy

### For Your Agents:
- **More powerful** - Tools for every task
- **More accurate** - Right tool for the job
- **Better UX** - TodoWrite shows progress
- **Extensible** - Easy to add new tools

### For Your Users:
- **Transparent** - See exactly what agents are doing
- **Controllable** - Approve commands before execution
- **Fast** - No unnecessary rewrites
- **Reliable** - Proper error handling

---

## 🎯 Success Metrics

After implementation, your agents will:

- ✅ Execute **any** shell command (like Claude Code)
- ✅ Edit files **surgically** (no full rewrites)
- ✅ Search codebases **efficiently** (Glob/Grep)
- ✅ Track tasks **visually** (TodoWrite)
- ✅ Research **comprehensively** (web tools)
- ✅ Run **in parallel** (multi-agent orchestration)
- ✅ Work **offline** (Termux compatible)
- ✅ Scale to **Claude API** (optional upgrade)

**Your PKN will be as powerful as Claude Code, but customized for YOUR workflow.**

---

## 🚦 Ready to Start?

I'll implement this in phases:

**Phase 1 (NOW):** Create all tool modules
**Phase 2:** Create specialized agents
**Phase 3:** Update agent_manager
**Phase 4:** Test everything
**Phase 5:** Documentation

**Each phase is independent** - we can test as we go.

**Estimated completion:** 5-7 hours of focused work (I'll be fast!)

---

## ❓ Your Decision Points:

Before I start, confirm:

1. **Claude API:** Do you have an Anthropic API key? (Optional, can add later)
2. **Safety level:**
   - Option A: Whitelist safe commands only (safer)
   - Option B: Allow all commands with confirmation (more powerful)
   - Option C: Trust agent completely (maximum power, your choice)
3. **Tool priority:** Start with which tools first?
   - Option A: code_tools + file_tools (for development)
   - Option B: system_tools (for execution/automation)
   - Option C: All at once (comprehensive)

**Let me know and I'll start building immediately!** 🚀

---

*Ultimate Agent Architecture Plan*
*December 29, 2025*
*Let's make PKN unstoppable!*
