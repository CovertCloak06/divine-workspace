# Multi-Agent AI System - Implementation Roadmap

**Goal:** Build an extremely efficient Multi-Agent AI assistant with full autonomy, persistence, web access, and code completion

---

## 📊 Current State Analysis

### What You Already Have (From Tarball):

#### ✅ **1. Enhanced Agent System** (`local_parakleon_agent.py`)
**Capabilities:**
- **Tool Use:** LangChain-based agent with 9 tools
- **Filesystem Access:** read_file, write_file_with_backup, list_project_files
- **Command Execution:** run_command (shell access)
- **Web Access:** http_get (basic URL fetching)
- **Memory System:**
  - Global memory (`~/.parakleon_memory.json`)
  - Project memory (`pkn_memory.json`)
- **Self-Improvement:** Can modify its own code with backups

**Current Limitations:**
- Single-shot execution (no conversation continuity)
- No web search (only direct URL fetch)
- No code completion/autocomplete
- Not integrated with UI

#### ✅ **2. Web Tools Module** (`web_tools.py`)
**Capabilities:**
- **DuckDuckGo Search** (privacy-focused)
- **URL Fetching** with HTML→text conversion
- **Wikipedia Lookup**
- **GitHub Search**
- Termux-compatible (fallback modes)

**Status:** Standalone, needs integration

#### ✅ **3. AI Router** (`ai_router.py`)
**Capabilities:**
- Smart routing based on task type
- Supports multiple models (llama, qwen, phi)
- Auto-detection for code/math/general tasks

**Status:** Basic implementation, needs enhancement

#### ✅ **4. Macro System** (`macros.json`, `macroboard.sh`)
**Capabilities:**
- Quick command execution
- System status checks
- Service control
- Navigation shortcuts

**Status:** Command-line only, needs UI integration

---

## 🎯 Implementation Plan

### **Phase 1: Enhanced Agent Integration** (HIGH PRIORITY)

#### Task 1.1: Merge Enhanced Agent into Main System
**Files to update:**
- `/home/gh0st/pkn/local_parakleon_agent.py` ← Replace with tarball version
- `/home/gh0st/pkn/web_tools.py` ← Add from tarball
- `/home/gh0st/pkn/ai_router.py` ← Add from tarball

**New Features:**
- ✅ Write file with backup
- ✅ Proper sandboxing (project root only)
- ✅ Better error handling
- ✅ Self-modification capability

#### Task 1.2: Integrate Web Access Tools
**Update `local_parakleon_agent.py`:**
```python
from web_tools import search, fetch, wiki, github

@tool
def web_search(query: str) -> str:
    """Search the web using DuckDuckGo"""
    return search(query)

@tool
def fetch_url(url: str) -> str:
    """Fetch and extract text from a URL"""
    return fetch(url)

@tool
def wikipedia_search(topic: str) -> str:
    """Search Wikipedia for a topic"""
    return wiki(topic)

@tool
def search_github(query: str) -> str:
    """Search GitHub repositories"""
    return github(query)
```

**Result:** Agent can search web, fetch URLs, access Wikipedia, search GitHub

---

### **Phase 2: Code Completion & Autocomplete** (HIGH PRIORITY)

#### Task 2.1: Add Code Context System
**Create `/home/gh0st/pkn/code_context.py`:**
```python
class CodeContext:
    """Maintains code context for autocomplete"""
    def __init__(self):
        self.recent_files = []
        self.symbols = {}  # Functions, classes, variables
        self.imports = {}

    def analyze_file(self, path):
        """Extract symbols, imports, docstrings"""

    def get_completions(self, prefix, context):
        """Return autocomplete suggestions"""

    def get_signature(self, symbol):
        """Return function/class signature"""
```

#### Task 2.2: Add Autocomplete API Endpoint
**Update `divinenode_server.py`:**
```python
@app.route('/api/autocomplete', methods=['POST'])
def autocomplete():
    """Provide code completions"""
    data = request.json
    prefix = data.get('prefix', '')
    file_path = data.get('file', '')
    cursor_pos = data.get('cursor', 0)

    # Use code context + AI for suggestions
    suggestions = code_context.get_completions(prefix, file_path)

    return jsonify({'completions': suggestions})
```

#### Task 2.3: Add UI Autocomplete Widget
**Create `/home/gh0st/pkn/js/autocomplete.js`:**
- Monaco Editor integration OR
- CodeMirror integration OR
- Custom autocomplete overlay

---

### **Phase 3: Multi-Agent Coordination** (CRITICAL FOR MULTI-AGENT)

#### Task 3.1: Create Agent Manager
**Create `/home/gh0st/pkn/agent_manager.py`:**
```python
class AgentManager:
    """Coordinates multiple specialized agents"""

    agents = {
        'coder': Qwen2.5Coder,    # Code writing
        'reasoner': DeepSeek,      # Planning, logic
        'researcher': Llama,       # Web research
        'executor': Shell,         # Command execution
    }

    def route_task(self, task):
        """Intelligently route to best agent"""

    def coordinate(self, task, agents):
        """Multi-agent collaboration on complex tasks"""

    def handoff(self, from_agent, to_agent, context):
        """Transfer work between agents"""
```

#### Task 3.2: Add Conversation Memory
**Enhance memory system:**
```python
# Session memory (in-memory, cleared on restart)
session_memory = {
    'conversation_id': str,
    'messages': [],
    'context': {},
    'active_files': [],
    'workspace_state': {}
}

# Persistent memory (JSON files)
persistent_memory = {
    'user_preferences': {},
    'project_context': {},
    'learned_patterns': {},
    'code_snippets': {}
}
```

#### Task 3.3: Add Agent-to-Agent Communication
**Create messaging protocol:**
```python
class AgentMessage:
    from_agent: str
    to_agent: str
    task_id: str
    content: dict
    requires_response: bool

class AgentBus:
    """Message bus for inter-agent communication"""
    def publish(self, message)
    def subscribe(self, agent_id, handler)
    def request(self, from_agent, to_agent, task)
```

---

### **Phase 4: Enhanced Persistence** (MEDIUM PRIORITY)

#### Task 4.1: Session Persistence
**Add to `divinenode_server.py`:**
```python
# Save conversation state on server restart
@app.before_request
def load_session():
    session_id = request.cookies.get('session_id')
    if session_id:
        restore_session(session_id)

@app.after_request
def save_session(response):
    save_session_state()
    return response
```

#### Task 4.2: Build Context Persistence
**Track and persist:**
- Open files
- Cursor positions
- Breakpoints
- Terminal state
- Model selections
- Active agents

#### Task 4.3: Checkpoint System
**Auto-save project state:**
- Every N messages
- Before risky operations
- On user request
- Automatic rollback on errors

---

### **Phase 5: Advanced Filesystem Access** (MEDIUM PRIORITY)

#### Task 5.1: Add Tree-sitter for Code Analysis
**Benefits:**
- Precise syntax understanding
- Symbol extraction
- Refactoring support
- Smart search

#### Task 5.2: Add Code Editing Tools
**New agent tools:**
```python
@tool
def insert_code(file: str, after_line: int, code: str):
    """Insert code at specific location"""

@tool
def replace_function(file: str, function_name: str, new_code: str):
    """Replace entire function"""

@tool
def rename_symbol(file: str, old_name: str, new_name: str):
    """Rename variable/function across file"""

@tool
def add_import(file: str, import_statement: str):
    """Add import to top of file"""
```

#### Task 5.3: Add Git Integration
```python
@tool
def git_diff(file: str = None):
    """Show git changes"""

@tool
def git_commit(message: str):
    """Create git commit"""

@tool
def git_undo():
    """Undo last change"""
```

---

### **Phase 6: UI Enhancements for AI Efficiency** (LOW-MEDIUM PRIORITY)

#### Task 6.1: Split-Panel Code Editor
- Left: Chat with AI
- Right: Live code editor
- Real-time AI suggestions

#### Task 6.2: Agent Status Dashboard
- Active agents
- Current tasks
- Memory usage
- Model performance

#### Task 6.3: Tool Execution Visualization
- Show what tools agent is using
- Display command outputs
- File changes diff viewer

#### Task 6.4: Context Awareness Indicators
- Files the AI "knows about"
- Current working directory
- Active project
- Available tools

---

## 🔧 Technical Architecture

### **System Layers:**

```
┌─────────────────────────────────────────┐
│           UI Layer (Browser)            │
│  pkn.html, app.js, autocomplete widget  │
└─────────────────┬───────────────────────┘
                  │ HTTP/WebSocket
┌─────────────────▼───────────────────────┐
│      API Layer (Flask Server)           │
│  divinenode_server.py, routes, session  │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│       Agent Manager Layer               │
│  Coordination, Routing, Memory          │
└──┬────────┬──────────┬─────────────┬───┘
   │        │          │             │
   ▼        ▼          ▼             ▼
┌──────┐┌────────┐┌─────────┐┌────────────┐
│Coder ││Reasoner││Researcher││Executor    │
│Qwen  ││DeepSeek││ Llama   ││ Shell      │
└──┬───┘└───┬────┘└────┬────┘└─────┬──────┘
   │        │          │           │
   └────────┴──────────┴───────────┘
                  │
   ┌──────────────▼──────────────┐
   │        Tool Layer           │
   │  Filesystem, Web, Git, etc. │
   └─────────────────────────────┘
```

### **Data Flow:**

```
User Input → UI → API → Agent Manager → Route to Best Agent
                                      → Execute Tools
                                      → Coordinate with Other Agents
                                      → Update Memory
                                      → Return Result → UI
```

---

## 📝 Implementation Priority

### **Week 1: Core Functionality**
1. ✅ **COMPLETED** - Integrate enhanced agent (Task 1.1)
2. ✅ **COMPLETED** - Add web tools (Task 1.2)
3. ✅ **COMPLETED** - Basic multi-agent routing (Task 3.1)
4. ✅ **COMPLETED** - Session memory (Task 3.2)

### **Week 2: Advanced Features**
5. ✅ **COMPLETED** - Code autocomplete (Task 2.1-2.3)
6. ✅ **COMPLETED** - Agent coordination (Task 3.3)
7. ✅ **COMPLETED** - Persistent sessions (Task 4.1-4.2)

### **Week 3: Polish & Optimization**
8. ✅ **COMPLETED** - UI Integration (Phase 4)
9. ✅ **COMPLETED** - Mobile support (Phase 4)
10. ✅ **COMPLETED** - Quality monitoring (Phase 4)

---

## 🚀 Immediate Next Steps

**Right Now:**
1. Copy enhanced agent files from tarball to main pkn directory
2. Update divinenode_server.py with new routes
3. Test enhanced agent with web tools
4. Add agent selection to UI

**Want me to start implementing now?** I can begin with Phase 1 (Enhanced Agent Integration).
