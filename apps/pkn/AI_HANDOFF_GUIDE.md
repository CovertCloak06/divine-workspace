# PKN - AI Development Handoff Guide

**For AI Assistants Continuing This Project**

This guide provides everything an AI needs to understand, maintain, and extend the PKN (Parakleon) multi-agent system.

**Date:** December 31, 2025
**Status:** Production Ready
**Platform:** Linux (PC) + Android (Termux)

---

## 📋 Project Overview

### What is PKN?

PKN is a self-hosted, privacy-first multi-agent AI system that combines:
- 6 specialized AI agents with automatic routing
- Local LLM inference (llama.cpp + Qwen2.5-Coder-14B)
- Modern web UI with cyberpunk aesthetics
- Terminal CLI for keyboard-driven workflow
- OSINT (Open Source Intelligence) capabilities
- File management and analysis
- Cross-platform support (Linux PC + Android/Termux)

### Core Philosophy
- **Privacy-first:** Everything runs locally
- **Multi-agent:** Right agent for each task
- **User-friendly:** Both GUI and CLI interfaces
- **Extensible:** Easy to add new tools and agents
- **Production-ready:** Error handling, health monitoring, auto-recovery

---

## 🗂️ Project Structure

```
/home/gh0st/pkn/
├── divinenode_server.py          # Flask web server (1,953 lines)
├── agent_manager.py              # Multi-agent coordinator (625 lines)
├── conversation_memory.py        # Session persistence
├── code_context.py               # Code analysis tools
├── local_parakleon_agent.py      # Local LLM agent
├── pkn_cli.py                    # Terminal CLI (400 lines)
├── pkn_control.sh                # Service management script
├── pkn-cli                       # CLI launcher
├── system_check.sh               # Integrity verification
├── prepare_android.sh            # Android package builder
│
├── tools/                        # Agent tools
│   ├── code_tools.py             # Code operations
│   ├── file_tools.py             # File system
│   ├── web_tools.py              # HTTP requests
│   ├── osint_tools.py            # Intelligence gathering (NEW)
│   ├── memory_tools.py           # Conversation memory
│   ├── system_tools.py           # Shell commands
│   ├── rag_tools.py              # Vector database RAG
│   ├── planning_tools.py         # Task planning
│   ├── delegation_tools.py       # Agent delegation
│   ├── chain_tools.py            # Tool chaining
│   ├── sandbox_tools.py          # Code execution
│   └── evaluation_tools.py       # Agent metrics
│
├── js/                           # Frontend modules
│   ├── files.js                  # File explorer (NEW dropdown menus)
│   ├── osint_ui.js               # OSINT interface (NEW)
│   ├── multi_agent_ui.js         # Agent routing UI
│   ├── chat.js                   # Chat interface
│   ├── autocomplete.js           # Code completion
│   ├── agent_quality.js          # Performance monitoring
│   ├── images.js                 # Image generation
│   ├── projects.js               # Project management
│   ├── settings.js               # User settings
│   ├── models.js                 # Model selection
│   └── storage.js                # LocalStorage wrapper
│
├── css/                          # Stylesheets
│   ├── main.css                  # Core styles + responsive
│   ├── multi_agent.css           # Agent-specific styles
│   ├── file-explorer.css         # File manager styles
│   └── osint.css                 # OSINT tool styles (NEW)
│
├── img/                          # Images and icons
│   ├── dev_labs.png              # Header logo
│   ├── avatar_labs_transparent.png  # Background avatar
│   └── [other assets]
│
├── pkn.html                      # Main web interface
├── app.js                        # Main application logic
├── requirements.txt              # Python dependencies
├── .env                          # Configuration
│
├── memory/                       # Session storage
├── uploads/                      # Uploaded files
└── llama.cpp/                    # LLM inference (submodule)
```

---

## 🧠 Architecture Deep Dive

### Multi-Agent System

**File:** `agent_manager.py`

**Key Components:**

1. **AgentType Enum** - 6 agent types
2. **AgentManager Class** - Coordinates agents
3. **Task Classification** - Routes to appropriate agent
4. **Tool Registry** - Available tools per agent

**Agent Routing Logic:**
```python
def classify_task(instruction):
    # Keywords-based classification
    if 'code' in instruction or 'function' in instruction:
        return AgentType.CODER
    elif 'research' in instruction or 'search' in instruction:
        return AgentType.RESEARCHER
    # ... etc
```

**Adding a New Agent:**
1. Add to `AgentType` enum
2. Define in `_init_agents()` with capabilities
3. Add routing logic in `classify_task()`
4. Assign tools in `get_tools_for_agent()`
5. Update frontend badges/icons

### Tool System

**Pattern:** LangChain Tool wrappers

**Example:**
```python
from langchain_core.tools import Tool

whois_tool = Tool(
    name="whois_lookup",
    func=lambda domain: osint.whois_lookup(domain),
    description="Perform WHOIS lookup on domain..."
)

TOOLS = [whois_tool, dns_tool, ...]  # Exported list
```

**Adding a New Tool:**
1. Create function in appropriate `tools/*.py` file
2. Wrap as LangChain Tool
3. Add to `TOOLS` list in that module
4. Import in `agent_manager.py`
5. Assign to agent in `get_tools_for_agent()`

### Frontend Architecture

**Pattern:** Vanilla JavaScript modules (no build step)

**Key Files:**
- `app.js` - Main application, chat logic, sidebar
- `js/*.js` - Feature modules (files, OSINT, etc.)
- `pkn.html` - DOM structure, loads all scripts

**CSS Organization:**
- `main.css` - Base styles, layout, responsive
- `multi_agent.css` - Agent-specific UI
- `file-explorer.css` - File manager
- `osint.css` - OSINT tools

**Adding UI Feature:**
1. Create `js/feature_name.js`
2. Add `<script src="js/feature_name.js"></script>` to `pkn.html`
3. Create CSS in `css/feature_name.css`
4. Link CSS in `pkn.html` `<head>`
5. Initialize in `app.js` or feature module

---

## 🔌 API Endpoints

**Base:** `http://localhost:8010`

### Core Endpoints

```
GET  /                              # Serve pkn.html
GET  /api/health                    # Health check
POST /api/multi-agent/chat          # Main chat endpoint
POST /api/multi-agent/chat/stream   # Streaming responses
GET  /api/multi-agent/agents        # List agents
POST /api/multi-agent/classify      # Classify task
```

### File Operations

```
POST /api/files/upload              # Upload file
GET  /api/files/list                # List files
GET  /api/files/<id>                # Download file
DELETE /api/files/<id>              # Delete file
POST /api/files/browse              # Browse directory
POST /api/files/view                # View file content
```

### OSINT (NEW)

```
POST /api/osint/whois               # WHOIS lookup
POST /api/osint/dns                 # DNS queries
POST /api/osint/ip-geo              # IP geolocation
POST /api/osint/port-scan           # Port scanning
POST /api/osint/email-validate      # Email validation
POST /api/osint/username-search     # Username search
POST /api/osint/web-tech            # Technology detection
POST /api/osint/ssl-cert            # SSL certificate info
POST /api/osint/wayback             # Wayback Machine
POST /api/osint/subdomain-enum      # Subdomain enumeration
POST /api/osint/reverse-dns         # Reverse DNS
POST /api/osint/phone-lookup        # Phone number lookup
```

### Images

```
POST /api/generate-image            # Generate AI image
```

### Models

```
GET  /api/models/ollama             # List Ollama models
GET  /api/models/llamacpp           # List llama.cpp models
GET  /api/models/health             # Model health
```

**Adding New Endpoint:**
1. Add route in `divinenode_server.py`
2. Implement handler function
3. Add frontend call in appropriate `js/*.js`
4. Update documentation

---

## 🛠️ Development Workflow

### Making Changes

**1. Backend (Python):**
```bash
# Edit files
vim divinenode_server.py

# Check syntax
python3 -m py_compile divinenode_server.py

# Restart service
./pkn_control.sh restart-divinenode

# Check logs
tail -f divinenode.log
```

**2. Frontend (JS/CSS):**
```bash
# Edit files
vim js/files.js

# Check JS syntax
node --check js/files.js

# Hard refresh browser (Ctrl+Shift+R)
# Or restart server for cache clear
./pkn_control.sh restart-divinenode
```

**3. Testing:**
```bash
# Run system check
./system_check.sh

# Test specific endpoint
curl -X POST http://localhost:8010/api/health

# Test OSINT
curl -X POST http://localhost:8010/api/osint/ip-geo \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

### Code Style

**Python:**
- PEP 8 style guide
- 4-space indentation
- Docstrings for functions
- Type hints encouraged

**JavaScript:**
- camelCase for variables/functions
- 4-space indentation
- Comments for complex logic
- ES6+ features OK (no transpiling)

**CSS:**
- BEM-like naming
- Mobile-first responsive
- Cyberpunk theme: dark backgrounds, cyan (#00FFFF) accents

---

## 📦 Dependencies

### Python (requirements.txt)

**Core:**
- flask>=2.3.0
- flask-cors>=4.0.0
- python-dotenv>=1.0.0

**Tools:**
- phonenumbers>=8.13.0
- requests>=2.31.0
- python-whois>=0.8.0  # OSINT
- dnspython>=2.4.0  # OSINT
- beautifulsoup4>=4.12.0  # OSINT

**AI/ML:**
- langchain>=1.2.0
- langchain-core>=1.2.0
- chromadb>=0.4.18  # RAG
- sentence-transformers>=2.2.2  # RAG

**Installation:**
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### System Dependencies

**Linux:**
- Python 3.8+
- curl
- git
- llama.cpp (submodule)

**Android (Termux):**
- python
- git
- termux-services (optional)

---

## 🔧 Configuration

### Environment Variables (.env)

```bash
# LLM Endpoints
OLLAMA_BASE=http://127.0.0.1:11434
LOCAL_LLM_BASE=http://127.0.0.1:8000/v1

# Model Paths
LLAMA_MODEL_PATH=/home/gh0st/pkn/llama.cpp/models/qwen2.5-coder-14b-instruct-q4_k_m.gguf

# External APIs (optional)
OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

# Server Config
DN_PORT=8010
LLAMA_PORT=8000
```

### Service Ports

| Service | Port | Purpose |
|---------|------|---------|
| DivineNode | 8010 | Web server, API |
| llama.cpp | 8000 | Local LLM inference |
| Parakleon | 9000 | API wrapper (optional) |
| Ollama | 11434 | Alternative LLM (optional) |

---

## 🆕 Recent Changes (December 2025)

### OSINT Implementation
- **Files:** `tools/osint_tools.py`, `js/osint_ui.js`, `css/osint.css`
- **Features:** 12 OSINT capabilities (WHOIS, DNS, IP geo, etc.)
- **Integration:** Researcher agent has OSINT tools
- **UI:** Modal overlay with categorized tools
- **Docs:** `OSINT_README.md`, `OSINT_COMPLETE.md`

### File Explorer Enhancements
- **Changes:** Reduced hover box size, added dropdown menus
- **New Features:** File operations (View, Download, Rename, Copy, Move, Delete)
- **UI:** Context menu with icons
- **Accessibility:** Better touch support for mobile

### Empty State Messages
- **Files:** `app.js` (renderHistory function)
- **Locations:** Favorites, Archive, Chats sections
- **Style:** Icon + text + hint

### CLI Interface
- **Files:** `pkn_cli.py`, `pkn-cli`
- **Features:** Terminal interface, readline support, colors
- **Docs:** `PKN_CLI_README.md`, `PKN_CLI_COMPLETE.md`

### Health Monitoring
- **File:** `pkn_health.py`
- **Features:** Auto-restart failed services
- **Usage:** `./pkn_control.sh monitor`

### Android Support
- **Script:** `prepare_android.sh`
- **Package:** `/tmp/pkn_android_package/`
- **Docs:** `INSTALL_ANDROID.md`
- **Transfer:** ADB or ZIP

---

## 🐛 Common Issues & Solutions

### Issue: "Module not found"
**Cause:** Missing Python dependencies or wrong Python path
**Fix:**
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Port already in use"
**Cause:** Service already running on port
**Fix:**
```bash
./pkn_control.sh stop-all
# OR kill specific process
pkill -f divinenode_server
./pkn_control.sh start-all
```

### Issue: "Connection refused" in browser
**Cause:** DivineNode not running
**Fix:**
```bash
./pkn_control.sh status
./pkn_control.sh restart-divinenode
```

### Issue: Slow LLM responses
**Cause:** llama.cpp not optimized or model too large
**Fix:**
- Use GPU acceleration: `--n_gpu_layers 45`
- Use smaller model (7B instead of 14B)
- Switch to external API (Claude/GPT)

### Issue: JS changes not reflecting
**Cause:** Browser caching
**Fix:**
- Hard refresh: Ctrl+Shift+R
- Clear localhost cache
- Restart server (clears headers)

### Issue: ADB "unauthorized"
**Cause:** USB debugging not authorized on phone
**Fix:**
- Check phone for popup
- Accept "Always allow from this computer"
- Reconnect USB

---

## 🚀 Future Development Ideas

### High Priority
- [ ] Streaming responses in web UI
- [ ] Multi-file upload and batch operations
- [ ] Enhanced planning mode visualization
- [ ] Voice input/output integration
- [ ] Session export/import (JSON/Markdown)

### Medium Priority
- [ ] Custom agent creation UI
- [ ] Tool usage analytics dashboard
- [ ] Advanced OSINT workflows
- [ ] Code sandbox improvements
- [ ] Real-time collaboration features

### Low Priority
- [ ] Plugin system for third-party tools
- [ ] Alternative themes (light mode, custom colors)
- [ ] Mobile app (React Native wrapper)
- [ ] Docker containerization
- [ ] Cloud deployment guide

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| `QUICKSTART_GUIDE.md` | User quick start |
| `AI_HANDOFF_GUIDE.md` | This file - for AI developers |
| `README.md` | Main project documentation (to be created) |
| `OSINT_README.md` | OSINT tools usage |
| `OSINT_COMPLETE.md` | OSINT implementation log |
| `PKN_CLI_README.md` | Terminal CLI guide |
| `PKN_CLI_COMPLETE.md` | CLI implementation log |
| `INSTALL_ANDROID.md` | Android/Termux setup |
| `SESSION_COMPLETE_*.md` | Development session logs |

---

## 🧪 Testing Checklist

Before committing changes:

```bash
# 1. Syntax check
node --check app.js
node --check js/*.js
python3 -m py_compile *.py

# 2. System check
./system_check.sh

# 3. Service test
./pkn_control.sh restart-divinenode
curl http://localhost:8010/api/health

# 4. Feature test
# Open browser, test changed features
# Check browser console for errors

# 5. Mobile test (if applicable)
# Test on Android/Termux
# Check responsive design @media queries
```

---

## 🎯 Best Practices

### When Adding Features

1. **Plan first:** Understand existing architecture
2. **Modular:** Keep features in separate files
3. **Document:** Add comments and update docs
4. **Test:** Use system_check.sh and manual testing
5. **Mobile-friendly:** Test responsive design
6. **Error handling:** Wrap in try/catch, return structured errors

### When Modifying Existing Code

1. **Read first:** Understand current implementation
2. **Preserve:** Don't break existing functionality
3. **Consistent:** Match existing code style
4. **Backward compatible:** Don't break saved sessions/data
5. **Test thoroughly:** Check all affected features

### When Debugging

1. **Check logs:** `tail -f divinenode.log`
2. **Browser console:** F12 → Console tab
3. **Network tab:** Check failed requests
4. **System check:** `./system_check.sh`
5. **Isolate:** Test components individually

---

## 🤝 Handoff Checklist

**For the next AI assistant:**

- [ ] Read this entire guide
- [ ] Review project structure section
- [ ] Understand multi-agent architecture
- [ ] Familiarize with API endpoints
- [ ] Check recent changes section
- [ ] Review common issues
- [ ] Run `./system_check.sh`
- [ ] Test basic functionality
- [ ] Read user's request carefully
- [ ] Ask clarifying questions if needed

---

## 📞 Quick Reference

**Start/Stop:**
```bash
./pkn_control.sh start-all          # Start everything
./pkn_control.sh stop-all           # Stop everything
./pkn_control.sh status             # Check status
```

**Development:**
```bash
./system_check.sh                   # Verify integrity
tail -f divinenode.log              # View logs
node --check file.js                # Check JS syntax
python3 -m py_compile file.py       # Check Python syntax
```

**Access:**
- Web UI: http://localhost:8010/pkn.html
- CLI: `./pkn-cli`
- API: http://localhost:8010/api/...

**Key Files:**
- Backend: `divinenode_server.py`, `agent_manager.py`
- Frontend: `app.js`, `pkn.html`
- Tools: `tools/*.py`
- Modules: `js/*.js`

---

**Last Updated:** December 31, 2025
**Version:** 1.0 (Production)
**Maintainer:** AI Assistant
**Contact:** Via code comments and documentation

---

Good luck with continued development! 🚀

**Remember:** This is a production system. Test thoroughly before deploying changes. The user depends on this working correctly!
