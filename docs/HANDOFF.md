# PKN Development Handoff Document

**Created:** 2026-01-18
**Last Session:** 2026-01-18 (Refactoring + bashrc/menu fixes + MCP enforcement)
**Status:** Development in progress - MCP routing rules now enforced

---

## Quick Reference

| Item | Location |
|------|----------|
| **PC Development** | `/home/gh0st/dvn/divine-workspace/` |
| **Phone PKN** | `~/pkn/` (on Android via Termux) |
| **Desktop App** | `apps/pkn/` |
| **Mobile App** | `apps/pkn-mobile/` |
| **Shared Backend** | `packages/pkn-shared/backend/` (planned consolidation) |
| **Docs Hub** | `docs/INDEX.md` |

---

## 🔴 CRITICAL: MCP Agent Enforcement (Added This Session)

**New rules added to `CLAUDE.md` requiring MANDATORY use of MCP agents.**

### Key Rules
1. **ALWAYS** use `mcp__agent-tools__<agent>` for matching tasks
2. **NEVER** do manually what an agent can do
3. **COMPLETE** the full cycle: Route → Plan → Execute → Deploy → Verify

### Task → Agent Mapping
| Task | Required MCP Agent |
|------|-------------------|
| UI/styling/menus | `ui_designer` or `css_wizard` |
| Mobile/PWA | `mobile_ui` |
| Deploy to phone | `devops` |
| Bug fixes | `debugger` |
| Documentation | `docs_writer` |
| Shell scripts | `debugger` |

### This Session's Failures (Don't Repeat)
- User said "use ui-designer" → I did it manually ❌
- Made edits → Forgot to deploy ❌
- docs-writer ran → Didn't verify output ❌

**Full rules in:** `CLAUDE.md` (Section: MANDATORY MCP AGENT-TOOLS USAGE)

---

## 1. Project Overview

### What is PKN?

**PKN (Parakleon)** is a local-first, multi-agent AI assistant system with two deployment targets:

1. **PKN Desktop** - Full-featured AI system for Linux desktop
2. **PKN Mobile** - Mobile-optimized version for Android (Termux/PWA)

### Core Architecture (Shared Between Desktop & Mobile)

```
Backend Structure:
├── agents/                      # 9 specialized AI agents
│   ├── manager.py               # Agent orchestration
│   ├── classifier.py            # Task routing
│   ├── types.py                 # Agent definitions
│   └── specialist_agents.py     # Individual agent classes
├── routes/                      # 16+ API blueprints
│   ├── multi_agent.py           # /api/multi-agent/*
│   ├── chat.py                  # Chat endpoints
│   ├── health.py                # Health checks
│   └── ... (13 more)
├── tools/                       # 21 tool modules
│   ├── code_tools.py            # Edit, Write, Read
│   ├── file_tools.py            # Glob, Grep, Find
│   ├── system_tools.py          # Bash, Process
│   ├── pentest_tools.py         # Security testing
│   ├── recon_tools.py           # Reconnaissance
│   ├── privesc_tools.py         # Privilege escalation
│   ├── network_tools.py         # Network operations
│   ├── crypto_tools.py          # Cryptography
│   └── ... (13 more)
└── config/
    └── model_config.py          # Agent-model mappings
```

### NON-NEGOTIABLE Principles

**ALWAYS REMEMBER THESE:**

1. **LOCAL-FIRST ARCHITECTURE** - Privacy by default, cloud is optional
   - Default: All agents use Ollama (local inference)
   - Option: Cloud (Groq/OpenAI) for speed when needed
   - NEVER make cloud-only or suggest removing local capability

2. **UNCENSORED MODELS REQUIRED** - For legitimate security work
   - Security agent: `dolphin-phi:latest` (uncensored)
   - Reasoner agent: `nous-hermes:latest` (uncensored)
   - Required for pentesting, vulnerability research, security education

3. **USER'S HARDWARE** - Samsung Galaxy S24 Ultra
   - Snapdragon 8 Gen 3, 12GB RAM
   - Can run 7B models at ~7-13s response time
   - DO NOT underestimate phone capabilities

4. **MODEL CHANGE POLICY**
   - Only suggest changes if FASTER AND HIGHER QUALITY
   - Uncensored requirements MUST still be met
   - Performance is king, not popularity

5. **SHARED ARCHITECTURE**
   - Backend tools/agents are IDENTICAL between desktop/mobile
   - Device differences: model sizes (14B vs 7B), UI responsiveness
   - Changes to backend should sync to BOTH apps

---

## 2. Current State - What's Working

### Desktop PKN (`apps/pkn/`)

**Status:** ✅ Production ready

- Multi-agent system (9 agents)
- 21 tool modules fully integrated
- Local LLM via Ollama (14B models)
- Modular backend (17 route blueprints)
- Cyberpunk-themed UI
- Memory system (session, global, project)
- Image generation (Stable Diffusion)
- OSINT tools (Shadow suite)

**Entry Point:** `./pkn_control.sh start-all`

### Mobile PKN (`apps/pkn-mobile/`)

**Status:** ✅ Working, some UI fixes needed

- Same 9 agents as desktop
- Same 21 tool modules
- Local LLM via Ollama (7B models)
- Mobile-responsive CSS
- PWA with offline support
- Termux menu system

**Entry Point (on phone):** `pkn` alias → termux_menu.sh

### Recent Refactoring (2026-01-18)

**Completed:**
- ✅ Fixed `backend/tools/__init__.py` - added 7 missing module exports
- ✅ Fixed termux_menu.sh - replaced dead `/api/tools/list` endpoint
- ✅ Fixed local_parakleon_agent.py - changed to Ollama port 11434
- ✅ Fixed settings.py - LOCAL_LLM_BASE points to Ollama
- ✅ Cleaned up 6 route files (removed dead AgentManager imports)
- ✅ Created `packages/pkn-shared/` directory structure (for future consolidation)

---

## 3. Current State - What's Broken

### Pending Fixes (User reports didn't work)

**These changes were made but user says they're not working:**

#### 1. PC bashrc - Enter key behavior after fzf_menu

**Problem:** When exiting fzf_menu, pressing Enter takes you to `~/dvn/divine-workspace` instead of home directory

**Attempted Fix:**
- Added `cd ~` to PC `~/.bashrc` after fzf_menu function exits
- Expected: Enter key should go to home directory
- Result: User reports it didn't work

**Location:** `/home/gh0st/.bashrc` (PC)

#### 2. termux_menu.sh - Multiple changes not working

**Changes attempted:**
- Changed banner from "PKN" to "Gh0st" ASCII art (blue gradient)
- Changed "r" restart option to numbered option
- Fixed Enter key to exit to shell (added `cd ~` and quoted `"$choice"`)
- Reorganized menu with sections

**Location:** `apps/pkn-mobile/scripts/termux_menu.sh`

**Expected behavior:**
- Banner shows "Gh0st" in blue ASCII
- Enter key exits menu to shell at home directory
- Restart is a numbered option, not "r"

**Current behavior:** User hasn't verified if changes took effect

---

## 4. Architecture Summary

### Backend Components

**Agent Manager** (`backend/agents/manager.py`)
- Orchestrates 9 specialized agents
- Routes tasks to appropriate agent
- Manages tool access (all agents get all 21 modules)

**9 Specialized Agents:**
| Agent | Model (Mobile) | Model (Desktop) | Purpose |
|-------|---------------|-----------------|---------|
| CODER | qwen2.5-coder:7b | qwen2.5-coder:14b | Code writing/debugging |
| REASONER | nous-hermes:latest | nous-hermes:latest | Planning, logic (uncensored) |
| SECURITY | dolphin-phi:latest | dolphin-phi:latest | Pentesting (uncensored) |
| RESEARCHER | mistral:latest | mistral:latest | Research, docs |
| EXECUTOR | qwen2.5-coder:7b | deepseek-coder:6.7b | System commands |
| GENERAL | qwen:latest | llama3.1-8b-lexi | Quick Q&A |
| VISION | llava:latest | llava:latest | Image analysis |
| VISION_CLOUD | Groq | Groq | Cloud vision (optional) |
| CONSULTANT | Claude API | Claude API | Cloud reasoning (optional) |

**21 Tool Modules:**
1. code_tools - Edit, Write, Read
2. file_tools - Glob, Grep, Find
3. system_tools - Bash, Process, Todo
4. web_tools - Search, Fetch
5. memory_tools - Context, Recall
6. osint_tools - WHOIS, DNS, IP lookup
7. rag_tools - Document retrieval
8. planning_tools - Task breakdown
9. delegation_tools - Agent-to-agent
10. chain_tools - Multi-step workflows
11. sandbox_tools - Safe execution
12. evaluation_tools - Performance tracking
13. scratchpad_tools - Agent handoff
14. workflow_tools - Multi-agent coordination
15. git_tools - Version control
16. project_tools - Project management
17. pentest_tools - Shells, payloads, exploits
18. recon_tools - Banner grab, directory enum
19. privesc_tools - SUID, kernel exploits
20. network_tools - Port scan, traceroute
21. crypto_tools - Hash crack, JWT decode

**API Routes** (16+ blueprints):
- `/api/multi-agent/*` - Multi-agent system
- `/api/chat/*` - Chat endpoints
- `/api/files/*` - File operations
- `/api/models/*` - Model management
- `/api/osint/*` - OSINT tools
- `/api/network/*` - Network operations
- `/health` - Health checks
- ... (10+ more)

### Frontend Architecture

**Desktop UI:**
- Cyberpunk theme (dark + cyan accents)
- Sidebar navigation
- Chat interface with agent badges
- Settings panel
- File explorer
- OSINT tools panel

**Mobile UI:**
- Same base UI as desktop
- Responsive CSS overrides (`css/mobile.css`)
- Hamburger menu (☰)
- Touch-optimized buttons (44px minimum)
- Full-screen modals
- Arrow send button (➤)

---

## 5. Key Files Map

### Most Important Files

**Backend Core:**
| File | Lines | Purpose |
|------|-------|---------|
| `backend/server.py` | ~75 | Flask app initialization |
| `backend/agents/manager.py` | ~1,111 | Agent orchestration |
| `backend/agents/classifier.py` | ~188 | Task classification |
| `backend/routes/multi_agent.py` | ~200 | Multi-agent API |
| `backend/routes/chat.py` | ~150 | Chat endpoints |
| `backend/config/model_config.py` | ~250 | Agent-model mappings |

**Frontend Core:**
| File | Lines | Purpose |
|------|-------|---------|
| `pkn.html` | ~1,580 | Main HTML entry point |
| `css/main.css` | ~3,589 | Desktop styles |
| `css/mobile.css` | ~398 | Mobile overrides |
| `js/core/app.js` | ~4,244 | Main app logic (LARGE - needs refactoring) |
| `js/features/files.js` | ~795 | File explorer |
| `js/ui/chat.js` | ~400 | Chat rendering |

**Configuration:**
| File | Purpose |
|------|---------|
| `.env` | API keys, endpoints |
| `requirements.txt` | Python dependencies |
| `manifest.json` | PWA configuration |
| `service-worker.js` | PWA caching |

**Scripts:**
| File | Purpose |
|------|---------|
| `pkn_control.sh` | Desktop service manager |
| `scripts/termux_menu.sh` | Mobile launcher menu |

---

## 6. Common Commands

### Desktop PKN

```bash
# Start all services (Flask + Ollama)
cd ~/dvn/divine-workspace/apps/pkn
./pkn_control.sh start-all

# Stop all services
./pkn_control.sh stop-all

# Check status
./pkn_control.sh status

# View logs
tail -f divinenode.log
```

### Mobile PKN (on phone via Termux)

```bash
# Open menu (alias)
pkn

# Menu options:
# 1) Start Server
# 2) Start + Open Browser
# 3) Restart Server
# 4) Stop Server
# 5) System Status
# 6) Cloud Mode
# 7) Local Mode
# 8) Start Ollama
# 9) View Logs
# 10) Test Chat
# 0/Enter) Exit to Shell

# Direct commands
cd ~/pkn
python -m backend.server  # Start server
pkill -f backend          # Stop server
curl http://localhost:8010/health  # Test
```

### Development (PC)

```bash
# SSH to phone
pkn-ssh  # Alias for sshpass + ssh

# Deploy to phone
pkn-push  # Copies apps/pkn-mobile/* to phone

# Pull from phone (backup)
pkn-pull  # Copies ~/pkn to ~/phone-backup

# Start Claude Code in mobile directory
ccm  # Alias for cd + claude in pkn-mobile

# Health check
pkn-health  # curl + json.tool
```

### Workspace Commands

```bash
# From project root
just dev        # Start all dev servers
just ci         # Run full CI pipeline
just lint       # Lint all code
just format     # Format all code
just test       # Run all tests
```

---

## 7. Known Issues

### Critical Bugs

**1. termux_menu.sh Enter key not exiting to home**
- Menu exits but lands in wrong directory
- Need to verify if `cd ~` is executing
- May need to check shell behavior after `case` statement

**2. PC bashrc fzf_menu Enter key behavior**
- Similar to #1 but on PC
- fzf_menu should exit to home, but goes to workspace

### UI Issues

**3. app.js is 4,244 lines (LARGE)**
- Monolithic file with 141 functions
- Contains duplicates of modular files
- 87 inline HTML event handlers depend on it
- Needs careful refactoring to avoid breaking UI

**4. Mobile CSS caching**
- Mobile browsers aggressively cache CSS
- Service worker can cause stale versions
- Solution: Cache-busting URLs with `?v=timestamp`

**5. Settings X button visibility (mobile)**
- Reported as not visible on some screens
- Multiple attempts to fix (44px, high z-index, cyan background)
- May need alternative approach (different positioning)

### Performance Notes

**Mobile response times (measured on S24 Ultra):**
- qwen:latest (2.3GB): ~0.8s
- dolphin-phi:latest (1.6GB): ~7.2s
- nous-hermes:latest (3.8GB): ~12.9s
- qwen2.5-coder:7b (4.7GB): ~10s

### Recently Fixed

**PWA Black Screen (2026-01-18)**
- Problem: PC PWA opened to black screen
- Cause: Service worker v1.0.0 using cache-first
- Fix: Updated to v2.0.0 with network-first for HTML/JS

**Phone Cleanup (2026-01-17)**
- Removed 2.5GB of old duplicates
- Consolidated to single ~/pkn/ directory
- Removed 22+ old scripts and configs

**Mobile Background Image (2026-01-18)**
- Changed background-size: contain → 85% auto
- gh0stbanner.png now properly sized

---

## 8. Next Steps

### Immediate Priority (Verify These)

1. **Test termux_menu.sh changes**
   - SSH to phone: `pkn-ssh`
   - Run: `pkn`
   - Verify:
     - Banner shows "Gh0st" ASCII (blue gradient)
     - Enter key exits to shell at `~` directory
     - Restart is numbered option

2. **Test PC bashrc fzf_menu**
   - On PC: Run fzf menu
   - Press Enter after selection
   - Should land at `~` not `~/dvn/divine-workspace`

### Refactoring Tasks

3. **Consolidate shared backend code**
   - Move common tools/agents to `packages/pkn-shared/backend/`
   - Symlink from both apps
   - Eliminates duplication

4. **Split app.js (carefully)**
   - Map all 87 HTML onclick handlers
   - Identify duplicate functions in modular files
   - Create backward compatibility shims
   - Test each function removal individually

5. **Improve mobile CSS delivery**
   - Consider inline critical CSS in HTML head
   - External CSS for non-critical styles
   - Better cache-busting strategy

### Feature Requests

6. **PC send button arrow icon**
   - User likes mobile ➤ arrow design
   - Apply to desktop version
   - Same red "STOP" toggle on processing

7. **Swipe gestures (optional)**
   - User originally requested swipe-to-open sidebar
   - Previous attempt broke OSINT, reverted
   - May revisit with better implementation

---

## 9. Development Workflow

### Making Changes

**ALWAYS:**
1. Read relevant CLAUDE.md first
2. Check `docs/ARCHITECTURE.md` for patterns
3. Look at similar existing code
4. Plan before coding (use architect agent)
5. Write/update tests
6. Run `just ci` before committing

**FILE SIZE LIMITS:**
- Utilities/Components: ~200 lines max
- App/Core files: 300-500 lines acceptable
- Enforced by pre-commit hook

### Testing Changes

**Backend:**
```bash
# Test endpoint
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "mode": "auto"}'

# Test specific agent
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Write Python hello world", "agent_override": "coder"}'

# Check health
curl http://localhost:8010/health | python3 -m json.tool
```

**Frontend:**
- Hard refresh: Ctrl+Shift+R
- Browser console: F12 (check for errors)
- Mobile: Chrome DevTools remote debugging

**Agents:**
```bash
# Test agent integration
cd ~/dvn/divine-workspace/apps/pkn
python3 test_free_agents.py

# Test streaming
./test_streaming.sh
```

### Deploying to Phone

**Via SSH:**
```bash
# Full deployment
pkn-push  # Copies all files to phone

# Single file
sshpass -p 'pkn123' scp -P 8022 \
  ~/dvn/divine-workspace/apps/pkn-mobile/file.py \
  u0_a322@192.168.12.183:~/pkn/

# Restart server on phone
pkn-ssh "pkill -f backend; cd ~/pkn && python -m backend.server &"
```

**Via ADB (USB):**
```bash
# Forward port
adb forward tcp:8022 tcp:8022

# Push files
adb push apps/pkn-mobile/* /sdcard/pkn/

# Termux commands
adb shell "su -c 'cp -r /sdcard/pkn/* ~/pkn/'"
```

---

## 10. Troubleshooting Guide

### Server Won't Start

**Desktop:**
```bash
# Check if already running
lsof -i :8010

# Kill existing
pkill -f divinenode_server
pkill -f 'python.*backend'

# Check Ollama
pgrep ollama
curl http://localhost:11434/api/tags

# Start fresh
cd ~/dvn/divine-workspace/apps/pkn
./pkn_control.sh start-all
```

**Mobile:**
```bash
# On phone via SSH
pkn-ssh

# Kill all Python
killall -9 python3

# Check Ollama
pgrep ollama
curl http://localhost:11434/api/tags

# Start fresh
cd ~/pkn
python -m backend.server
```

### UI Looks Broken

**Mobile:**
1. Hard refresh: Settings → Clear browsing data → Cached images
2. Open with cache-busting: `http://localhost:8010/?v=$(date +%s)`
3. Check CSS exists: `ls ~/pkn/css/mobile.css`
4. Disable service worker: Rename `sw.js` to `sw.js.disabled`

**Desktop:**
1. Hard refresh: Ctrl+Shift+R
2. Check browser console (F12)
3. Verify CSS loaded: Network tab
4. Check for JavaScript errors

### Agent Timeout

**Check model loaded:**
```bash
curl http://localhost:11434/api/tags
# Should list installed models
```

**Check backend mode:**
```bash
curl http://localhost:8010/api/multi-agent/backend
# Should return "local" or "cloud"
```

**Switch to cloud (temporary):**
```bash
curl -X POST http://localhost:8010/api/multi-agent/backend \
  -H "Content-Type: application/json" \
  -d '{"backend": "cloud"}'
```

### Tools Not Working

**Verify tool imports:**
```bash
# Check if module exists
python3 -c "from backend.tools import pentest_tools; print('OK')"

# Check if registered
curl http://localhost:8010/api/multi-agent/agents | python3 -m json.tool
# Look for "tools_enabled": true
```

### Memory Issues

**Check memory files:**
```bash
# Session memory
ls ~/pkn/memory/session_*.json

# Global memory
cat ~/.pkn_mobile_memory.json

# Project memory
cat ~/pkn/project_memory.json
```

**Clear session (start fresh conversation):**
```bash
curl -X POST http://localhost:8010/api/memory/clear-session
```

---

## 11. Session Context

### What Was Attempted This Session (2026-01-18)

**Earlier (Refactoring workflow):**
1. Fixed mobile tools/__init__.py
   - Added 7 missing module exports
   - Added ToolRegistry class
   - All 21 modules now properly exported

2. Fixed termux_menu.sh
   - Replaced dead `/api/tools/list` endpoint with `/api/multi-agent/agents`
   - Menu now correctly shows agent count

3. Fixed local_parakleon_agent.py
   - Changed default endpoint to Ollama port 11434
   - Was pointing to llama.cpp port 8000

4. Fixed settings.py
   - LOCAL_LLM_BASE now points to Ollama
   - Consistent backend configuration

5. Cleaned up route files
   - Removed dead AgentManager imports from 6 files
   - Updated import paths to use blueprints

6. Created packages/pkn-shared/ structure
   - Directory for future backend consolidation
   - Will eliminate duplication between desktop/mobile

**Later (bashrc/menu fixes - USER SAYS DIDN'T WORK):**
1. PC bashrc - Added `cd ~` after fzf_menu exits
   - Goal: Enter key should go to home, not workspace
   - User reports: Didn't work

2. termux_menu.sh changes:
   - Changed banner to "Gh0st" ASCII art
   - Changed restart from "r" to numbered option
   - Fixed Enter key to exit with `cd ~`
   - Quoted `"$choice"` in case statement
   - Reorganized with section headers
   - User reports: Needs verification

### Files Modified This Session

**Mobile (`apps/pkn-mobile/`):**
- `backend/tools/__init__.py` - Fixed exports
- `backend/agents/local_parakleon_agent.py` - Ollama endpoint
- `backend/config/settings.py` - LOCAL_LLM_BASE
- `backend/routes/chat.py` - Removed dead import
- `backend/routes/health.py` - Removed dead import
- `backend/routes/multi_agent.py` - Removed dead import
- `scripts/termux_menu.sh` - Banner, menu, Enter key

**PC:**
- `~/.bashrc` - Added `cd ~` after fzf_menu

**Workspace:**
- `packages/pkn-shared/backend/` - Created directory structure

---

## 12. Critical Reminders

### Before You Code

- [ ] Read the app's CLAUDE.md
- [ ] Check docs/ARCHITECTURE.md
- [ ] Look at similar existing code
- [ ] Plan changes (use architect agent)
- [ ] Consider file size limits

### Before You Commit

- [ ] Code runs without errors
- [ ] `just fmt` applied
- [ ] `just lint` passes
- [ ] Tests pass
- [ ] No debug code left
- [ ] Docs updated if API changed
- [ ] `just ci` passes

### Quality Gates

**File Size Limits:**
- Utilities/Components: ~200 lines
- App files: 300-500 lines max
- Use `scripts/check_file_size.py`

**Code Style:**
- Python: Type hints, docstrings, Black formatting
- JavaScript: ES6 modules, not CommonJS
- All: Single responsibility, modular

### Communication with User

- Be concise
- Show code, don't just describe
- Brief summaries after tasks
- No walls of text
- No emojis unless requested

---

## 13. Resources

### Documentation

**Read these first:**
- `/home/gh0st/dvn/divine-workspace/CLAUDE.md` - Workspace-wide instructions
- `/home/gh0st/dvn/divine-workspace/apps/pkn-mobile/CLAUDE.md` - Mobile specifics
- `/home/gh0st/dvn/divine-workspace/apps/pkn/CLAUDE.md` - Desktop specifics
- `/home/gh0st/dvn/divine-workspace/docs/INDEX.md` - Documentation hub

**Architecture & Design:**
- `docs/ARCHITECTURE.md` - System design
- `docs/AGENTS.md` - All 9 agents, models, tools
- `docs/TOOLS.md` - 90+ tools reference
- `docs/SHADOW_OSINT.md` - 35 OSINT tools

**Development:**
- `docs/CONTRIBUTING.md` - Contribution workflow
- `docs/TROUBLESHOOTING.md` - Common issues
- `docs/DEPLOYMENT.md` - Deployment guides

### Key Paths

**PC:**
- Workspace: `/home/gh0st/dvn/divine-workspace/`
- Desktop PKN: `apps/pkn/`
- Mobile PKN: `apps/pkn-mobile/`
- Shared: `packages/pkn-shared/`
- Scripts: `scripts/`
- Docs: `docs/`

**Phone (Termux):**
- PKN: `~/pkn/`
- Scripts: `~/pkn/scripts/`
- Data: `~/pkn/data/`
- Logs: `~/pkn/data/server.log`
- Memory: `~/pkn/memory/`

### Connection Info

**Phone SSH:**
- IP: `192.168.12.183` (changes with network)
- Port: 8022
- User: `u0_a322`
- Password: `pkn123`
- Command: `pkn-ssh` (alias)

**Ports:**
- Flask server: 8010
- Ollama: 11434
- llama.cpp: 8000 (desktop only)

---

## 14. Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-01-18 | Local-first architecture is NON-NEGOTIABLE | Privacy is core to PKN's value proposition |
| 2026-01-18 | Security agent uses uncensored models | Required for legitimate pentesting work |
| 2026-01-18 | Cloud is OPTION, not default | User controls when to trade privacy for speed |
| 2026-01-18 | Backend tools should be identical between desktop/mobile | Reduce duplication, single source of truth |
| 2026-01-17 | Phone cleanup: single ~/pkn/ directory | Eliminate confusion from multiple PKN locations |
| 2026-01-12 | Mobile uses 7B models, desktop uses 14B | Optimize for hardware capabilities |

---

## 15. Contact & Support

### Getting Help

**When stuck:**
1. Check `docs/TROUBLESHOOTING.md`
2. Review relevant CLAUDE.md
3. Search git history for similar fixes
4. Ask user for clarification

**For architecture questions:**
- Read `docs/ARCHITECTURE.md`
- Check existing patterns in codebase
- Use architect agent for complex features

**For agent/tool questions:**
- See `docs/AGENTS.md` (agent configuration)
- See `docs/TOOLS.md` (tool reference)
- Check `backend/agents/manager.py` (implementation)

---

## 16. Version History

| Date | Change | Author |
|------|--------|--------|
| 2026-01-18 | Created comprehensive handoff document | Claude Code |
| 2026-01-18 | Refactored mobile tools/__init__.py | Claude Code |
| 2026-01-18 | Fixed termux_menu.sh endpoint | Claude Code |
| 2026-01-18 | Updated local_parakleon_agent.py to Ollama | Claude Code |

---

**END OF HANDOFF DOCUMENT**

For the next session, start by verifying the two pending fixes (bashrc Enter key, termux_menu changes). Test both and report results before proceeding with new work.
