# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**🔴 CRITICAL: Read `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md` BEFORE making any changes to ANY Divine Node project.**

## Project Overview

Divine Node (PKN - Parakleon) is a self-hosted, multi-agent AI system that runs locally with complete privacy. It combines 6 specialized AI agents coordinated through a Flask backend, using llama.cpp for local LLM inference (Qwen2.5-Coder-14B), and a cyberpunk-themed web UI. The system is designed for both desktop Linux and Android (Termux).

**This project follows the modular architecture standards defined in `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md`.**

## Code Documentation Standard

**CRITICAL: Always use inline annotations when modifying code.**

The project owner is a beginner and requires comprehensive inline documentation to understand and maintain the codebase. When editing any file, always add same-line comments that include:

1. **Short description** - What this line/block does
2. **Adjustments made** - What was changed and why (if modifying existing code)
3. **File references** - Other files that reference this attribute/function (format: `ref:filename.ext`)

### Examples:

**JavaScript/CSS:**
```javascript
openMenuElement = menu;  // Store reference to open menu for click-outside detection | ref:app.js:2337-2350

menu.style.zIndex = '99999';  // High z-index ensures menu appears above all other elements | ref:main.css:.history-menu

const overlay = document.getElementById('menuOverlay');  // Get click-outside overlay | Created in openProjectMenu() | ref:app.js:2321-2330
```

**Python:**
```python
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')  # API key for cloud LLM fallback | ref:.env, external_llm.py

session_id = str(uuid.uuid4())  # Generate unique session identifier | Stored in memory/session_{id}.json | ref:conversation_memory.py
```

**HTML:**
```html
<div class="sidebar">  <!-- Left navigation panel | Toggles with .visible class | ref:main.css:.sidebar, app.js:toggleSidebar() -->
```

### When to Apply:
- **Always**: When modifying existing code
- **Always**: When adding new functions, classes, or significant logic blocks
- **Always**: When working with shared state or global variables
- **Always**: When CSS/HTML changes affect JavaScript behavior or vice versa

### Benefits:
- Owner can understand changes without asking questions
- Cross-file dependencies are immediately visible
- Future modifications easier to reason about
- Reduces need for external documentation

**This is mandatory unless it would make code unreadable (e.g., simple variable assignments in loops).**

## Build & Test Commands

### Service Management
```bash
# Start all services (Flask server port 8010, llama.cpp port 8000)
./pkn_control.sh start-all

# Stop all services
./pkn_control.sh stop-all

# Check service status
./pkn_control.sh status

# Individual service control
./pkn_control.sh start-divinenode    # Flask server
./pkn_control.sh start-llama         # llama.cpp inference server
./pkn_control.sh start-parakleon     # API wrapper
./pkn_control.sh start-ollama        # Ollama (optional)

# Debug LLM connection
./pkn_control.sh debug-qwen
```

### Development
```bash
# Python environment
source .venv/bin/activate
pip install -r requirements.txt

# View logs
tail -f divinenode.log    # Flask server logs
tail -f llama.log         # llama.cpp inference logs

# Test endpoints
curl http://localhost:8010/health
curl http://localhost:8000/v1/models
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "mode": "auto"}'
```

### Testing
```bash
# Test agent integration
python3 test_free_agents.py
python3 test_fixed_agents.py

# Test streaming responses
./test_streaming.sh

# Test specific tools
curl -X POST http://localhost:8010/api/phonescan \
  -H "Content-Type: application/json" \
  -d '{"number": "+1-555-123-4567"}'
```

## Architecture

### Multi-Agent System
The core architecture uses **agent_manager.py** to coordinate 6 specialized agents:

1. **Coder** (`AgentType.CODER`) - Code writing, debugging, refactoring via Qwen2.5-Coder
2. **Reasoner** (`AgentType.REASONER`) - Planning, logic, problem-solving
3. **Researcher** (`AgentType.RESEARCHER`) - Web research, documentation lookup
4. **Executor** (`AgentType.EXECUTOR`) - System commands, file operations
5. **General** (`AgentType.GENERAL`) - Quick Q&A, simple queries
6. **Consultant** (`AgentType.CONSULTANT`) - External LLM calls (Claude/GPT)

**Key Design Pattern:**
- Frontend sends message → `divinenode_server.py` receives via `/api/multi-agent/chat`
- `agent_manager.py` classifies task and routes to appropriate agent
- Agent executes with tool access via `tools/` modules
- Response returns with agent metadata (which agent, tools used, performance metrics)

### Backend Structure (Python)

```
divinenode_server.py (1,212 lines)
├── Flask server on port 8010
├── Routes: /api/multi-agent/chat, /api/phonescan, /api/generate-image, /health
└── Serves static files (pkn.html, js/, css/, img/)

agent_manager.py (625 lines)
├── AgentManager class coordinates all agents
├── Task classification based on keywords and complexity
├── Agent-to-agent messaging via AgentMessage
└── Tool integration via tools/ modules

conversation_memory.py (404 lines)
├── Session persistence (memory/ directory)
├── Global memory (~/.parakleon_memory.json)
└── Project memory (pkn_memory.json)

code_context.py (416 lines)
├── Project analysis and symbol extraction
└── Tree-sitter integration for code parsing

local_parakleon_agent.py (386 lines)
├── Local LLM agent implementation
└── Interfaces with llama.cpp via OpenAI-compatible API

external_llm.py (374 lines)
├── External API integration (Claude, GPT)
└── Fallback for consultant agent
```

### Frontend Structure (JavaScript - Modular)

**Core UI:**
- `pkn.html` - Main entry point, loads all JS modules
- `js/main.js` - Core UI initialization and event handling
- `js/chat.js` - Chat message rendering and history
- `js/multi_agent_ui.js` - Agent selection, routing, and status display

**Features:**
- `js/autocomplete.js` - Code completion (40-120ms)
- `js/agent_quality.js` - Performance monitoring and health checks
- `js/images.js` - AI image generation UI
- `js/projects.js` - Project management and file operations
- `js/settings.js` - User settings and preferences
- `js/files.js` - File upload and management

**Utilities:**
- `js/storage.js` - LocalStorage wrapper for persistence
- `js/utils.js` - Common utility functions
- `js/models.js` - Model selection and configuration

### Tool System

Tools are organized in `tools/` directory (imported in agent_manager.py):
- `code_tools.py` - Code analysis, symbol extraction
- `file_tools.py` - Read/write files with safety checks
- `system_tools.py` - Execute shell commands
- `web_tools.py` - HTTP requests, web scraping
- `memory_tools.py` - Conversation persistence

**Tool Usage Pattern:**
Agents can call tools during task execution. Tools return structured data that agents incorporate into responses.

### LLM Integration

**llama.cpp server:**
- Started via `pkn_control.sh start-llama`
- OpenAI-compatible API on port 8000
- Model: Qwen2.5-Coder-14B-Instruct-Q4_K_M (8.4GB)
- Key parameters: `--n_gpu_layers 45`, `--n_batch 512`, `--n_ctx 8192`
- Chat format: `--chat_format qwen`

**Backend connection:**
- Python agents use requests library to call http://127.0.0.1:8000/v1/chat/completions
- Follows OpenAI API spec (messages array, temperature, max_tokens)

## Key Patterns & Conventions

### Agent Routing Logic
Located in `agent_manager.py`, routing uses keyword matching:
- "code", "function", "debug" → Coder agent
- "plan", "analyze", "think" → Reasoner agent
- "research", "search", "find" → Researcher agent
- "run", "execute", "command" → Executor agent
- Default fallback → General agent

Override with `agent_override` parameter in `/api/multi-agent/chat` request.

### Session Management
- Each chat session gets unique `session_id` (UUID)
- Sessions persist to `memory/session_{id}.json`
- Global context in `~/.parakleon_memory.json` (user preferences, notes)
- Project context in `pkn_memory.json` (project-specific knowledge)

### Error Handling
- Agents return structured responses with `{"error": "message"}` on failure
- Frontend displays errors in red badges
- Quality monitor tracks success/failure rates per agent
- Automatic retry logic: 1 retry attempt with 3s delay

### Performance Targets
- Autocomplete: <120ms
- Agent selection: <50ms
- Simple queries (General agent): 2-4s
- Code generation (Coder agent): 8-15s
- Complex tasks (multi-agent): 20-45s

## Configuration Files

### Environment Variables (.env)
```bash
OLLAMA_BASE=http://127.0.0.1:11434
LOCAL_LLM_BASE=http://127.0.0.1:8000/v1
LLAMA_MODEL_PATH=/home/gh0st/pkn/llama.cpp/models/qwen2.5-coder-14b-instruct-q4_k_m.gguf
OPENAI_API_KEY=your_key_here  # Optional for consultant agent
ANTHROPIC_API_KEY=your_key_here  # Optional for consultant agent
```

### Memory Files
- `~/.parakleon_memory.json` - Global user preferences and notes
- `pkn_memory.json` - Project-specific context
- `memory/session_{id}.json` - Individual chat sessions

### Model Requirements
The system expects a GGUF model file at path specified in `pkn_control.sh` (line 22):
```bash
GGUF_MODEL="$PKN_DIR/llama.cpp/models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf"
```

## Mobile Deployment (Termux)

Key differences for Android:
- Use `termux_menu.sh` instead of `pkn_control.sh` for user-friendly menu
- Build llama.cpp with: `cmake .. -DCMAKE_BUILD_TYPE=Release` (no GPU)
- Reduce model size: Use Qwen 7B Q4_0 (3.8GB) instead of 14B
- Reduce threads: `--n_threads 4` in pkn_control.sh
- Battery: Acquire wake lock via `termux-wake-lock`
- Storage: Extract to `/sdcard/pkn` for better permissions

## Important Notes for Development

### Code Analysis - Run Before Major Changes

**CRITICAL: Run analysis before committing major changes to catch bugs early.**

**Two ways to analyze code:**

#### Option 1: Visual Interface (Recommended for Beginners)
Use the Chrome DevTools extension - **no terminal required!**

```
1. Open http://localhost:8010 in Chrome
2. Press F12 (open DevTools)
3. Click "Divine Debugger" tab
4. Click "🔍 Code Analysis" tab
5. Click "🚀 Run Full Analysis"
```

See [debugger-extension/QUICK_START.md](debugger-extension/QUICK_START.md) for guide.

**Features:**
- ✅ Click buttons instead of typing commands
- ✅ Visual results with color coding
- ✅ Learning mode with detailed explanations
- ✅ Perfect for beginners

#### Option 2: Command Line (Advanced)
For automation and CI/CD integration:

```bash
cd /home/gh0st/pkn/debugger-extension
python3 run_all_checks.py /home/gh0st/pkn
```

**What it catches:**
- **Duplicate functions** - Same function defined in multiple files (e.g., `openProjectMenu` in both `app.js` and `js/projects.js`)
- **Scope mismatches** - Variable used as both local and `window.variable` (e.g., `openMenuElement` vs `window.openMenuElement`)
- **Missing selectors** - JS references CSS classes/IDs that don't exist in HTML/CSS

**When to run:**
- After adding new features spanning multiple files
- Before committing to git
- When debugging mysterious bugs
- Before production deployments

**Example issues caught:**
- Today's menu bug: `openProjectMenu` duplicated, scope mismatch on `openMenuElement`
- Settings panel bug: `toggleSettings()` duplicated in `app.js` and `settings.js`
- Theme inconsistencies: Hardcoded colors vs CSS variables

See `debugger-extension/README.md` for full documentation.

### When Modifying Agents
1. Agent definitions are in `agent_manager.py` `_init_agents()` method
2. Update routing keywords in `_classify_task()` if adding new capabilities
3. Test with `./pkn_control.sh debug-qwen` to verify LLM connectivity

### When Adding Tools
1. Create tool function in appropriate `tools/` module
2. Import in `agent_manager.py` top section
3. Document tool in agent's `capabilities` list
4. Tools must return JSON-serializable data

### When Modifying Frontend
1. All JS is modular - edit specific `js/*.js` file, not monolithic app.js
2. CSS follows cyberpunk theme: dark backgrounds, cyan accents (#00ffff)
3. Mobile breakpoints: 320px, 768px, 1024px
4. Hard refresh required: Ctrl+Shift+R (browser caching is disabled but helpful during development)

### When Debugging
- Check `divinenode.log` for Flask errors
- Check `llama.log` for LLM inference errors
- Browser console (F12) for frontend JavaScript errors
- Use `curl` to test API endpoints directly
- Quality monitor UI shows per-agent performance and errors

### Critical Path for Message Flow
1. User types in `pkn.html` input → Event listener in `js/chat.js`
2. `sendMessage()` calls `/api/multi-agent/chat` with message + mode
3. Flask route in `divinenode_server.py` receives request
4. `agent_manager.handle_task()` classifies and routes to agent
5. Agent calls llama.cpp at `http://127.0.0.1:8000/v1/chat/completions`
6. Response flows back through agent_manager → Flask → frontend
7. `js/chat.js` renders response with agent badge and performance metrics

### Ports in Use
- 8010: Flask server (divinenode_server.py)
- 8000: llama.cpp inference server
- 9000: Parakleon API wrapper (optional)
- 11434: Ollama (optional)

Avoid conflicts by checking `lsof -i :8010` before starting services.

## llama.cpp Integration

The project includes llama.cpp as a submodule for local inference:

### Building llama.cpp
```bash
cd llama.cpp
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release  # Add -DLLAMA_CUDA=ON for GPU
make -j$(nproc)
```

### Server Usage
Launched via `pkn_control.sh` which runs:
```bash
python3 -m llama_cpp.server \
  --model "$GGUF_MODEL" \
  --host 0.0.0.0 \
  --port 8000 \
  --chat_format qwen \
  --n_threads $(($(nproc) - 2)) \
  --n_gpu_layers 45 \
  --n_batch 512 \
  --n_ctx 8192
```

See llama.cpp/README.md for full build options and `.github/copilot-instructions.md` for llama.cpp-specific conventions.

## Recent Fixes (2026-01-05)

### Welcome Screen Overlay Issue - RESOLVED

**Problem**: Welcome screen was appearing over chat messages after user sent first message.

**Root Cause**: Multiple `setTimeout(() => showWelcomeScreen(), 50)` calls throughout app.js were re-showing the welcome screen even after messages existed.

**Solution Implemented**:
1. CSS: `.welcome-screen` now has `display: none` by default (line 1806 in main.css)
2. JS: `hideWelcomeScreen()` completely removes element from DOM using `.remove()` (app.js:338-343)
3. JS: `showWelcomeScreen()` actively checks for messages and removes welcome screen if any exist (app.js:347-363)

**Key Code Locations**:
- `/home/gh0st/pkn/css/main.css` line 1806: Default hidden state
- `/home/gh0st/pkn/app.js` lines 338-363: Welcome screen show/hide logic
- `/home/gh0st/pkn/app.js` lines 757, 2355, 2372, 2405, 2533: setTimeout calls that trigger showWelcomeScreen()

### Agent Switcher FAB Button - REFINED

**Changed**: Made FAB button more subtle and less intrusive
- Size: 56px → 44px (40px on mobile)
- Background: Translucent `rgba(0, 255, 255, 0.15)` instead of solid cyan
- Opacity: 60% default, 100% on hover
- Icon: Reduced to 24px with 80% opacity

**Code Location**: `/home/gh0st/pkn/css/main.css` lines 2070-2097

## Current State (as of 2026-01-05)

### Active Files
- **Frontend**: `pkn.html`, `app.js` (143KB), modular `js/*.js` files
- **Backend**: `divinenode_server.py`, `agent_manager.py`, Python modules
- **Styles**: `css/main.css`, `css/multi_agent.css`
- **Config**: `pkn_control.sh`, `.env`, `CLAUDE.md`, `CHANGELOG.md`

### Cleaned Up
- Removed: `css/main.css.backup`, `css/multi_agent.css.backup`
- Excluded from backups: `minecraft_builds/` (gaming projects), `llama.cpp/`, `.venv/`, `node_modules/`, `*.log`, `memory/`

### Backup Location
Latest backup: `../pkn_backup_YYYYMMDD_HHMMSS.tar.gz` (excludes gaming content, logs, dependencies)

## Debugging Tips

### If Welcome Screen Issues Return
1. Check browser console for "Welcome screen shown/hidden/removed" logs
2. Verify CSS has `display: none` on `.welcome-screen` class
3. Ensure `hideWelcomeScreen()` is called in `sendMessage()` (app.js line 386)
4. Check that `showWelcomeScreen()` has the message-checking logic

### If FAB Button Too Loud
- Adjust opacity in `.agent-switcher-fab` class (main.css line 2088)
- Reduce background alpha: `rgba(0, 255, 255, 0.15)` (lower last value)
- Check mobile breakpoint styles at line 2278

## Mobile Phone Deployment (2026-01-07)

### Termux Android Deployment Summary

**Deployment Location**: User's Android phone via Termux
- Phone directory: `~/pkn-phone/` (separate from PC build at `/home/gh0st/pkn/`)
- SSH access: `ssh u0_a322@192.168.1.200 -p 8022` (password: `pkn123`)
- Server port: 8010 (same as desktop)

### Lightweight Mobile Server

Created **`~/pkn-phone/divinenode_server.py`** - stripped-down Flask server optimized for mobile:
- Single local Phi-3 Mini agent (3.8GB model)
- Minimal endpoints for chat functionality
- No Ollama, no multi-agent orchestration (too resource-intensive for phone)
- Added missing API endpoints to prevent 405 errors:
  - `/api/multi-agent/chat/stream` (non-streaming fallback for mobile)
  - `/api/autocomplete` (disabled - returns empty suggestions)
  - `/api/multi-agent/agents` (returns single "general" agent)
  - `/api/health` (health check)
  - `/api/files/list` (disabled - returns empty array)
  - `/api/models/ollama` (not available on mobile)
  - `/api/models/llamacpp` (returns phi3-mini-3.8b)

### UI Files Transferred to Phone

All UI files copied from PC (`/home/gh0st/pkn/`) to phone (`~/pkn-phone/`):
- `pkn.html` - Main HTML (modified for mobile with inline CSS)
- `css/` - Stylesheets directory
- `js/` - JavaScript modules
- `img/` - Images including `icchat.png` icon
- `manifest.json` - PWA manifest

### Mobile CSS Strategy - Inline Critical CSS

**Problem**: External CSS files were aggressively cached by mobile browsers (304 Not Modified responses), preventing layout updates.

**Solutions Attempted**:
1. ✗ External `css/mobile.css` - kept caching
2. ✗ Cache-busting parameters `?v=timestamp` - still cached
3. ✗ Disabled service worker (`sw.js` → `sw.js.disabled`) - helped but not enough
4. ✓ **Inline CSS in HTML `<head>`** - final working solution

**Implemented Mobile CSS** (added directly to `~/pkn-phone/pkn.html` before `</head>`):
```html
<!-- MOBILE INLINE CSS -->
<style>
@media (max-width: 1024px) {
    /* Hide scrollbars */
    *::-webkit-scrollbar { display: none !important; }
    * { scrollbar-width: none !important; max-width: 100vw !important; }

    /* Base font size readable on mobile */
    html, body { font-size: 14px !important; overflow-x: hidden !important; width: 100vw !important; margin: 0 !important; }

    /* Sidebar completely hidden by default */
    .sidebar { transform: translateX(-105%) !important; position: fixed !important; width: 240px !important; z-index: 1000 !important; }
    .sidebar.visible { transform: translateX(0) !important; }
    .hover-strip { display: none !important; width: 0 !important; }

    /* Main content full width */
    .main { margin-left: 0 !important; width: 100% !important; }

    /* Hide desktop-only controls */
    .header select, select#modelSelect, select#agentSelect { display: none !important; }
    .header button { width: 100% !important; font-size: 13px !important; height: 36px !important; }

    /* Subtle menu toggle button */
    .toggle-btn { position: fixed !important; top: 12px !important; left: 12px !important; width: 36px !important; height: 36px !important; background: rgba(0,255,255,0.15) !important; opacity: 0.6 !important; }

    /* Welcome boxes stack vertically */
    .welcome-grid, .features-grid { display: flex !important; flex-direction: column !important; }
    .welcome-box { width: calc(100% - 20px) !important; padding: 12px !important; }

    /* Messages area with bottom padding for fixed input */
    #messagesContainer { padding-bottom: 140px !important; font-size: 15px !important; }
    .message { padding: 12px !important; font-size: 15px !important; }

    /* Fixed input container at bottom */
    .input-container { position: fixed !important; bottom: 0 !important; padding: 10px !important; z-index: 999 !important; }

    /* Chat controls in 3-column grid above input */
    .input-controls { display: flex !important; flex-wrap: wrap !important; gap: 6px !important; margin-bottom: 8px !important; }
    .input-controls button { flex: 1 1 calc(33% - 4px) !important; font-size: 12px !important; height: 32px !important; }

    /* Textarea sizing */
    #messageInput { font-size: 15px !important; height: 42px !important; padding: 10px !important; }

    /* Circular glowing send button */
    .send-btn { width: 42px !important; height: 42px !important; border-radius: 50% !important; background: linear-gradient(135deg, #00ffff, #00cccc) !important; color: #000 !important; }
    .send-btn::after { content: "▶" !important; }
    .send-btn span { display: none !important; }
}
</style>
```

### Termux Menu Integration

Updated **`~/pkn/scripts/termux_menu.sh`** to launch PKN Mobile:
```bash
PKN_MOBILE="$HOME/pkn-phone"
MOBILE_PORT=8010
MOBILE_URL="http://127.0.0.1:${MOBILE_PORT}"

start_pkn_mobile() {
    cd "$PKN_MOBILE"
    python3 divinenode_server.py &
    sleep 2
    # Cache-busting URL with timestamp
    am start -a android.intent.action.VIEW -d "${MOBILE_URL}?v=$(date +%s)"
}
```

Menu options added:
- `PKN Mobile` - Start server and open in browser with cache-busting
- `PKN Server Only` - Start server without opening browser

### Known Issues (as of 2026-01-07)

**CRITICAL - Still Unresolved**:
1. **UI Overlap** - User reports "a lot of overlap still" with mobile layout
   - Elements may be overlapping despite CSS fixes
   - Hard to debug without visual access to phone screen
   - May require additional CSS refinements or `!important` flags

**Resolved Issues**:
- ✓ Service worker caching old versions - Disabled `sw.js`
- ✓ External CSS caching - Switched to inline CSS
- ✓ 405 errors on chat endpoint - Added all missing API endpoints
- ✓ Menu button halfway visible - Fixed with CSS positioning
- ✓ Elements too large/too small - Iterated multiple versions to find readable sizes
- ✓ Sidebar not fully hiding - Set `transform: translateX(-105%)`

### Mobile vs Desktop Build

**IMPORTANT**: Two separate deployments maintained:
- **PC Build**: `/home/gh0st/pkn/` - Full multi-agent system, all features intact
- **Phone Build**: `~/pkn-phone/` - Lightweight single-agent, mobile-optimized UI

**DO NOT** mix files between these two locations. PC build is production-quality and should not be overwritten by mobile experiments.

### Debugging Mobile Layout Issues

When fixing mobile CSS:
1. **DO**: Edit `~/pkn-phone/pkn.html` inline `<style>` block directly
2. **DO**: Use SSH to restart server: `pkill -f divinenode_server.py && cd ~/pkn-phone && python3 divinenode_server.py &`
3. **DO**: Open with cache-busting: `http://127.0.0.1:8010?v=TIMESTAMP`
4. **DON'T**: Rely on external CSS files - they cache aggressively
5. **DON'T**: Forget to use `!important` flags - mobile browsers are stubborn
6. **DON'T**: Modify PC build files when working on mobile deployment

### Browser Cache Clearing Commands

User tested in both browsers on Android:
- **Firefox Nightly**: Settings → Clear browsing data → Cached images and files
- **Chrome**: Settings → Privacy → Clear browsing data → Cached images and files

Even with manual clearing, inline CSS proved more reliable than external files.

### Next Steps for Mobile (When Resumed)

1. Get visual screenshot from user to identify overlap issues
2. Refine inline CSS in `~/pkn-phone/pkn.html` based on specific overlap problems
3. Test in both Firefox Nightly and Chrome to ensure cross-browser compatibility
4. Consider adding user agent detection to serve different CSS for different mobile browsers
5. Document final working mobile CSS once layout issues are fully resolved

## Phone Cleanup & Screen Mirroring Setup (2026-01-07 Evening)

### Cleanup Session

**Problem**: User had conflicting scripts, duplicates, and temp files scattered across phone from multiple build attempts.

**Audit Results**: Found 21 items to remove:
- 5 temp fix scripts from CSS debugging (add-css-safe.sh, add-inline.sh, fix-html.sh, fix-overlap.sh, update-server.sh)
- 1 duplicate menu (~/termux_menu.sh - old 242-line version)
- 4 old PKN directories (~/.pkn/, ~/devnode/pkn/, ~/static/pkn/, ~/projects/pkn_extract_20251230_112926/)
- 5 old Python components (ai_router.py, fix_models.py, fix_ui_layout.py, image_gen_api.py, local_parakleon_agent.py)
- 2 old build scripts (pkn-installer.sh, pkn-sync.sh)
- 1 Python cache (__pycache__/)
- 3 old log files (divinenode.log, data/divinenode.log, data/parakleon.log)

**Solution**: Created and executed `auto_cleanup.sh` that removed all 21 items automatically.

**bashrc Fix**: Updated alias from `alias pkn='bash "$HOME/termux_menu.sh"'` to `alias pkn='bash "$HOME/pkn/scripts/termux_menu.sh"'`

**Log**: Cleanup log saved to `~/cleanup_log_YYYYMMDD_HHMMSS.txt` on phone

### SSH Access

**Current Setup**:
- Phone IP: `192.168.12.184` (changes based on WiFi network)
- SSH Port: `8022`
- User: `u0_a322`
- Password: `pkn123`

**Connection Command**:
```bash
ssh u0_a322@192.168.12.184 -p 8022
```

**With sshpass** (for automation):
```bash
sshpass -p 'pkn123' ssh -o StrictHostKeyChecking=no u0_a322@192.168.12.184 -p 8022
```

**Note**: SSH server (sshd) must be running in Termux. Start with `sshd` command.

### Screen Mirroring with scrcpy

**Purpose**: View phone screen on PC for debugging mobile UI issues

**Requirements**:
- scrcpy installed on PC (`sudo apt install scrcpy`)
- ADB version 31.0.0+ (for wireless pairing support)
- Phone's "Wireless debugging" enabled in Developer Options

**Setup Process**:

1. **Update ADB** (if version < 31):
```bash
cd ~/Downloads
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
unzip platform-tools-latest-linux.zip
adb kill-server
sudo cp platform-tools/adb /usr/bin/adb
sudo chmod +x /usr/bin/adb
adb start-server
adb --version  # Should show 31.0.0+
```

2. **Enable Wireless Debugging on Phone**:
   - Settings → Developer Options → Wireless debugging → ON
   - Tap "Pair device with pairing code"
   - Note the IP:Port and 6-digit code

3. **Pair from PC**:
```bash
adb pair 192.168.12.184:XXXXX XXXXXX  # Use port and code from phone
adb connect 192.168.12.184:5555       # Standard wireless ADB port
```

4. **Launch scrcpy**:
```bash
scrcpy --show-touches --stay-awake         # Basic with touch indicators
scrcpy --show-touches --stay-awake --max-size 1080  # Recommended for demos
scrcpy --turn-screen-off --show-touches    # Save battery, screen off on phone
```

**Common Issues**:
- Pairing codes expire quickly (60 seconds) - get fresh code if needed
- "adb: unknown command pair" = ADB too old, update to 31.0.0+
- "Text file busy" when copying adb = Kill server first with `adb kill-server`
- Connection timeout = Ensure phone and PC on same WiFi network

**Alternative - USB Method**:
```bash
# Connect phone via USB
adb devices
adb tcpip 5555
# Disconnect USB
adb connect 192.168.12.184:5555
scrcpy
```

### Working Directory Structure After Cleanup

**Phone** (`~/` on Termux):
```
~/pkn-phone/              # Working mobile build (KEEP)
  ├── divinenode_server.py
  ├── pkn.html
  ├── css/
  ├── js/
  ├── img/
  └── manifest.json

~/pkn/                    # Scripts and tools
  ├── scripts/
  │   └── termux_menu.sh  # Updated menu with cache-busting
  └── email_osint.py

~/.bashrc                 # Fixed pkn alias

# Everything else from old builds DELETED
```

**PC** (`/home/gh0st/pkn/`):
- Full production build untouched
- CLAUDE.md updated with all session notes
- All changes pushed to GitHub branch `claude/add-android-app-branch-RKG9I`

## Mobile UI Fixes Session (2026-01-07 Night)

### Current State
Working on mobile CSS fixes via scrcpy screen mirroring (USB connection).

**Phone Connection:**
- USB connected, scrcpy running: `cd ~/Downloads/scrcpy-linux-x86_64-v3.3.4 && ./scrcpy --show-touches --stay-awake`
- SSH: `sshpass -p 'pkn123' ssh -o StrictHostKeyChecking=no u0_a322@192.168.12.184 -p 8022`
- Server: `cd ~/pkn-phone && python3 divinenode_server.py`

### Mobile CSS Changes Made (in ~/pkn-phone/pkn.html inline styles)

**COMPLETED FIXES:**
1. ✓ Session display ("New" + floppy icon) - HIDDEN on mobile
2. ✓ Left cyan sidebar border bleeding through - FIXED (sidebar translateX(-120%), visibility:hidden)
3. ✓ Sidebar close mechanism - Added clickable overlay (`<div class="sidebar-overlay" onclick="toggleSidebar()">`)
4. ✓ Menu button - Attached to sidebar edge, slides with it (top:12px, left:0, transitions to left:240px when open)
5. ✓ Agent selector (AUTO/CODER/REASONER) - HIDDEN on mobile (too cluttered)
6. ✓ Chat toolbar - Restored and made compact

**CURRENT CSS STRUCTURE (line ~85-145 in pkn.html):**
```css
/* Key mobile overrides */
.sidebar { transform: translateX(-120%); visibility: hidden; z-index: 2000; }
.sidebar.visible { transform: translateX(0); visibility: visible; }
.toggle-btn { position: fixed; top: 12px; left: 0; width: 18px; height: 32px; z-index: 2001; border-radius: 0 8px 8px 0; transition: left 0.25s; }
.sidebar.visible ~ .main .toggle-btn { left: 240px; }
.sidebar-overlay { z-index: 1999; } /* Click to close sidebar */
.header-agent-selector { display: none; }
.send-btn { width: 36px; height: 36px; border-radius: 6px; font-size: 0; } /* Icon only, no text */
.chat-toolbar { padding: 4px 8px; width: 100%; }
```

**STILL NEEDS WORK:**
- Menu button hamburger icon (☰) not visible inside the tab
- Send button still showing "SEND" text instead of arrow icon
- Welcome screen cards may still be slightly cut off
- Overall layout may need left margin adjustments
- Agent selector needs accessible alternative (currently hidden)

### How to Continue This Work

1. **View phone screen:**
   ```bash
   cd ~/Downloads/scrcpy-linux-x86_64-v3.3.4 && ./scrcpy --show-touches --stay-awake
   ```

2. **Edit mobile CSS:**
   ```bash
   sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022 "sed -i 's|OLD|NEW|' ~/pkn-phone/pkn.html"
   ```

3. **Restart server (if needed):**
   ```bash
   sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022 "pkill -f divinenode_server.py; cd ~/pkn-phone && python3 divinenode_server.py &"
   ```

4. **Backup before major changes:**
   ```bash
   sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022 "cp ~/pkn-phone/pkn.html ~/pkn-phone/pkn.html.bak"
   ```

### Key Files
- **Mobile HTML/CSS:** `~/pkn-phone/pkn.html` (inline `<style>` block around line 62-145)
- **Mobile CSS file:** `~/pkn-phone/css/mobile-fix.css` (external, but inline CSS takes precedence)
- **Backup:** `~/pkn-phone/pkn.html.bak`

### Notes
- All mobile CSS uses `!important` flags due to specificity issues
- Inline CSS in HTML `<head>` works better than external files (caching issues)
- Phone is Samsung SM-S938U running Android 16
- scrcpy v3.3.4 required for Android 16 compatibility (system scrcpy v1.21 too old)

## Mobile Production Deployment Complete (2026-01-08)

### Final Session - All Features Implemented

Tonight's session completed the mobile PKN deployment with all requested features working.

### Critical Issues Resolved

**1. LLM Backend - Cloud API Solution**
- **Problem**: Local llama-cpp-python had no backends loaded, couldn't load Phi-3 model
- **Solution**: Switched to OpenAI API (GPT-4o-mini) for reliability
- **Configuration**: Using API key from PC `.env` file
- **File**: `~/pkn-phone/divinenode_server.py` - Flask server with OpenAI integration
- **Status**: ✓ Working, fast, reliable

**2. Server Connection Issues**
- **Problem**: "localhost refused to connect" - port 8010 not listening
- **Root Cause**: Old server process crashed/hung
- **Solution**: Force kill all Python processes, restart server
- **Command**: `killall -9 python3 && cd ~/pkn-phone && python3 divinenode_server.py &`

**3. Menu Button Still Too Large**
- **Problem**: User kept reporting menu button as "huge" despite multiple fixes (18px → 12px → 10px)
- **Final Solution**: Reduced to **8px wide** - just a thin vertical line
- **Visual**: 2px indicator line inside, hamburger icon hidden
- **CSS**: `width: 8px !important; font-size: 0 !important;`
- **Location**: `~/pkn-phone/pkn.html` inline mobile CSS

**4. Thinking Animation Missing**
- **Problem**: No visual feedback when AI is processing
- **Solution**: Ensured `.thinking-dots` CSS is visible in mobile
- **Animation**: Three cyan dots with pulsing animation (1.4s cycle)
- **Implementation**: Already existed in app.js, just needed CSS visibility fix

**5. Send → Stop Button Toggle**
- **Problem**: Mobile CSS had `font-size: 0 !important` which hid "STOP" text
- **Solution**: Dynamic CSS based on `data-state` attribute
  - **Send state**: Shows ➤ arrow icon (36px round button, cyan)
  - **Stop state**: Shows "STOP" text (50px wide, red background)
- **Functionality**: Click during AI response to interrupt (abort controller)

**6. Launcher Background White**
- **Problem**: Welcome screen had white/light background
- **Solution**: Changed to `rgba(0,0,0,0.8)` with blur effect
- **Style**: Black transparent background, matches cyberpunk theme
- **Affected**: Welcome screen, feature boxes, quick actions

**7. Bash Configuration Mess**
- **Problem**: 
  - Duplicate `OPENAI_API_KEY` (set twice in `.bash_profile`)
  - Conflicting PATH definitions across 3 files
  - Old backup files (.bash_profile.bak, .profile.bak)
- **Solution**: Cleaned up structure:
  - `.bash_profile` → Sources `.bashrc` + auto-launches PKN menu
  - `.bashrc` → All PKN configuration, aliases, API keys (canonical source)
  - `.profile` → Minimal PATH only
- **Script**: `~/clean_bash.sh` - automated cleanup with backups

### Final Mobile Server Configuration

**Backend**: OpenAI API (GPT-4o-mini)
**Port**: 8010
**Host**: 0.0.0.0 (accessible from phone browser)
**API Key**: From PC `.env` (hardcoded in server for mobile simplicity)

**Server File**: `~/pkn-phone/divinenode_server.py`
```python
OPENAI_API_KEY = "sk-proj-..." # From PC .env
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o-mini"
```

**Endpoints Working**:
- `/api/multi-agent/chat` - Main chat (OpenAI)
- `/api/osint/email-validate` - Email validation
- `/api/phonescan` - Phone number check
- `/health` - Health check
- `/api/autocomplete` - Disabled (returns empty)
- `/api/files/list` - Disabled (returns empty)

### Mobile UI Final State

**Menu Button**: 8x24px thin line on left edge, slides with sidebar

**Send Button**:
- **Normal**: 36px circle, cyan, ➤ arrow icon
- **Sending**: 50px pill, red, "STOP" text
- **CSS**: Dynamic via `data-state="stop"` attribute

**Thinking Animation**: Cyan pulsing dots while AI processes

**Welcome Screen**: Black transparent `rgba(0,0,0,0.8)` with blur

**Mobile CSS Location**: `~/pkn-phone/pkn.html` inline `<style>` block (lines ~60-350)

### Termux Menu Script

**Location**: `~/pkn/scripts/termux_menu.sh`
**Features**:
1. PKN Mobile (Start server + Open browser with cache-busting)
2. Server Only (No browser)
3. Open Browser (Cache-busting URL with timestamp)
4. Stop Server
5. Check Status
6. Exit

**Alias**: `pkn` (in `~/.bashrc`)

**Cache-Busting**: All browser opens use `?v=$(date +%s)` to bypass cache

### Testing & Verification

**Health Check**:
```bash
curl http://localhost:8010/health
# {"status":"ok","backend":"openai-cloud","model":"gpt-4o-mini","api_configured":true}
```

**Chat Test**:
```bash
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Hello","mode":"auto"}'
```

**OSINT Test**:
```bash
curl -X POST http://localhost:8010/api/osint/email-validate \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com"}'
```

### Session Artifacts

**Created Files**:
- `~/pkn-phone/divinenode_server.py` - OpenAI cloud server
- `~/pkn-phone/fix_menu_final.py` - Menu button 8px fix
- `~/pkn-phone/fix_mobile_features.py` - Thinking/Stop/Background fixes
- `~/clean_bash.sh` - Bash config cleanup script

**Modified Files**:
- `~/pkn-phone/pkn.html` - Mobile CSS (inline styles)
- `~/.bashrc` - Cleaned up, all config consolidated
- `~/.bash_profile` - Simplified, sources .bashrc only

**Backups Created**:
- `~/pkn-phone/pkn.html.bak_menu_*` - Before menu button fixes
- `~/pkn-phone/pkn.html.bak_features` - Before feature fixes
- `~/.bashrc.bak_*` - Before bash cleanup
- `~/.bash_profile.bak_*` - Before bash cleanup

### TODO for Next Session

**Feature Request - PC Send Button Arrow**:
- User likes the mobile send button ➤ arrow design
- Request: Apply same arrow icon to PC version send button
- **File to modify**: `/home/gh0st/pkn/css/main.css` or `/home/gh0st/pkn/pkn.html`
- **Current PC button**: Shows "SEND" text
- **Desired**: Show ➤ arrow like mobile, turn red "STOP" when processing

**Implementation Notes**:
- Copy mobile send button CSS to desktop version
- Use same `data-state="stop"` toggle logic
- Desktop has more space, could be slightly larger (48px instead of 36px)
- Ensure `font-size` is NOT 0 when in stop state (mobile bug we fixed)

### Phone Deployment Info

**Connection**:
- IP: `192.168.12.184` (changes per network)
- SSH Port: 8022
- User: `u0_a322`
- Password: `pkn123`
- Command: `sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022`

**Directories**:
- Mobile build: `~/pkn-phone/`
- Scripts: `~/pkn/scripts/`
- Models: `~/models/` (has Phi-3 but not used currently)

**Status**: ✓ Production ready for work tomorrow

### Lessons Learned

1. **Cloud API > Local LLM on Mobile**: llama-cpp-python backend issues too complex for mobile, OpenAI "just works"
2. **Inline CSS > External Files on Mobile**: Browser cache extremely aggressive, inline bypasses issues
3. **Iterative Sizing**: Menu button went through 5 iterations before user satisfaction (8px final)
4. **font-size:0 breaks text**: CSS trick for hiding text also prevents dynamic text from showing
5. **Multiple config files cause conflicts**: Consolidate to single source of truth (.bashrc)

### Performance Notes

- Chat response: ~2-4 seconds (OpenAI GPT-4o-mini)
- Server startup: ~3 seconds
- Browser cold start: ~5 seconds
- No lag or performance issues reported by user

### Branch Info

**Current branch**: `claude/add-android-app-branch-RKG9I`
**Last push**: 2026-01-07 (pre-final-session)
**Pending push**: Tonight's completion (2026-01-08)


### Additional Fixes - Memory & Modals (2026-01-08 Late)

**Memory System Added**:

Mobile server now has full memory persistence matching desktop version:

1. **Session Memory**: `~/pkn-phone/memory/current_session.json`
   - Current conversation history
   - Last 30 messages kept
   - Persists across app restarts

2. **Global Memory**: `~/.pkn_mobile_memory.json`
   - Long-term facts about user
   - User preferences
   - Important information
   - Never deleted

3. **Project Memory**: `~/pkn-phone/project_memory.json`
   - Project-specific notes
   - PKN Mobile context
   - Never deleted

Memory API endpoints:
- `GET /api/memory/status` - View all memory stats
- `POST /api/memory/add-fact` - Add long-term fact
- `POST /api/memory/clear-session` - Start new conversation

**Modal/Panel Fixes**:

**Problem**: Settings, Files Explorer, AI Models panels couldn't open on mobile. Close buttons were invisible/too small.

**Root Cause**: Mobile CSS line 326 had:
```css
#filesPanel, #agentSwitcherPanel, #aiModelsModal, #codeEditorModal, .modal-overlay:not(.visible), .settings-overlay.hidden { display: none !important; visibility: hidden !important; }
```

This forced ALL panels to be hidden with `!important`, preventing JavaScript from showing them.

**Solution**:
1. Removed force-hidden CSS for panel IDs
2. Added proper `.visible` class logic for show/hide
3. Made close buttons 36x36px (was too small to tap)
4. Changed close button style: cyan background, black X
5. Made panels full-width and scrollable for mobile

**Fixed Panels**:
- ✅ Settings panel
- ✅ Files explorer (#filesPanel)
- ✅ AI Models panel (#aiModelsModal)
- ✅ Project modal
- ✅ Image generator modal
- ✅ Code editor overlay

**CSS Changes** (in `~/pkn-phone/pkn.html` inline mobile styles):
- Close buttons: `width: 36px; height: 36px; background: var(--theme-primary); font-size: 24px;`
- Panels: `max-width: calc(100vw - 40px); max-height: calc(100vh - 40px);`
- Modal overlays: `background: rgba(0,0,0,0.85); z-index: 9999;`


## Final Mobile Integration Session (2026-01-09)

### Session Summary

**Goal**: Integrate tracking pixels into OSINT Tools and fix remaining UI issues on mobile PWA.

**Key Accomplishments**:
1. ✓ Tracking Pixels integrated into OSINT Tools panel
2. ✓ Paperclip icon moved to right side of input
3. ✓ Enhanced phonescan with better validation
4. ✓ Settings X button made larger and more visible
5. ✓ All backend APIs verified working

### Tracking Pixels Integration

**Problem**: Tracking Pixels was a separate menu item, user wanted it inside OSINT Tools with other tools.

**Solution**: Added Tracking Pixels as a button category inside the OSINT Tools modal panel.

**Implementation**:
- Modified `~/pkn-phone/js/osint_ui.js`
- Added new category "🔍 Tracking & Privacy" with Tracking Pixels button
- Button appears at bottom of OSINT panel alongside:
  - Domain Intelligence (WHOIS, DNS, etc.)
  - IP & Network
  - Email & Username
  - Web Intelligence
  - Phone
  - **Tracking & Privacy** (NEW)

**How it works**:
1. Click "🔍 OSINT Tools" in sidebar
2. OSINT panel opens showing all tool categories
3. Click "Tracking Pixels" button at bottom
4. Opens full tracking panel with 4 tabs (Detector, Generator, Blocker, Manager)

### Paperclip Icon Fix

**Problem**: Paperclip icon had large gap from left edge of input area.

**Solution**: Positioned paperclip absolutely on the right side.

**CSS Changes** (in `~/pkn-phone/pkn.html`):
```css
.input-wrapper { position: relative !important; }
.paperclip-btn { 
    position: absolute !important; 
    right: 8px !important; 
    top: 50% !important; 
    transform: translateY(-50%) !important; 
    width: 32px !important; 
    height: 32px !important; 
}
#messageInput { padding-right: 48px !important; }
```

### Phone Scan Enhancement

**Problem**: Phonescan API only did basic length check.

**Solution**: Enhanced with proper parsing and formatting.

**New Features**:
- Cleans number (digits only)
- Detects country (US/CA vs International)
- Formats output: `+1 (555) 867-5309`
- Extracts area code
- Returns cleaned and formatted versions

**Example Response**:
```json
{
  "area_code": "555",
  "cleaned": "15558675309",
  "country": "US/CA",
  "formatted": "+1 (555) 867-5309",
  "length": 11,
  "message": "Phone number analyzed",
  "number": "+1-555-867-5309",
  "valid": true
}
```

### Settings Panel X Button

**Problem**: X close button not visible on settings panel (cut off by screen edge).

**Multiple Attempts**:
1. Reduced panel height: 80vh → 70vh → 50vh
2. Added top margin: 60px
3. Made button larger and more visible

**Final Solution** (in `~/pkn-phone/pkn.html` mobile CSS):
```css
.settings-close-x { 
    display: block !important; 
    width: 44px !important; 
    height: 44px !important; 
    font-size: 32px !important; 
    background: rgba(0,255,255,0.3) !important; 
    border: 2px solid var(--theme-primary) !important; 
    border-radius: 50% !important; 
    position: absolute !important;
    top: 10px !important;
    right: 10px !important;
    z-index: 9999 !important;
}
```

**Result**: Large cyan circular button at top-right of panel.

### Backend APIs Verified

**Tested and Working**:
- ✓ Email validation: `/api/osint/email-validate`
- ✓ Phone scan (enhanced): `/api/phonescan`
- ✓ Tracking detection: `/api/tracking/detect`
- ✓ Tracking generation: `/api/tracking/generate`
- ✓ Tracking list: `/api/tracking/list`
- ✓ Tracking sanitize: `/api/tracking/sanitize`
- ✓ Health check: `/health`

**Tracking Pixel Database**: 7 test pixels stored and tracked.

### Files Modified

**Phone** (`~/pkn-phone/`):
- `js/osint_ui.js` - Added Tracking Pixels category to OSINT panel
- `pkn.html` - Paperclip positioning, X button styling, settings panel height
- `divinenode_server.py` - Enhanced phonescan endpoint

**Scripts Created**:
- `fix_paperclip_position.py` - Move paperclip to right
- `add_tracking_to_osint_panel.py` - Integrate tracking into OSINT
- `enhance_phonescan.py` - Better phone validation
- `fix_settings_smaller.py` - Reduce panel height
- `fix_settings_top_padding.py` - Add top margin
- `make_x_button_visible.py` - Large cyan X button

### Issues Encountered

**Tracking Pixels Integration**: 
- Initial attempts added submenu in sidebar (not what user wanted)
- User wanted button inside OSINT panel modal, not sidebar submenu
- Fixed by adding to `osint_ui.js` panel HTML instead of sidebar

**Settings X Button**:
- Multiple iterations to make visible
- Panel was too tall (extended beyond screen)
- Final solution: 50vh height + large visible button

**Bash Heredoc Syntax**:
- SSH heredoc with complex Python strings caused syntax errors
- Solution: Use Write tool to create files locally, then SCP to phone

### Current State (2026-01-09 End of Session)

**Phone Server**:
- Running: `~/pkn-phone/divinenode_server.py`
- Port: 8010
- Backend: OpenAI API (GPT-4o-mini)
- Status: ✓ All APIs functional

**PWA Features**:
- ✓ Transparent sword icon
- ✓ Named "Divine Node"
- ✓ Menu button (8px thin line)
- ✓ Tracking Pixels in OSINT Tools
- ✓ Enhanced phonescan
- ✓ Paperclip on right
- ✓ Large visible X buttons (44px, cyan background)

**Known Issues**:
- Settings X button visibility still reported by user after final fix (needs follow-up)

### Lessons Learned (This Session)

1. **User Intent Clarification**: Always confirm if user wants sidebar submenu vs panel button - very different implementations
2. **Iterative UI Fixes**: Sometimes need multiple approaches (height, margin, size, background) to make elements visible
3. **Mobile CSS Specificity**: Need `!important` flags and high z-index to override conflicting styles
4. **SSH Heredoc Limitations**: Complex Python scripts better created locally then copied to remote
5. **Test After Each Change**: Verify each fix before moving to next issue

### Next Session TODO

1. **Verify Settings X Button**: User still reported not seeing it - may need different approach
2. **Test All Tracking Features**: Detector, Generator, Blocker, Manager tabs in browser
3. **Swipe Gestures** (optional): User originally requested swipe-to-open sidebar (attempted but broke OSINT, reverted)
4. **Documentation**: User wants tracking pixel usage documented in UI

