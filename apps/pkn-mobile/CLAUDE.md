# CLAUDE.md - PKN Mobile

This file provides guidance to Claude Code when working with the PKN Mobile codebase.

**🔴 CRITICAL: Read `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md` BEFORE making any changes.**

---

## 📚 Documentation Cross-References

**This file is part of a larger documentation system. See related docs:**

| Topic | Document | Description |
|-------|----------|-------------|
| **All Docs Index** | [docs/INDEX.md](../../docs/INDEX.md) | Central documentation hub |
| **Agents** | [docs/AGENTS.md](../../docs/AGENTS.md) | All 9 agents, models, tools |
| **Tools** | [docs/TOOLS.md](../../docs/TOOLS.md) | 90+ tools reference |
| **OSINT** | [docs/SHADOW_OSINT.md](../../docs/SHADOW_OSINT.md) | 35 Shadow OSINT tools |
| **Deployment** | [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md) | Deploy all apps |
| **Mobile Deploy** | [docs/DEPLOYMENT_MOBILE.md](./docs/DEPLOYMENT_MOBILE.md) | Termux/Android setup |
| **Mobile Issues** | [docs/TROUBLESHOOTING_MOBILE.md](./docs/TROUBLESHOOTING_MOBILE.md) | Mobile troubleshooting |
| **Architecture** | [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) | System design |
| **Troubleshooting** | [docs/TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md) | Common issues |

**When to reference other docs:**
- Agent configuration details → [AGENTS.md](../../docs/AGENTS.md)
- Tool usage → [TOOLS.md](../../docs/TOOLS.md)
- OSINT operations → [SHADOW_OSINT.md](../../docs/SHADOW_OSINT.md)
- Deployment issues → [DEPLOYMENT_MOBILE.md](./docs/DEPLOYMENT_MOBILE.md)

---

## 🚨 NON-NEGOTIABLE PROJECT REQUIREMENTS

**READ THIS SECTION FIRST. THESE ARE HARD REQUIREMENTS THAT MUST NEVER BE VIOLATED.**

### 1. LOCAL-FIRST ARCHITECTURE (Privacy by Default)

```
┌─────────────────────────────────────────────────────────────────┐
│  THIS PROJECT IS BUILT AROUND GIVING THE USER A MORE PRIVATE   │
│  EXPERIENCE PLUS THE OPTION TO RUN CLOUD IF SPEED IS NEEDED.   │
│                                                                 │
│  LOCAL INFERENCE IS THE DEFAULT. CLOUD IS THE OPTION.          │
│  NEVER SUGGEST CLOUD-ONLY OR REMOVE LOCAL CAPABILITY.          │
└─────────────────────────────────────────────────────────────────┘
```

**What this means:**
- ✅ DEFAULT: All agents run locally via Ollama
- ✅ OPTION: User can toggle to cloud (Groq/OpenAI) when speed needed
- ❌ NEVER: Suggest removing local inference
- ❌ NEVER: Make cloud the only option
- ❌ NEVER: Say "local is too slow, just use cloud"

**Backend Toggle:**
- Endpoint: `/api/multi-agent/backend`
- Values: `"local"` (default) or `"cloud"`
- User controls this, not Claude

### 2. UNCENSORED/ABLITERATED MODELS (Security Work)

**The security agent MUST use uncensored models for legitimate pentesting work.**

**Required Uncensored Models (Installed on Phone):**
| Model | Size | Purpose | Agent |
|-------|------|---------|-------|
| `dolphin-phi:latest` | 1.6GB | Fast uncensored security | SECURITY |
| `nous-hermes:latest` | 3.8GB | Uncensored reasoning | REASONER |

**Why uncensored models are required:**
- User does legitimate security/pentesting work
- Need models that can discuss: SQL injection, XSS, buffer overflows, etc.
- Censored models refuse helpful security education
- "Abliterated" = fine-tuned to remove safety guardrails

**Model Assignment (in `backend/config/model_config.py`):**
```python
MOBILE_LOCAL_MODELS = {
    "security": {
        "model": "ollama:dolphin-phi:latest",  # MUST be uncensored
        "uncensored": True,
    },
    "reasoner": {
        "model": "ollama:nous-hermes:latest",  # Uncensored for security analysis
        "uncensored": True,
    },
    # ... other agents use standard models
}
```

### 3. USER'S HARDWARE (Samsung Galaxy S24 Ultra)

**DO NOT UNDERESTIMATE THIS PHONE'S CAPABILITIES.**

| Spec | Value |
|------|-------|
| **Model** | Samsung Galaxy S24 Ultra (SM-S938U) |
| **SoC** | Snapdragon 8 Gen 3 |
| **RAM** | 12GB |
| **Storage** | 256GB+ |
| **AI Capability** | Can run 7B models easily, 14B models with patience |

**This phone CAN:**
- ✅ Run Ollama with multiple 7B models
- ✅ Run qwen2.5-coder:7b (4.7GB) in ~10 seconds
- ✅ Run dolphin-phi:latest in ~7 seconds
- ✅ Handle local LLM inference for all daily use

**Response Time Benchmarks (Measured 2026-01-18):**
| Model | Response Time | Use Case |
|-------|---------------|----------|
| qwen:latest (2.3GB) | ~0.8s | Fast general queries |
| dolphin-phi:latest (1.6GB) | ~7.2s | Security questions |
| nous-hermes:latest (3.8GB) | ~12.9s | Complex reasoning |
| qwen2.5-coder:7b (4.7GB) | ~10s | Code generation |

### 4. AGENT CONFIGURATION EXPECTATIONS

**All 9 agents must be configured with appropriate models:**

| Agent | Model | Uncensored | Purpose |
|-------|-------|------------|---------|
| CODER | qwen2.5-coder:7b | No | Code writing, debugging |
| GENERAL | qwen:latest | No | Quick Q&A |
| REASONER | nous-hermes:latest | **Yes** | Planning, logic |
| SECURITY | dolphin-phi:latest | **Yes** | Pentesting, security |
| RESEARCHER | mistral:latest | No | Research, docs |
| EXECUTOR | qwen2.5-coder:7b | No | System commands |
| VISION | llava:latest | No | Image analysis |
| CONSULTANT | Claude API | N/A | Cloud fallback |
| VISION_CLOUD | Groq | N/A | Fast cloud vision |

### 6. MODEL CHANGES POLICY

```
┌─────────────────────────────────────────────────────────────────┐
│  DO NOT CHANGE THE AI MODEL CONFIGURATION UNLESS:              │
│                                                                 │
│  1. A BETTER model exists that improves ALL-AROUND performance │
│  2. The new model is FASTER and HIGHER QUALITY                 │
│  3. Uncensored requirements are STILL MET                      │
│                                                                 │
│  NEVER change models just because you think something else     │
│  would be "easier" or "more standard". Performance is king.    │
└─────────────────────────────────────────────────────────────────┘
```

**Valid reasons to suggest a model change:**
- ✅ New uncensored model released that's faster AND better quality
- ✅ Existing model deprecated/unavailable
- ✅ User explicitly requests evaluation of alternatives

**Invalid reasons:**
- ❌ "This model is more popular"
- ❌ "This would be simpler to configure"
- ❌ "I'm more familiar with this model"
- ❌ "The censored version is safer"

### 5. TOOLS MUST BE ENABLED

**All 13 tool modules must be accessible to all agents:**
- code_tools, file_tools, system_tools, web_tools
- memory_tools, osint_tools, rag_tools, planning_tools
- delegation_tools, chain_tools, sandbox_tools, evaluation_tools
- advanced features

**Never disable tools or suggest removing them.**

---

## 🐛 DEBUGGING HISTORY & KNOWN ISSUES

### Issues We've Already Solved (Don't Re-Introduce)

**1. PWA Black Screen on PC (Fixed 2026-01-18)**
- **Problem:** PC PWA opened to black screen, needed hard refresh
- **Cause:** Service worker v1.0.0 using cache-first for HTML/JS
- **Fix:** Updated to v2.0.0 with network-first for HTML/JS
- **File:** `/apps/pkn/www/service-worker.js`

**2. Model Config Referencing Missing Models (Fixed 2026-01-18)**
- **Problem:** MOBILE_LOCAL_MODELS referenced models not installed
- **Fix:** Updated config to use actually installed models
- **File:** `~/pkn/backend/config/model_config.py` (on phone)

**3. Phone Cleanup - Old Files Removed (Fixed 2026-01-17)**
- **Removed:** ~/pkn-phone/ (17MB old duplicate)
- **Removed:** ~/llama.cpp-termux/ (2.4GB duplicate)
- **Removed:** 22+ old scripts and configs
- **Single PKN directory:** `~/pkn/` on phone

**4. Mobile Background Image Too Small (Fixed 2026-01-18)**
- **Problem:** gh0stbanner.png displayed too small on mobile
- **Fix:** Changed `background-size: contain` to `85% auto`
- **File:** `css/mobile.css` line 132

**5. Settings Panel X Button Not Visible (Fixed 2026-01-09)**
- **Problem:** Close button cut off by screen edge
- **Fix:** 44px cyan circular button with high z-index
- **CSS:** `.settings-close-x { width: 44px; height: 44px; z-index: 9999; }`

### Current Phone Configuration

**Ollama Models Installed:**
```
qwen:latest           2.3GB   Fast general
qwen2.5-coder:7b      4.7GB   Code generation
mistral:latest        4.4GB   Research
dolphin-phi:latest    1.6GB   Uncensored security
nous-hermes:latest    3.8GB   Uncensored reasoning
```

**Backend Status:**
- Mode: `local` (using Ollama)
- Port: 8010
- Agents: 39 configured
- Cloud available: Yes (toggle option)

---

## Project Overview

PKN Mobile is the Android/Termux deployment of the Divine Node multi-agent AI system. It runs the same backend architecture as the desktop version but with optimized, lighter models for mobile hardware.

**Key Differences from Desktop PKN:**
- Uses 7B models instead of 14B for better mobile performance
- All agents use Ollama (port 11434) - no llama.cpp
- Cloud API integration as fallback option (NOT default)
- Mobile-optimized UI with responsive CSS
- Simplified configuration for Termux environment

## Agent Configuration (Updated 2026-01-18)

**IMPORTANT: Mobile agents use lighter models. Security/Reasoner use UNCENSORED models.**

PKN Mobile uses 9 specialized AI agents:
- **CODER** (qwen2.5-coder:7b) - Code writing, debugging [~10s]
- **REASONER** (nous-hermes:latest) - Planning, logic, analysis [~13s] **UNCENSORED**
- **RESEARCHER** (mistral:latest) - Web research, documentation [~15s]
- **EXECUTOR** (qwen2.5-coder:7b) - System commands, file ops [~10s]
- **GENERAL** (qwen:latest) - Quick Q&A [~1s]
- **SECURITY** (dolphin-phi:latest) - Pentesting, security [~7s] **UNCENSORED**
- **VISION** (llava:latest) - Image/screenshot analysis [~15s]
- **VISION_CLOUD** (Groq) - Optional cloud vision [~2s]
- **CONSULTANT** (Claude API) - Optional cloud reasoning [~3s]

**All agents have access to 13 tool modules:**
code_tools, file_tools, system_tools, web_tools, memory_tools, osint_tools, rag_tools, planning_tools, delegation_tools, chain_tools, sandbox_tools, evaluation_tools, and advanced features.

**For complete agent configuration details, see:**
- `backend/agents/manager.py` - Mobile agent implementation

## Mobile vs Desktop Comparison

| Feature | Desktop PKN | Mobile PKN |
|---------|-------------|------------|
| **Models** | 14B (qwen2.5-coder:14b) | 7B (qwen2.5-coder:7b) |
| **Backend** | Ollama (11434) | Ollama (11434) |
| **Performance** | 15-30s (CODER) | 10s (CODER) |
| **Storage** | ~40GB all models | ~20GB mobile models |
| **UI** | Desktop CSS | Mobile responsive CSS |
| **Memory** | Full memory system | Full memory system (shared) |
| **Tools** | All 13 modules | All 13 modules |

## Directory Structure

```
apps/pkn-mobile/
├── backend/                          # Python Flask backend
│   ├── server.py                     # Flask app initialization
│   ├── routes/                       # API route blueprints
│   ├── agents/                       # Agent orchestration
│   ├── tools/                        # Agent tools (13 modules)
│   └── config/                       # Settings
├── css/                              # Stylesheets
│   ├── main.css                      # Base styles
│   └── mobile.css                    # Mobile responsive overrides
├── js/                               # JavaScript modules
│   ├── debugger.js                   # Divine Debugger module
│   ├── core/                         # Core app logic
│   ├── features/                     # Feature modules
│   └── plugins/                      # Plugin system
├── scripts/
│   ├── termux_menu.sh                # Termux launcher
│   └── deploy-to-phone.sh            # ADB deployment helper
├── pkn.html                          # Main HTML
├── service-worker.js                 # PWA service worker
└── server.py                         # Server entry point
```

## Architecture Deep Dive (Updated 2026-01-17)

### File Size Status

| File | Lines | Status | Notes |
|------|-------|--------|-------|
| `js/core/app.js` | 4,244 | ⚠️ Large | Monolithic, has 141 functions. Contains duplicates of modular files. |
| `css/main.css` | 3,589 | ✅ OK | Well-organized with 19 section headers. Keep as-is. |
| `pkn.html` | ~1,580 | ⚠️ Large | Includes 445 lines of inline scripts. |
| `backend/agents/manager.py` | 1,111 | ⚠️ Large | Core orchestration, refactor carefully. |
| `js/features/files.js` | 795 | ⚠️ Large | File explorer, isolated module. |
| `css/mobile.css` | 398 | ✅ OK | Mobile overrides only. |

### JavaScript Architecture

**Loading Order (from pkn.html):**
1. Sentry (CDN) - Error tracking
2. `js/debugger.js` - Divine Debugger (IIFE)
3. `tools.js` - `window.ParakleonTools`
4. `config.js` - `window.PARAKLEON_CONFIG`
5. `js/core/app.js` - **4,244 lines, 141 functions** (traditional script)
6. `js/features/agent_quality.js` - AgentQualityMonitor
7. ES6 modules via `<script type="module">` - loads last

**Critical Issue:** `app.js` loads as traditional script, defining 80+ global functions. Modular files (`chat.js`, `settings.js`, etc.) exist but may duplicate functions in `app.js`. Changes to either require careful testing.

**Global State Variables:**
```javascript
window.currentChatId       // Active chat session
window.currentProjectId    // Active project
window.appInitialized      // App ready flag
window.ParakleonTools      // OSINT/network tools
window.PARAKLEON_CONFIG    // Configuration
window.openMenuElement     // Menu state tracking
```

### CSS Architecture

**main.css Section Map (3,589 lines):**
| Section | Lines | Content |
|---------|-------|---------|
| RESET & GLOBAL | 1-127 | Variables, themes, scrollbars |
| LAYOUT & CONTAINERS | 128-199 | Grid, flexbox structure |
| SIDEBAR STYLES | 200-478 | Navigation, history items |
| MAIN CONTENT | 479-1007 | Messages, chat area |
| INPUT AREA | 1008-1287 | Textarea, send button |
| MODALS & OVERLAYS | 1288-1638 | Settings, file explorer |
| RESPONSIVE (MOBILE) | 1639-1971 | Breakpoint overrides |
| WELCOME SCREEN | 1972-2167 | Landing page |
| AGENT SWITCHER | 2238-2442 | Quick access panel |
| CODE BLOCKS | 2790-2935 | Syntax highlighting |
| LIGHT MODE | 3008-3277 | Theme variant |
| PLUGINS | 3386-3589 | Plugin system UI |

**mobile.css** (398 lines) - Single `@media (max-width: 768px)` wrapper that overrides main.css for mobile devices. Includes: hidden hoverstrip, arrow send button, swipe gestures.

### HTML Event Handler Coupling

**87 inline event handlers** in pkn.html call functions from `app.js`:
- 67 onclick handlers
- 13 onchange handlers
- 7 range slider handlers

**High-risk functions (called from HTML, defined in app.js):**
- `sendMessage()`, `toggleSettings()`, `showFilesPanel()`, `hideFilesPanel()`
- `selectHeaderAgent()`, `openImageGenerator()`, `toggleDebugger()`
- `createNewProject()`, `saveNewProject()`, `toggleSection()`

### Backend API Endpoints (50+ routes)

**Most Used:**
| Endpoint | Method | Frontend Caller | Purpose |
|----------|--------|-----------------|---------|
| `/api/multi-agent/chat` | POST | app.js, multi_agent_ui.js | Main chat |
| `/api/multi-agent/chat/stream` | POST | multi_agent_ui.js | Streaming chat |
| `/api/models/ollama` | GET | models.js, app.js | List models |
| `/api/files/list` | GET | files.js, app.js | List uploads |
| `/api/osint/*` | POST | osint_ui.js | 11 OSINT tools |

### Refactoring Guidelines

**Safe Changes:**
- CSS within existing sections (main.css is well-organized)
- Adding new modular JS files (don't modify app.js globals)
- Backend route additions (new blueprints)

**Risky Changes:**
- Modifying `app.js` functions (87 HTML handlers depend on them)
- Changing function signatures (breaks onclick calls)
- Splitting CSS files (requires updating all imports)

**Before Refactoring app.js:**
1. Map all onclick handlers to their function targets
2. Identify which modular file duplicates exist
3. Test each function removal individually
4. Keep backward compatibility via `window.functionName = functionName`

## Divine Debugger (Added 2026-01-17)

Mobile debug panel accessible via sidebar toggle.

**Features:**
- **Console tab**: Intercepts console.log/error/warn, displays in panel
- **Analysis tab**: Finds duplicate IDs, undefined functions, missing selectors
- **Security tab**: Protocol check, cookies, localStorage, external scripts audit

**Files:**
- `js/debugger.js` - Main debugger module
- `css/mobile.css` - Mobile styles for debugger panel

**Usage:**
1. Open sidebar (swipe from left)
2. Tap "Debugger" toggle
3. Panel appears at bottom with 3 tabs

**To toggle via code:** `toggleDebugger()`

## Deployment to Phone (via SSH)

**Prerequisites:** SSH running in Termux (`sshd`), ADB connected

```bash
# From PC - establish connections
adb forward tcp:8022 tcp:8022

# Copy files via SSH
scp -r -P 8022 /path/to/pkn-mobile/* localhost:~/pkn-phone/

# Or use the helper script
./scripts/deploy-to-phone.sh
```

**Restart server in Termux:**
```bash
pkill -f server.py
cd ~/pkn-phone && python server.py &
```

**Cache busting:** Increment version in `service-worker.js` or add `?v=timestamp` to URL

## Mobile-Specific Configuration

### Termux Environment

**Installation Location:** `~/pkn-phone/` on Termux
**Port:** 8010 (same as desktop)
**Python:** Termux Python 3.x
**Dependencies:** `requirements.txt` (minimal for mobile)

### Starting PKN Mobile

**Via Termux Menu (Recommended):**
```bash
pkn
# Select: 1) PKN Mobile (Start server + Open browser)
```

**Via Aliases:**
```bash
pkn           # Start server
pkn-ui        # Open browser with cache-busting
pkn-status    # Check server status
pkn-stop      # Stop server
```

**Manual Start:**
```bash
cd ~/pkn-mobile
python backend/server.py &
```

### Mobile UI Features

**Responsive Design (css/mobile.css):**
- Hamburger menu (☰) for sidebar access
- Touch-optimized buttons (44px minimum)
- Arrow-only send button (➤)
- Full-screen modals
- Hidden agent/model selectors (auto-select)
- Fixed bottom input container

**Mobile CSS Media Query:**
```css
@media (max-width: 768px) {
    /* Mobile overrides */
}
```

## Agent Manager Configuration

**File:** `backend/agents/manager.py`

**Key Mobile Optimizations:**
```python
# Mobile uses lighter 7B models
self.agents[AgentType.CODER] = {
    "model": "ollama:qwen2.5-coder:7b",  # Desktop uses :14b
    "endpoint": "http://127.0.0.1:11434",
    "tools_enabled": True,
    "speed": "fast",
    "quality": "good"
}
```

**All agents configured for Ollama:**
- CODER: qwen2.5-coder:7b
- REASONER: qwen2.5-coder:7b (Desktop uses qwen3:14b)
- RESEARCHER: mistral:latest
- EXECUTOR: qwen2.5-coder:7b (Desktop uses deepseek-coder:6.7b)
- GENERAL: qwen:latest (Desktop uses llama3.1-8b-lexi)
- SECURITY: qwen2.5-coder:7b (Desktop uses qwen3-abliterated:4b)
- VISION: llava:latest

## Common Development Tasks

### Testing Agents
```bash
# Test chat endpoint
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "mode": "auto"}'

# Test specific agent
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Write Python hello world", "agent_override": "coder"}'

# Check health
curl http://localhost:8010/health
```

### Debugging

**Server Logs:**
```bash
# View live logs
tail -f ~/pkn-mobile/data/divinenode.log

# Check for errors
grep ERROR ~/pkn-mobile/data/divinenode.log
```

**Check Ollama:**
```bash
curl http://localhost:11434/api/tags
# Should list installed models
```

**Browser Console:**
- Open Chrome on phone
- Navigate to `chrome://inspect`
- View console for JavaScript errors

### Common Issues

**Server won't start:**
```bash
# Kill existing process
pkill -f divinenode_server.py

# Check port availability
lsof -i :8010

# Start fresh
cd ~/pkn-mobile
python backend/server.py
```

**UI looks broken:**
1. Hard refresh: Settings → Clear browsing data → Cached images
2. Open with cache-busting: `http://localhost:8010/?v=$(date +%s)`
3. Check `css/mobile.css` exists

**Agent timeout:**
- Check Ollama is running: `pgrep ollama`
- Check model is loaded: `curl http://localhost:11434/api/tags`
- Try lighter model if memory constrained

**Tools not working:**
- Verify `tools_enabled: True` in `backend/agents/manager.py`
- Check tool imports at top of manager.py
- Test individual tool endpoints

## Performance Considerations

### Model Selection

**7B vs 14B Models:**
- 7B: Faster (8-15s), less memory (~3-4GB), good quality
- 14B: Slower (15-30s), more memory (~6-8GB), better quality
- Mobile uses 7B for battery/memory efficiency

**Storage Requirements:**
- Minimal setup: ~10GB (3-4 models)
- Full setup: ~20GB (all 7 models)
- Desktop comparison: ~40GB (all 14B models)

### Battery Optimization

**Termux Wake Lock:**
```bash
termux-wake-lock  # Prevent sleep during inference
termux-wake-unlock  # Release when done
```

**Background Processing:**
- Server runs in background
- Use `nohup` for persistent sessions
- Monitor battery drain with `termux-battery-status`

## Code Sharing with Desktop PKN

### Shared Components

**Memory System:**
- Conversation persistence
- Session management
- Global memory
- Project memory

**Tool Modules:**
- All 13 tool modules identical between desktop/mobile
- Same API interfaces
- Same error handling

**Frontend Components:**
- Base CSS structure
- Core JavaScript modules
- UI components (modals, panels)

**Mobile Overrides:**
- `css/mobile.css` - Responsive overrides
- `backend/agents/manager.py` - Lighter models
- `scripts/termux_menu.sh` - Termux-specific launcher

## Deployment

### Phone Setup (Termux)

1. **Install Termux** from F-Droid
2. **Update packages:**
   ```bash
   pkg update && pkg upgrade
   ```
3. **Install dependencies:**
   ```bash
   pkg install python git openssh
   pip install flask flask-cors requests
   ```
4. **Install Ollama:**
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ollama serve &
   ```
5. **Pull models:**
   ```bash
   ollama pull qwen2.5-coder:7b
   ollama pull qwen:latest
   ollama pull mistral:latest
   ollama pull llava:latest
   ```
6. **Clone/deploy PKN:**
   ```bash
   cd ~
   # Deploy via SSH or git clone
   ```
7. **Start server:**
   ```bash
   cd ~/pkn-mobile
   python backend/server.py &
   ```

### SSH Access (Optional)

**Enable SSH in Termux:**
```bash
pkg install openssh
sshd
# Get username: whoami
# Get IP: ifconfig
```

**Connect from PC:**
```bash
ssh u0_a322@192.168.x.x -p 8022
```

## Migration from Desktop PKN

**Differences to Consider:**
1. **Model sizes:** Change :14b to :7b in agent configs
2. **Ollama only:** Remove llama.cpp references
3. **Mobile CSS:** Add responsive overrides
4. **Termux paths:** Adjust file paths for Termux
5. **Memory limits:** Reduce context windows if needed

## Testing Strategy

### Unit Tests
Same as desktop PKN - test agents, tools, routes

### Mobile-Specific Tests
- Touch interactions
- Responsive layout breakpoints
- Battery consumption
- Memory usage under load
- Network interruption handling

### Performance Benchmarks
- Agent response times
- Memory footprint per model
- Storage usage
- Battery drain rate

## Additional Resources

- **Desktop PKN:** `/home/gh0st/dvn/divine-workspace/apps/pkn/`
- **Agent Configuration:** `docs/AGENT_CONFIGURATION.md` (desktop version)
- **Architecture:** `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md`
- **Mobile UI Fixes:** `docs/mobile_ui_fixes.md`

---

**Last Updated:** 2026-01-18
**Version:** 2.1 (Local-First with Uncensored Models)
