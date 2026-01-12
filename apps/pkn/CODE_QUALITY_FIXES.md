# PKN Code Quality Fix List

Generated: 2026-01-11
Tools: `debugger-extension/run_all_checks.py`

## Priority Legend
- 🔴 **P0 - Critical**: Likely causing bugs NOW, fix immediately
- 🟠 **P1 - High**: Will cause bugs, fix this sprint
- 🟡 **P2 - Medium**: Technical debt, fix when touching file
- 🟢 **P3 - Low**: Nice to have, backlog

---

## Scope Mismatches (18 total)

### 🔴 P0 - Critical (Fix First)

| Variable | Issue | Files | Fix Strategy |
|----------|-------|-------|--------------|
| `openMenuElement` | Local in app.js, window.* in 4 files | app.js, main.js, utils.js, projects.js | Standardize to `window.openMenuElement` everywhere |
| `currentChatId` | Declared local, used as window.* | chat.js, app.js, projects.js, settings.js, images.js | Export from chat.js, import elsewhere |
| `currentProjectId` | Declared local, used as window.* | chat.js, app.js, projects.js, settings.js, images.js | Export from chat.js, import elsewhere |
| `multiAgentUI` | Local declaration, window.* usage in same file | multi_agent_ui.js, app.js | Standardize to `window.multiAgentUI` |

### 🟠 P1 - High

| Variable | Issue | Files | Fix Strategy |
|----------|-------|-------|--------------|
| `agentQualityMonitor` | Mixed scope | agent_quality.js, multi_agent_ui.js | Export/import pattern |
| `ACTIVE_MODEL` | Declared local, window.* in models.js | chat.js, app.js, models.js | Centralize in models.js |
| `ACTIVE_PROVIDER` | Declared local, window.* in models.js | chat.js, app.js, models.js | Centralize in models.js |
| `capacitorBackend` | Mixed in same file | capacitor-backend.js | Pick one, be consistent |

### 🟡 P2 - Medium

| Variable | Issue | Files | Fix Strategy |
|----------|-------|-------|--------------|
| `ACTIVE_API_KEY` | Cross-file mismatch | app.js, models.js | Centralize config |
| `ACTIVE_BASE_URL` | Cross-file mismatch | app.js, models.js | Centralize config |
| `ACTIVE_TEMPERATURE` | Cross-file mismatch | app.js, settings.js | Centralize config |
| `ACTIVE_MAX_TOKENS` | Cross-file mismatch | app.js, settings.js | Centralize config |
| `ACTIVE_TOP_P` | Cross-file mismatch | app.js, settings.js | Centralize config |
| `ACTIVE_FREQUENCY_PENALTY` | Cross-file mismatch | app.js, settings.js | Centralize config |
| `ACTIVE_PRESENCE_PENALTY` | Cross-file mismatch | app.js, settings.js | Centralize config |

### 🟢 P3 - Low (Intentional patterns)

| Variable | Issue | Notes |
|----------|-------|-------|
| `OSINTTools` | Local class, window.* export | Intentional - class exported to window for HTML onclick |
| `pluginManager` | Local singleton, window.* export | Intentional - exposed for debugging |
| `SpeechRecognition` | Browser API polyfill | Intentional - checking for browser support |

---

## Duplicate Functions (393 total)

### Exclude from analysis (not bugs):
- `archive/` - Old code backups
- `android/` - Capacitor build output
- `www/` - Capacitor build output
- `llama.cpp/` - Submodule
- `.venv/` - Python virtual env

### 🔴 P0 - Critical Duplicates

| Function | Locations | Fix |
|----------|-----------|-----|
| `sendMessage()` | chat.js, app.js, android copies | Keep chat.js, remove from app.js |
| `addMessage()` | chat.js, app.js, android copies | Keep chat.js, remove from app.js |
| `showToast()` | utils.js, app.js, multiple plugins | Keep utils.js, import elsewhere |

### 🟠 P1 - Backend Duplicates

| Function | Locations | Fix |
|----------|-----------|-----|
| `_load_json()` | memory_tools.py, local_parakleon_agent.py | Create shared utility |
| `_save_json()` | memory_tools.py, local_parakleon_agent.py | Create shared utility |
| `_execute_step()` | chain_tools.py, planning_tools.py | Create shared base class |

---

## Missing Selectors (97 total)

### 🟠 P1 - Settings Panel IDs

These are referenced but may not exist:
- `#agentNickname`
- `#apiEndpoint`
- `#anthropicKey`
- `#settingsModal`

**Action**: Verify these exist in pkn.html or remove dead code.

### 🟡 P2 - Plugin Selectors

May be dynamically created:
- `.context-suggestion-toast`
- `.osint-tab`
- `.voice-status`

**Action**: Document that these are created dynamically.

---

## Fix Order

1. **Today**: P0 scope mismatches (4 variables)
2. **This week**: P1 scope mismatches + P0 duplicates
3. **Next week**: P2 items + missing selectors audit
4. **Backlog**: P3 items (document as intentional)

---

## Running Checks

```bash
# Full check
just code-quality

# Individual analyzers
python3 debugger-extension/analyze_scope_mismatches.py frontend/
python3 debugger-extension/analyze_duplicate_functions.py .
python3 debugger-extension/analyze_missing_selectors.py frontend/
```

## After Fixing

Re-run `just code-quality` - target is 0 HIGH severity issues.
