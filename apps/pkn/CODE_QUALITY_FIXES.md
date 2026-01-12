# PKN Code Quality Fix List

Generated: 2026-01-11
Last Updated: 2026-01-11
Tools: `debugger-extension/run_all_checks.py`

## Current Metrics

| Category | Before | After | Reduction |
|----------|--------|-------|-----------|
| Duplicate Functions | 393 | 115 | 71% ✓ |
| Scope Mismatches | 86 | 16 | 81% ✓ |
| Missing Selectors | 97 | 88 | 9% (mostly dynamic) |

## Priority Legend
- 🔴 **P0 - Critical**: Likely causing bugs NOW, fix immediately
- 🟠 **P1 - High**: Will cause bugs, fix this sprint
- 🟡 **P2 - Medium**: Technical debt, fix when touching file
- 🟢 **P3 - Low**: Nice to have, backlog
- ✅ **DONE**: Fixed

---

## Scope Mismatches (16 remaining, down from 86)

### ✅ P0 - Critical (COMPLETED 2026-01-11)

| Variable | Status | Fix Applied |
|----------|--------|-------------|
| `openMenuElement` | ✅ DONE | Standardized to `window.openMenuElement` in app.js |
| `currentChatId` | ✅ DONE | Removed local declaration from app.js/projects.js, use window.* |
| `currentProjectId` | ✅ DONE | Removed local declaration from app.js/projects.js, use window.* |
| `ACTIVE_MODEL` | ✅ DONE | Changed to `window.ACTIVE_MODEL` in app.js |
| `ACTIVE_PROVIDER` | ✅ DONE | Changed to `window.ACTIVE_PROVIDER` in app.js |
| `ACTIVE_API_KEY` | ✅ DONE | Changed to `window.ACTIVE_API_KEY` in app.js |
| `ACTIVE_BASE_URL` | ✅ DONE | Changed to `window.ACTIVE_BASE_URL` in app.js |
| `ACTIVE_TEMPERATURE` | ✅ DONE | Changed to `window.ACTIVE_TEMPERATURE` in app.js |
| `ACTIVE_MAX_TOKENS` | ✅ DONE | Changed to `window.ACTIVE_MAX_TOKENS` in app.js |
| `ACTIVE_TOP_P` | ✅ DONE | Changed to `window.ACTIVE_TOP_P` in app.js |
| `ACTIVE_FREQUENCY_PENALTY` | ✅ DONE | Changed to `window.ACTIVE_FREQUENCY_PENALTY` in app.js |
| `ACTIVE_PRESENCE_PENALTY` | ✅ DONE | Changed to `window.ACTIVE_PRESENCE_PENALTY` in app.js |

### 🟠 P1 - High (Remaining)

| Variable | Issue | Files | Fix Strategy |
|----------|-------|-------|--------------|
| `multiAgentUI` | Local declaration, window.* usage in same file | multi_agent_ui.js, app.js | Standardize to `window.multiAgentUI` |
| `agentQualityMonitor` | Mixed scope | agent_quality.js, multi_agent_ui.js | Export/import pattern |
| `capacitorBackend` | Mixed in same file | capacitor-backend.js | Pick one, be consistent |

### 🟢 P3 - Low (Intentional patterns)

| Variable | Issue | Notes |
|----------|-------|-------|
| `OSINTTools` | Local class, window.* export | Intentional - class exported to window for HTML onclick |
| `pluginManager` | Local singleton, window.* export | Intentional - exposed for debugging |
| `SpeechRecognition` | Browser API polyfill | Intentional - checking for browser support |

---

## Duplicate Functions (115 remaining, down from 393)

### ✅ Major Cleanup Completed (2026-01-11)

**Removed duplicate plugins directory**: `apps/pkn/plugins/` was an exact duplicate of `frontend/js/plugins/`. Deleted 10 plugins, 21 files, 6,318 lines.

### Exclude from analysis (not bugs):
- `archive/` - Old code backups
- `android/` - Capacitor build output
- `www/` - Capacitor build output
- `llama.cpp/` - Submodule
- `.venv/` - Python virtual env
- `apps/pkn/plugins/` - ✅ REMOVED (was duplicate)

### 🟡 P2 - Remaining Duplicates (Legacy app.js overlap)

Most remaining duplicates are due to `app.js` (legacy monolithic file) duplicating functions that also exist in modular `js/*.js` files. These are low priority because `app.js` is being phased out.

| Function | Locations | Status |
|----------|-----------|--------|
| `sendMessage()` | chat.js, app.js | Legacy overlap, app.js being deprecated |
| `addMessage()` | chat.js, app.js | Legacy overlap, app.js being deprecated |
| `showToast()` | utils.js, app.js | Legacy overlap, import from utils.js |

### 🟢 P3 - Backend Duplicates (Low Priority)

| Function | Locations | Fix Strategy |
|----------|-----------|--------------|
| `_load_json()` | memory_tools.py, local_parakleon_agent.py | Create shared utility when refactoring |
| `_save_json()` | memory_tools.py, local_parakleon_agent.py | Create shared utility when refactoring |

---

## Missing Selectors (88 remaining)

### ✅ Analysis Complete (2026-01-11)

**Finding**: Most "missing" selectors are **dynamically created** at runtime by JavaScript. They are NOT bugs.

### Dynamic Element Creation Sources:

| Selector Pattern | Created By | Status |
|------------------|------------|--------|
| `#agent-card-*` | multi_agent_ui.js | ✅ Dynamic - not a bug |
| `.thinking-dots` | chat.js | ✅ Dynamic - not a bug |
| `.message-*` | chat.js | ✅ Dynamic - not a bug |
| `.osint-*` | plugins/osint_tools.js | ✅ Dynamic - not a bug |
| `.tracking-*` | plugins/tracking_pixels.js | ✅ Dynamic - not a bug |
| `.context-suggestion-*` | plugins/context_suggestions.js | ✅ Dynamic - not a bug |
| `.voice-*` | plugins/voice_input.js | ✅ Dynamic - not a bug |

### 🟡 P2 - Verify These Exist

Small number of selectors that should be in HTML/CSS but might be missing:

| Selector | File | Action |
|----------|------|--------|
| `#agentNickname` | settings.js | Verify in pkn.html |
| `#settingsModal` | settings.js | Verify in pkn.html |

---

## Progress Summary

### ✅ Completed (2026-01-11)
1. P0 scope mismatches - 12 variables fixed
2. Duplicate plugins directory removed
3. ACTIVE_* config variables standardized to window.*
4. window.window.* double-prefix bug fixed
5. Missing selectors analyzed - mostly dynamic elements

### 🔜 Remaining Work
1. P1 scope mismatches (3 variables)
2. Legacy app.js cleanup (gradual deprecation)
3. Backend utility consolidation (when refactoring)

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
