# PKN Frontend Modularization Plan
**Date**: 2026-01-11
**Target**: Split app.js (4,217 lines, 152KB) into modular structure

## Current State

### File Analysis
- **Total Size**: 152KB, 4,217 lines
- **Current Structure**: 4 main sections
- **Problem**: 88% of code (3,758 lines) in one "Send Message Handler" section
- **Status**: Violates 200-line file size limit by 21x

### Section Breakdown

| Section | Lines | Functions | Status |
|---------|-------|-----------|--------|
| Utility Functions | 46 | 1 | ✅ Small |
| Error Handling | 271 | 3 | ⚠️ Moderate |
| Send Message Handler | 3,758 | 171 | ❌ MASSIVE |
| Application Init | 136 | 2 | ✅ Small |

## Target Architecture

```
frontend/
├── js/
│   ├── core/
│   │   ├── app.js                    # Main initialization only (≤200 lines)
│   │   ├── init.js                   # App initialization logic (≤200 lines)
│   │   └── config.js                 # Configuration loading (≤200 lines)
│   ├── ui/
│   │   ├── chat/
│   │   │   ├── messages.js           # Message rendering & management
│   │   │   ├── input.js              # Message input handling
│   │   │   ├── history.js            # Chat history
│   │   │   ├── search.js             # Chat search functionality
│   │   │   └── welcome.js            # Welcome screen
│   │   ├── modals/
│   │   │   ├── settings.js           # Settings modal
│   │   │   ├── models.js             # AI models manager
│   │   │   ├── files.js              # File manager modal
│   │   │   └── shortcuts.js          # Keyboard shortcuts modal
│   │   ├── sidebar.js                # Sidebar navigation
│   │   ├── toolbar.js                # Chat toolbar
│   │   └── theme.js                  # Theme management
│   ├── features/
│   │   ├── agent-selector.js         # Agent selection UI
│   │   ├── code-highlight.js         # Code syntax highlighting
│   │   ├── file-upload.js            # File upload handling
│   │   ├── model-manager.js          # Model management
│   │   └── projects.js               # Project management (already exists)
│   ├── api/
│   │   ├── client.js                 # Base API client
│   │   ├── chat.js                   # Chat API calls
│   │   ├── files.js                  # File API calls
│   │   └── models.js                 # Model API calls
│   ├── utils/
│   │   ├── toast.js                  # Toast notifications
│   │   ├── errors.js                 # Error handling
│   │   ├── storage.js                # LocalStorage wrapper
│   │   ├── dom.js                    # DOM utilities
│   │   └── format.js                 # Text formatting utilities
│   └── plugins/                      # Plugin system (already exists)
```

## Modularization Strategy

### Phase 1: Extract Utilities (Low Risk)
**Goal**: Remove simple, self-contained functions first

Files to create:
1. `utils/toast.js` - Toast notification system (1 function, ~30 lines)
2. `utils/errors.js` - Error handling system (3 functions, ~270 lines)
3. `utils/format.js` - Text formatting utilities

**Risk**: ✅ Low - These have minimal dependencies

### Phase 2: Extract UI Components (Medium Risk)
**Goal**: Split UI-related functionality

Files to create:
1. `ui/chat/welcome.js` - Welcome screen logic
2. `ui/chat/search.js` - Chat search functionality
3. `ui/modals/shortcuts.js` - Keyboard shortcuts modal
4. `features/code-highlight.js` - Code syntax highlighting

**Risk**: ⚠️ Medium - May have cross-dependencies

### Phase 3: Extract Message Handling (High Risk)
**Goal**: Break down the massive "Send Message Handler" section

Files to create:
1. `ui/chat/messages.js` - Message CRUD operations
2. `ui/chat/input.js` - Input handling and sending
3. `ui/chat/history.js` - Chat history management
4. `api/chat.js` - Chat API integration

**Risk**: ⚠️ High - Core functionality, extensive testing needed

### Phase 4: Extract Modal Systems (Medium Risk)
**Goal**: Modularize settings and model management

Files to create:
1. `ui/modals/settings.js` - Settings panel
2. `ui/modals/models.js` - AI models manager
3. `ui/modals/files.js` - File manager
4. `features/model-manager.js` - Model management logic

**Risk**: ⚠️ Medium - Complex state management

### Phase 5: Extract Initialization (Low Risk)
**Goal**: Clean up app startup

Files to create:
1. `core/init.js` - Application initialization
2. `core/config.js` - Configuration loading

**Risk**: ✅ Low - Run once at startup

## Extraction Template

Each extracted module should follow this pattern:

```javascript
// ui/chat/welcome.js

/**
 * Welcome Screen Module
 * Handles showing/hiding welcome screen
 */

export function showWelcomeScreen() {
    const welcome = document.getElementById('welcomeScreen');
    const messages = document.getElementById('messagesContainer');

    if (!messages || messages.children.length === 0) {
        if (welcome) {
            welcome.style.display = 'flex';
            console.log('Welcome screen shown');
        }
    } else {
        hideWelcomeScreen();
    }
}

export function hideWelcomeScreen() {
    const welcome = document.getElementById('welcomeScreen');
    if (welcome) {
        welcome.remove();
        console.log('Welcome screen removed from DOM');
    }
}
```

## Migration Steps

### Step 1: Create Module Structure
```bash
mkdir -p frontend/js/utils
mkdir -p frontend/js/ui/chat
mkdir -p frontend/js/ui/modals
mkdir -p frontend/js/api
mkdir -p frontend/js/features
```

### Step 2: Extract Function Groups
For each module:
1. Create new file with exports
2. Copy functions from app.js
3. Add imports/exports
4. Test in isolation
5. Update app.js to import

### Step 3: Update HTML
Modify `pkn.html` to load modules:

```html
<!-- Load order matters! -->
<script type="module">
    // Utilities first
    import { showToast } from './js/utils/toast.js';
    import { formatError, showFormattedError } from './js/utils/errors.js';

    // UI components
    import { showWelcomeScreen, hideWelcomeScreen } from './js/ui/chat/welcome.js';
    import { sendMessage, addMessage } from './js/ui/chat/messages.js';

    // Make functions globally available (for onclick handlers)
    window.showToast = showToast;
    window.sendMessage = sendMessage;
    // ... etc

    // Initialize app
    import('./js/core/app.js').then(module => {
        module.init();
    });
</script>
```

### Step 4: Testing Checklist
After each extraction, verify:
- [ ] Page loads without errors
- [ ] Chat input/output works
- [ ] Modals open/close
- [ ] File upload works
- [ ] Settings persist
- [ ] Keyboard shortcuts work
- [ ] Agent selector functions
- [ ] Code highlighting works

## Dependencies to Resolve

### Global Variables Used Across Modules
- `messagesContainer` - Chat messages div
- `messageInput` - Message input textarea
- `currentChatId` - Active chat session
- `ACTIVE_MODEL` - Currently selected model
- `ACTIVE_BASE_URL` - API endpoint URL

**Solution**: Create a central state management module

```javascript
// core/state.js

export const state = {
    currentChatId: null,
    currentProjectId: null,
    isWaiting: false,
    model: null,
    baseUrl: null,
    // ... etc
};

export function setState(updates) {
    Object.assign(state, updates);
}
```

## Conversion Strategy: Global → Module

### Option 1: ES6 Modules (Recommended)
- Use `export`/`import`
- Clean, modern approach
- Requires updating HTML to use `<script type="module">`

### Option 2: Keep Global Functions
- Extract to separate files
- Load with `<script src="">`
- Functions remain in global scope
- Easier migration, but less clean

**Recommendation**: Use ES6 modules for new code, maintain compatibility for existing onclick handlers via window assignment.

## File Size Compliance

### Target Metrics
- ✅ Each file ≤200 lines
- ✅ Single responsibility per module
- ✅ Clear import/export boundaries

### Current Violations
| File | Lines | Target Split |
|------|-------|--------------|
| app.js | 4,217 | → 25+ modules |
| Multi-agent section | 3,758 | → 20+ modules |

## Risk Mitigation

### Backup Strategy
1. Create `app.js.backup` before any changes
2. Git commit after each successful extraction
3. Keep modular and monolithic versions running in parallel during migration

### Testing Strategy
1. **Unit Tests**: Test each module in isolation
2. **Integration Tests**: Test module interactions
3. **E2E Tests**: Full user workflows
4. **Manual Testing**: Real browser usage

### Rollback Plan
If issues arise:
```bash
# Revert to monolithic version
cp frontend/js/core/app.js.backup frontend/js/core/app.js
git checkout frontend/pkn.html
```

## Success Criteria

✅ **Code Quality**
- All files ≤200 lines
- Clear module boundaries
- Documented exports

✅ **Functionality**
- All features working
- No regressions
- Same performance

✅ **Maintainability**
- Easy to find code
- Easy to add features
- Easy to fix bugs

## Estimated Timeline

| Phase | Tasks | Est. Time | Priority |
|-------|-------|-----------|----------|
| 1. Utilities | 3 files | 1-2 hours | High |
| 2. UI Components | 4 files | 2-3 hours | High |
| 3. Message Handling | 4 files | 4-6 hours | Critical |
| 4. Modal Systems | 4 files | 3-4 hours | Medium |
| 5. Initialization | 2 files | 1 hour | Low |
| **Total** | **17+ files** | **11-16 hours** | - |

## Next Actions

1. ✅ Create this plan document
2. [ ] Get user approval for modularization approach
3. [ ] Backup current app.js
4. [ ] Start Phase 1 (Utilities extraction)
5. [ ] Test Phase 1 in browser
6. [ ] Proceed to Phase 2

---
**Created by**: Claude Code (Opus 4.5)
**Session**: 2026-01-11
**Based on**: Backend modularization success (2,486 lines → 17 files)
