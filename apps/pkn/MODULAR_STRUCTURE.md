# Modular Code Structure

## Overview
The application has been refactored from a single 2,764-line `app.js` file into modular ES6 modules for better maintainability, readability, and debugging.

## Module Organization

### `/js/` Directory Structure

```
js/
├── utils.js         - Shared utilities (toast, escapeHtml, backend check)
├── storage.js       - LocalStorage operations (chats, projects, models, settings)
├── chat.js          - Chat messaging and conversation management
├── models.js        - AI model selection and management
├── projects.js      - Project CRUD operations
├── files.js         - File upload and management
├── images.js        - Image generation and gallery
├── settings.js      - Settings UI and customization
└── main.js          - Application initialization and event handlers
```

## Module Details

### 1. **utils.js** (156 lines)
**Purpose:** Shared utility functions used across modules

**Exports:**
- `showToast(message, duration, type)` - Toast notifications
- `escapeHtml(str)` - XSS prevention
- `toggleSection(sectionId)` - Sidebar section toggling
- `closeHistoryMenu()` - Close menu helper
- `checkBackend(showToastOnFail)` - Backend availability check
- `showBackendBanner(htmlMessage)` - Show backend status banner
- `hideBackendBanner()` - Hide backend banner

### 2. **storage.js** (142 lines)
**Purpose:** All localStorage operations and data persistence

**Exports:**
- Storage keys: `STORAGE_KEY`, `PROJECTS_KEY`, `MODELS_KEY`, `SETTINGS_KEY`
- `loadChatsFromStorage()` / `saveChatsToStorage(chats)`
- `loadProjectsFromStorage()` / `saveProjectsFromStorage(projects)`
- `loadModelsFromStorage()` / `saveModelsToStorage(models)`
- `loadSettings()` / `saveSettings(settings)`

### 3. **chat.js** (399 lines)
**Purpose:** Chat messaging functionality

**Exports:**
- `sendMessage()` - Send user message to AI
- `addMessage(text, sender, saveToChat, attachments, id, model, timestamp)` - Add message to DOM
- `appendMessageToCurrentChat(sender, text, attachments, messageId, model)` - Persist message
- `renderHistory()` - Render chat history sidebar
- `getCurrentChat(chats)` - Get active chat

**Features:**
- Request timeout handling (30s)
- Loading states (disabled input during request)
- Specific error messages (502, 500, 404, timeout, network)
- Toast notifications for errors

### 4. **models.js** (245 lines)
**Purpose:** AI model management

**Exports:**
- `initModelSelector()` - Initialize model dropdown
- `refreshOllamaModels()` - Fetch models from Ollama
- `refreshLlamaCppModels()` - Fetch models from llama.cpp
- `updateModelSelectDropdown()` - Update model selection UI
- `renderModelsList()` - Render models in settings

**Supported Providers:**
- Local: Ollama, llama.cpp
- Cloud: OpenAI, Groq, HuggingFace, Together

### 5. **projects.js** (417 lines)
**Purpose:** Project management (workspaces)

**Exports:**
- `renderProjects()` - Render projects sidebar
- `saveNewProject()` - Create new project
- `loadProjectFromData(projectId, chatId)` - Load project data
- `switchToGlobalChat()` - Exit project mode
- Project CRUD operations

**Features:**
- Multiple projects with separate chats
- System prompts per project
- Project rename/delete functionality

### 6. **files.js** (136 lines)
**Purpose:** File upload and management

**Exports:**
- `showFilesPanel()` / `hideFilesPanel()` - Toggle files panel
- `initFilesPanelRefs()` - Initialize DOM references
- `deleteGlobalFile(fileId)` - Delete uploaded file

**Features:**
- File upload to server
- File listing with size display
- Image/document icons
- Delete confirmation

### 7. **images.js** (422 lines)
**Purpose:** AI image generation

**Exports:**
- `generateImage()` - Generate image from prompt
- `renderImages()` - Render images sidebar
- `renderImagesGallery()` - Render image modal gallery
- `saveGeneratedImages(imageAttachments, prompt)` - Save to gallery
- `openImageGenerator()` / `closeImageGenerator()` - Toggle image modal

**Features:**
- Pollinations.ai integration (free)
- Local image storage
- Image gallery with preview
- 60s timeout with error handling

### 8. **settings.js** (355 lines)
**Purpose:** Application settings and customization

**Exports:**
- `toggleSettings()` - Open/close settings modal
- `applyAppearanceSettings()` - Apply font/color customization
- Settings persistence

**Settings:**
- Font family, size, weight
- Color scheme customization
- Timestamp display
- Temperature and max tokens

### 9. **main.js** (290 lines)
**Purpose:** Application initialization and event binding

**Exports:**
- DOM element references (messagesContainer, sendBtn, etc.)
- Event handlers setup
- `init()` - Main initialization function
- `setupSidebarHover()` - Sidebar interaction logic
- `networkAction()` - Network tools menu

**Responsibilities:**
- Wire up all event handlers
- Initialize all modules
- Setup keyboard shortcuts
- Sidebar hover/touch behavior

## Loading Order

The modules are loaded in `pkn.html` in this order:

```html
<!-- Configuration -->
<script src="config.js"></script>
<script src="config.local.js"></script>

<!-- ES6 Modules -->
<script type="module" src="js/utils.js"></script>
<script type="module" src="js/storage.js"></script>
<script type="module" src="js/chat.js"></script>
<script type="module" src="js/models.js"></script>
<script type="module" src="js/projects.js"></script>
<script type="module" src="js/files.js"></script>
<script type="module" src="js/images.js"></script>
<script type="module" src="js/settings.js"></script>
<script type="module" src="js/main.js"></script>
```

## Benefits of Modularization

### Before (Single File)
- ❌ 2,764 lines in one file
- ❌ Difficult to navigate
- ❌ Hard to debug
- ❌ Merge conflicts likely
- ❌ No clear separation of concerns

### After (Modular)
- ✅ 9 focused modules (avg ~250 lines each)
- ✅ Clear separation of concerns
- ✅ Easy to locate and fix bugs
- ✅ Better code reusability
- ✅ JSDoc comments on all exports
- ✅ ES6 import/export syntax
- ✅ Easier for multiple developers

## Backward Compatibility

Critical functions are exposed globally for inline HTML handlers:

```javascript
window.toggleSection = toggleSection;
window.sendMessage = sendMessage;
window.networkAction = networkAction;
window.showToast = showToast;
window.deleteGlobalFile = deleteGlobalFile;
```

## Migration Notes

**Old code (app.js):**
```javascript
// All 2,764 lines in one file
function sendMessage() { ... }
function renderProjects() { ... }
// ... 100+ more functions
```

**New code (modular):**
```javascript
// chat.js
export function sendMessage() { ... }

// projects.js
export function renderProjects() { ... }

// main.js
import { sendMessage } from './chat.js';
import { renderProjects } from './projects.js';
```

## Debugging Tips

1. **Module not found errors:** Check import paths in browser console
2. **Function undefined:** Check if exported and imported correctly
3. **Circular dependencies:** Use dynamic imports or window globals
4. **Inline handlers:** Ensure functions are exposed on window object

## Development Workflow

### Adding a New Feature

1. Identify which module it belongs to
2. Add function to appropriate module
3. Export the function
4. Import where needed
5. Update MODULAR_STRUCTURE.md (this file)

### Example: Adding a new chat feature

```javascript
// 1. Add to js/chat.js
export function newChatFeature() {
    // implementation
}

// 2. Import in js/main.js (if needed)
import { sendMessage, newChatFeature } from './chat.js';

// 3. Use in initialization or event handler
function init() {
    // ... existing code
    newChatFeature();
}
```

## File Sizes

```
utils.js     - 4.5 KB  (156 lines)
storage.js   - 3.7 KB  (142 lines)
chat.js      - 16 KB   (399 lines)
models.js    - 8.9 KB  (245 lines)
projects.js  - 13 KB   (417 lines)
files.js     - 4.1 KB  (136 lines)
images.js    - 14 KB   (422 lines)
settings.js  - 13 KB   (355 lines)
main.js      - 8.8 KB  (290 lines)
```

**Total:** ~86 KB modular code vs 92 KB monolithic

## Future Improvements

- [ ] Add unit tests for each module
- [ ] Use TypeScript for type safety
- [ ] Implement lazy loading for non-critical modules
- [ ] Add module bundling (webpack/rollup) for production
- [ ] Create API documentation with JSDoc
- [ ] Add linting (ESLint) for code quality
