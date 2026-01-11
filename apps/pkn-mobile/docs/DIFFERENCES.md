# Mobile PKN vs Desktop PKN

## Overview

PKN Mobile is a **simplified version** of the desktop PKN designed for mobile deployment on Android devices using Termux. It prioritizes:
- Minimal resource usage (no GPU, no large models)
- Cloud-based LLM (OpenAI API instead of local llama.cpp)
- Simplified UI optimized for touch
- Shared code where possible (memory system, utilities)

## Backend Differences

| Feature | Desktop PKN | Mobile PKN |
|---------|-------------|------------|
| **LLM Backend** | Local llama.cpp (GPU-accelerated) | OpenAI API (cloud) |
| **Multi-Agent System** | 6 specialized agents | Single general agent |
| **Image Generation** | Local Stable Diffusion | Disabled |
| **OSINT Tools** | Full suite (phone lookup, IP, domain) | Disabled |
| **Tool Execution** | Full bash/Python tools | Disabled |
| **Memory System** | ✅ Shared (symlink) | ✅ Shared (symlink) |
| **API Routes** | 16 blueprints | 2 blueprints (chat, health) |
| **Dependencies** | Heavy (torch, transformers, llama.cpp) | Minimal (Flask, requests) |
| **Port** | 8010 | 8010 (same) |

## Frontend Differences

| Feature | Desktop PKN | Mobile PKN |
|---------|-------------|------------|
| **CSS** | External CSS files (7 files) | Inline CSS in HTML |
| **JavaScript** | Modular ES6 (20+ files) | Minimal inline JS |
| **UI Components** | Full (sidebar, modals, file manager) | Simplified (chat only) |
| **Chat Interface** | Rich markdown, code blocks, images | Plain text |
| **Agent Selector** | Multi-agent FAB | Disabled |
| **Model Picker** | Dropdown with local models | Disabled |
| **Settings Panel** | Full config UI | Disabled |
| **File Upload** | Drag & drop, file browser | Disabled |
| **Image Gallery** | Grid view with filters | Disabled |
| **Theme Switcher** | 3 themes (dark, cyberpunk, light) | Dark only |
| **Touch Targets** | 18px (desktop) | 44px (mobile) |

## Shared Code (Symlinks)

The following directories are **shared** via symlinks to maximize code reuse:

### Backend
- ✅ **memory/** - Conversation memory and code context (100% shared)
  - `conversation_memory.py`
  - `code_context.py`
  - `__init__.py`

### Frontend
- ✅ **js/core/** - Core JavaScript modules (shared)
  - Event bus
  - App initialization
- ✅ **js/utils/** - Utility functions (shared)
  - Storage helpers
  - Formatters
  - Event handlers
- ✅ **js/api/** - API client (shared)
  - HTTP client
  - Request/response handling

## Mobile-Specific Code

### Backend
- `backend/server.py` - Simplified Flask app (no static file serving complexity)
- `backend/routes/chat.py` - OpenAI API integration
- `backend/routes/health.py` - Health check endpoint
- `backend/api/openai_client.py` - OpenAI API wrapper
- `backend/config/settings.py` - Mobile-specific config

### Frontend
- `frontend/pkn.html` - Inline CSS, minimal JS (better caching on mobile browsers)
- `frontend/mobile/css/mobile.css` - Mobile-specific overrides (if needed)
- `frontend/mobile/js/mobile-ui.js` - Touch gesture handlers (if needed)

## Resource Requirements

| Resource | Desktop PKN | Mobile PKN |
|----------|-------------|------------|
| **RAM** | 8GB+ (llama.cpp + models) | 512MB (Flask only) |
| **Storage** | 20GB+ (models, cache) | <100MB (code only) |
| **GPU** | Recommended (Vulkan/CUDA) | Not required |
| **CPU** | 4+ cores | 2+ cores |
| **Network** | Optional (local LLM) | Required (OpenAI API) |

## Performance Comparison

| Operation | Desktop PKN | Mobile PKN |
|-----------|-------------|------------|
| **Cold Start** | ~30s (load models) | ~2s (Flask only) |
| **First Response** | ~2-5s (local inference) | ~1-3s (API latency) |
| **Streaming** | ✅ Fast (local) | ✅ Fast (API streaming) |
| **Offline** | ✅ Full functionality | ❌ Requires network |

## Cost Comparison

| Aspect | Desktop PKN | Mobile PKN |
|--------|-------------|------------|
| **Hardware** | High (GPU recommended) | Low (any Android phone) |
| **Electricity** | ~$2-5/month (GPU usage) | <$1/month (phone charging) |
| **API Costs** | $0 (local) | $0.01-0.10/session (OpenAI) |
| **Total Monthly** | $2-5 | $1-10 (depending on usage) |

## Feature Parity Roadmap

**Currently Missing in Mobile:**
1. ❌ Multi-agent system (coder, reasoner, researcher, etc.)
2. ❌ Image generation (Stable Diffusion)
3. ❌ OSINT tools (phone lookup, IP check, domain info)
4. ❌ Tool execution (bash, Python scripts)
5. ❌ File upload/management
6. ❌ Rich markdown rendering
7. ❌ Code syntax highlighting
8. ❌ Model switching UI

**Could Be Added Later:**
- Limited multi-agent (if OpenAI supports tool calling well)
- Cloud image generation (DALL-E API)
- Basic file upload (limited by storage)
- Markdown rendering (with marked.js)
- Syntax highlighting (with highlight.js)

**Will Never Be Added:**
- Local LLM (too resource-intensive for mobile)
- Local image generation (requires GPU)
- Heavy tool execution (security risk in Termux)

## Development Workflow

### Desktop PKN
```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn
just dev-app pkn        # Starts Flask + llama.cpp
just test-app pkn       # Runs full test suite
```

### Mobile PKN
```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn-mobile
just dev-app pkn-mobile  # Starts Flask only
./scripts/deploy_to_phone.sh  # Deploy via SSH to phone
```

## Deployment

### Desktop PKN
- **Local**: Run directly on Linux/Mac/Windows
- **Docker**: Full containerization with GPU support
- **Production**: Deploy to cloud VM with GPU

### Mobile PKN
- **Termux**: Direct deployment on Android
- **SSH**: Remote access from phone
- **Autostart**: Set up Termux boot service
- **Background**: Run as persistent service

## Configuration Differences

### Desktop PKN (.env)
```bash
OLLAMA_BASE=http://127.0.0.1:11434
LOCAL_LLM_BASE=http://127.0.0.1:8000/v1
ANTHROPIC_API_KEY=sk-...  # Optional
OPENAI_API_KEY=sk-...     # Optional
```

### Mobile PKN (.env)
```bash
OPENAI_API_KEY=sk-...     # REQUIRED
OPENAI_MODEL=gpt-4o-mini  # Optional
SERVER_PORT=8010          # Optional
```

## File Structure Comparison

### Desktop PKN
```
apps/pkn/
├── backend/
│   ├── agents/       # Multi-agent system
│   ├── routes/       # 16 blueprints
│   ├── tools/        # 13 tool modules
│   ├── memory/       # Conversation memory
│   ├── image_gen/    # Stable Diffusion
│   └── server.py     # Main Flask app
├── frontend/
│   ├── css/          # 7 CSS files
│   ├── js/           # 20+ JS modules
│   └── pkn.html      # Rich UI
└── llama.cpp/        # Local LLM engine
```

### Mobile PKN
```
apps/pkn-mobile/
├── backend/
│   ├── routes/       # 2 blueprints (chat, health)
│   ├── api/          # OpenAI client
│   ├── config/       # Mobile settings
│   ├── memory/       # ✅ SYMLINK to ../pkn/backend/memory
│   └── server.py     # Simplified Flask
├── frontend/
│   ├── js/
│   │   ├── core/     # ✅ SYMLINK to ../pkn/frontend/js/core
│   │   ├── utils/    # ✅ SYMLINK to ../pkn/frontend/js/utils
│   │   └── api/      # ✅ SYMLINK to ../pkn/frontend/js/api
│   ├── mobile/       # Mobile-specific overrides
│   └── pkn.html      # Simplified UI (inline CSS)
└── scripts/
    └── deploy_to_phone.sh
```

## Migration Path

**To migrate from Desktop PKN to Mobile PKN:**
1. Export conversation memory (shared automatically via symlink)
2. Copy `.env` (change to OpenAI API key)
3. Deploy to phone
4. Conversations continue seamlessly

**To migrate from Mobile PKN to Desktop PKN:**
1. Memory already synced (if using shared directory)
2. Install desktop version
3. Load local models
4. All features available

## Summary

Mobile PKN is **NOT a replacement** for desktop PKN. It's a **companion app** for:
- On-the-go access
- Low-resource environments
- Testing/development on mobile
- Quick queries without starting full server

Desktop PKN remains the **primary platform** for:
- Heavy workloads (code generation, research)
- Offline operation
- Full feature set
- Maximum performance

**Use Mobile PKN when**: You're away from your desktop and need quick AI assistance.
**Use Desktop PKN when**: You need full power, offline operation, or advanced features.
