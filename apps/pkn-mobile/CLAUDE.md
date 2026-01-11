# PKN Mobile - Development Guide

**Last Updated**: 2026-01-10
**App Version**: 1.0.0
**Package**: @divine/pkn-mobile

---

## Quick Reference

| Item | Value |
|------|-------|
| **Entry Point** | backend/server.py |
| **Dev Server** | `just dev-app pkn-mobile` |
| **Port** | 8010 |
| **LLM Backend** | OpenAI API (cloud) |
| **Platform** | Android (Termux) |
| **Tests** | `just test-app pkn-mobile` |

---

## Architecture Overview

### Project Type
Python Flask backend + simplified web frontend for mobile deployment

### Key Differences from Desktop PKN
- ☁️ Uses OpenAI API instead of local llama.cpp
- 📱 Optimized for mobile (touch UI, minimal resources)
- 🔗 Shares memory system and core JS with desktop PKN via symlinks
- 📝 Inline CSS for better mobile browser caching
- 🚫 No multi-agent, no image generation, no heavy tools

**See [docs/DIFFERENCES.md](docs/DIFFERENCES.md) for full comparison.**

### Directory Structure
```
pkn-mobile/
├── backend/              # Python Flask backend
│   ├── server.py         # Main Flask app (≤200 lines)
│   ├── routes/           # API routes
│   │   ├── chat.py       # OpenAI chat integration
│   │   └── health.py     # Health check
│   ├── api/
│   │   └── openai_client.py  # OpenAI API wrapper
│   ├── config/
│   │   └── settings.py   # Mobile-specific settings
│   └── memory/           # ✅ SYMLINK to ../pkn/backend/memory
├── frontend/             # Web UI
│   ├── pkn.html          # Main HTML (inline CSS)
│   ├── js/
│   │   ├── core/         # ✅ SYMLINK to ../pkn/frontend/js/core
│   │   ├── utils/        # ✅ SYMLINK to ../pkn/frontend/js/utils
│   │   └── api/          # ✅ SYMLINK to ../pkn/frontend/js/api
│   └── mobile/           # Mobile-specific overrides
├── scripts/
│   ├── deploy_to_phone.sh    # SSH deployment
│   └── termux_menu.sh        # Termux launcher
├── docs/
│   ├── DIFFERENCES.md    # Desktop vs Mobile comparison
│   ├── MOBILE_SETUP.md   # Phone setup guide
│   └── TERMUX_GUIDE.md   # Termux deployment
├── data/
│   └── memory/           # Session persistence
├── package.json          # @divine/pkn-mobile
├── requirements.txt      # Minimal Python deps
├── biome.json            # Extends shared-config
├── .env.example          # Configuration template
└── README.md             # User documentation
```

### Tech Stack
- **Language**: Python 3.10+
- **Framework**: Flask 3.0.0
- **LLM**: OpenAI API (gpt-4o-mini)
- **Frontend**: Vanilla JS (ES6 modules)
- **Storage**: File-based (memory/, data/)

---

## Critical Code Paths

### Path 1: Chat Request Flow
**File**: `backend/routes/chat.py:17`

**Flow**:
1. User sends message via `/api/multi-agent/chat` POST
2. `handle_chat()` extracts message and context
3. Calls `openai_client.chat_completion()` with messages array
4. Streams response chunks back to frontend
5. Frontend appends to chat UI

**Imports**:
```python
from ..api.openai_client import OpenAIClient
```

**Breakpoints**: Line 33 (before API call), Line 51 (response handling)

### Path 2: OpenAI API Integration
**File**: `backend/api/openai_client.py:24`

**Flow**:
1. Initialize client with `OPENAI_API_KEY` from env
2. `chat_completion()` builds request payload
3. POST to `https://api.openai.com/v1/chat/completions`
4. Stream response line-by-line
5. Parse SSE (Server-Sent Events) format
6. Yield content chunks

**Imports**:
```python
import requests
from typing import Generator
```

**Breakpoints**: Line 46 (API request), Line 67 (streaming parser)

### Path 3: Server Initialization
**File**: `backend/server.py:16`

**Flow**:
1. Import Flask and CORS
2. Register routes from `backend/routes/__init__.py`
3. Configure static file serving from `frontend/`
4. Start server on 0.0.0.0:8010

**Imports**:
```python
from backend.routes import register_routes
```

---

## Dependencies

### Runtime Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 3.0.0 | Web server |
| flask-cors | 4.0.0 | CORS handling |
| requests | 2.31.0 | HTTP client (OpenAI API) |
| python-dotenv | 1.0.0 | Environment variables |

### Development Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| @divine/shared-config | workspace:* | Biome config |

### Internal Dependencies (Shared via Symlinks)
- `../pkn/backend/memory/` - Conversation memory and code context
- `../pkn/frontend/js/core/` - Core JavaScript modules
- `../pkn/frontend/js/utils/` - Utility functions
- `../pkn/frontend/js/api/` - API client

---

## Configuration

### Environment Variables (.env)
```bash
# REQUIRED
OPENAI_API_KEY=sk-...                 # Your OpenAI API key

# OPTIONAL
OPENAI_MODEL=gpt-4o-mini              # Model to use (default: gpt-4o-mini)
SERVER_HOST=0.0.0.0                   # Host to bind (default: 0.0.0.0)
SERVER_PORT=8010                      # Port to listen (default: 8010)
```

### Config Files
- `backend/config/settings.py` - Mobile-specific settings
- `biome.json` - Linter/formatter config (extends shared)
- `package.json` - Package metadata and scripts

---

## Common Development Tasks

### Start Development Server
```bash
just dev-app pkn-mobile
# OR
cd apps/pkn-mobile
python3 backend/server.py --debug
```

**What it does**: Starts Flask server with debug mode enabled
**Port**: 8010
**Hot Reload**: No (requires manual restart)
**API Docs**: http://localhost:8010/health

### Run Tests
```bash
just test-app pkn-mobile
```

**Test Types**: Unit (utils, API client)
**Coverage**: Target >80%

### Build for Production
```bash
# No build step - Python runs directly
```

**Deployment**: Copy to phone via `./scripts/deploy_to_phone.sh`

### Debug
```bash
just debug-pkn-mobile
# OR
cd apps/pkn-mobile
python3 -m pdb backend/server.py
```

**Debugger**: pdb (Python debugger)
**Breakpoints**: Add `import pdb; pdb.set_trace()` in code

---

## Known Issues & Solutions

### Issue 1: "OpenAI API not configured"
**Symptom**: Chat endpoint returns 500 error with "OpenAI API not configured"
**Cause**: OPENAI_API_KEY not set in environment
**Solution**:
```bash
cp .env.example .env
# Edit .env and add your API key
export OPENAI_API_KEY=sk-...
python3 backend/server.py
```

### Issue 2: "ModuleNotFoundError: No module named 'requests'"
**Symptom**: Server fails to start with import error
**Cause**: Python dependencies not installed
**Solution**:
```bash
pip3 install -r requirements.txt
```

### Issue 3: Symlinks broken (memory/ not found)
**Symptom**: ImportError for memory modules
**Cause**: Symlinks created with absolute paths instead of relative
**Solution**:
```bash
cd apps/pkn-mobile/backend
rm memory
ln -s ../../pkn/backend/memory memory
```

### Issue 4: OpenAI API rate limit exceeded
**Symptom**: 429 error from API
**Cause**: Too many requests in short time
**Solution**:
```bash
# Switch to gpt-3.5-turbo (cheaper, faster)
export OPENAI_MODEL=gpt-3.5-turbo

# Or wait 60 seconds and retry
```

---

## File Size Limits (STRICT 200 LINES)

### Current Files
| File | Lines | Status |
|------|-------|--------|
| backend/server.py | ~50 | ✅ OK |
| backend/routes/chat.py | ~90 | ✅ OK |
| backend/api/openai_client.py | ~95 | ✅ OK |
| frontend/pkn.html | ~180 | ✅ OK |

**All files under 200 lines ✅**

---

## Import Paths (CRITICAL)

### Python Imports
```python
# From backend/server.py:
from backend.routes import register_routes
from flask import Flask, send_from_directory

# From backend/routes/chat.py:
from ..api.openai_client import OpenAIClient
from flask import Blueprint, request, Response

# From backend/api/openai_client.py:
import requests
from typing import Generator
```

### JavaScript Imports (ES6 Modules)
```javascript
// Inline in pkn.html (no external modules for mobile)
// Shared modules available via symlinks if needed
```

### Static Asset Paths
```python
# Flask serves from: apps/pkn-mobile/frontend/
ROOT = Path(__file__).parent.parent / 'frontend'

# HTML references (relative):
# None - all CSS inline in pkn.html for mobile optimization
```

---

## Recent Changes

### 2026-01-10 - Initial Mobile PKN Implementation
**Changed**:
- Created apps/pkn-mobile/ directory structure
- Implemented OpenAI API backend (server.py, routes/, api/)
- Created simplified mobile frontend (pkn.html with inline CSS)
- Symlinked shared code (memory, core JS, utils JS, api JS)
- Configured package.json, requirements.txt, biome.json

**Impact**: New mobile-optimized PKN app for Android (Termux) deployment
**Migration**: None (new app, does not affect desktop PKN)

---

## Debugging Guide

### Common Errors

#### Error: "Failed to fetch"
**File**: frontend/pkn.html (JavaScript)
**Cause**: Server not running or wrong port
**Fix**:
```bash
# Check if server is running
curl http://localhost:8010/health

# If not running, start server
python3 backend/server.py
```

#### Error: "401 Unauthorized" from OpenAI
**File**: backend/api/openai_client.py:46
**Cause**: Invalid API key
**Fix**:
```bash
# Verify API key is correct
echo $OPENAI_API_KEY

# Update .env with correct key
vim .env
```

#### Error: "Connection refused"
**File**: backend/api/openai_client.py:46
**Cause**: Network issue or firewall
**Fix**:
```bash
# Test network connectivity
curl https://api.openai.com/v1/models

# Check DNS resolution
ping api.openai.com
```

### Logging

**Backend Logs**: `stdout` (console)
**Frontend Logs**: Browser Console (F12 → Console)
**API Logs**: Check requests in Network tab

**Log Levels**: INFO (default), DEBUG (with --debug flag)

### Performance Profiling

**Backend**:
```bash
python3 -m cProfile -o profile.out backend/server.py
python3 -m pstats profile.out
```

**Frontend**: Chrome DevTools → Performance tab

---

## Testing Strategy

### Unit Tests
**Location**: `tests/unit/`
**Run**: `pytest tests/unit/`
**Coverage Target**: >80%

**Example**:
```python
# tests/unit/test_openai_client.py
from backend.api.openai_client import OpenAIClient

def test_chat_completion():
    client = OpenAIClient()
    messages = [{'role': 'user', 'content': 'Hello'}]
    response = list(client.chat_completion(messages, stream=False))
    assert len(response) > 0
```

### Integration Tests
**Location**: `tests/integration/`
**Purpose**: Test full chat flow (request → OpenAI → response)

### E2E Tests
**Location**: `tests/e2e/`
**Tool**: Playwright (mobile viewport)

---

## Deployment

### Local Development
1. `cd apps/pkn-mobile`
2. `cp .env.example .env` (add your OpenAI API key)
3. `pip3 install -r requirements.txt`
4. `python3 backend/server.py --debug`
5. Open `http://localhost:8010`

### Mobile Deployment (Termux)
1. **Prepare phone**:
   ```bash
   # On phone (Termux)
   pkg install python openssh
   pip install --upgrade pip
   mkdir ~/pkn-mobile
   ```

2. **Deploy from desktop**:
   ```bash
   # On desktop
   cd apps/pkn-mobile
   ./scripts/deploy_to_phone.sh <phone-ip>
   ```

3. **Start on phone**:
   ```bash
   # On phone (Termux)
   cd ~/pkn-mobile
   export OPENAI_API_KEY=sk-...
   python backend/server.py
   ```

4. **Access**:
   - From phone browser: `http://localhost:8010`
   - From desktop browser: `http://<phone-ip>:8010`

### Production Deployment
```bash
# Use production WSGI server
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:8010 backend.server:app
```

---

## Troubleshooting

### Server Won't Start
1. Check port 8010 is free: `lsof -i :8010`
2. Kill existing process: `pkill -f "python.*server.py"`
3. Check Python version: `python3 --version` (need 3.10+)
4. Check dependencies: `pip3 list | grep -E "Flask|requests"`

### OpenAI API Errors
1. Verify API key: `curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"`
2. Check rate limits: https://platform.openai.com/account/limits
3. Try different model: `export OPENAI_MODEL=gpt-3.5-turbo`

### Memory Not Persisting
1. Check symlink: `ls -la backend/memory`
2. Verify write permissions: `touch backend/memory/test.txt`
3. Check disk space: `df -h`

### Mobile UI Issues
1. Clear browser cache (mobile browsers cache aggressively)
2. Check touch targets are ≥44px
3. Test on actual device (not just DevTools mobile emulation)

---

## Contributing

### Before Committing
1. `just lint` - Fix linting errors
2. `just format` - Format code
3. `just test-app pkn-mobile` - Run tests
4. Verify all files ≤200 lines

### Code Style
- **File Size**: Max 200 lines (strictly enforced)
- **Imports**: Sorted alphabetically
- **Formatting**: Biome (JavaScript), Black (Python)
- **Docstrings**: Google style for Python

---

## Additional Resources

- [DIFFERENCES.md](docs/DIFFERENCES.md) - Desktop vs Mobile comparison
- [Main PKN CLAUDE.md](../pkn/CLAUDE.md) - Desktop version guide
- [Workspace CLAUDE.md](../../CLAUDE.md) - Monorepo guide
- [OpenAI API Docs](https://platform.openai.com/docs/api-reference)

---

## Security Considerations

### API Key Safety
- ⚠️ Never commit `.env` file to git
- ⚠️ Use environment variables only (not hardcoded)
- ⚠️ Rotate API keys regularly
- ⚠️ Set spending limits on OpenAI account

### Network Security
- Flask CORS is wide open (allow all origins) - **OK for personal use**
- Consider adding authentication for production
- Use HTTPS in production (nginx reverse proxy)

### Mobile Security
- Termux apps run in sandboxed environment (safe)
- No shell access from web UI (safer than desktop)
- Minimal attack surface (only 2 routes)

---

## Performance Targets

- Cold Start: < 5 seconds
- First Response: < 3 seconds (API latency)
- Streaming Latency: < 100ms per chunk
- Memory Usage: < 100MB
- Battery Usage: < 5%/hour

---

## Browser Support

**Target**:
- Chrome Mobile (latest)
- Firefox Mobile (latest)
- Mobile Safari (iOS 14+)

**No support needed**:
- Desktop browsers (use desktop PKN instead)
- Old Android browsers (< Android 8)

---

## Questions?

1. Check [DIFFERENCES.md](docs/DIFFERENCES.md) for desktop vs mobile comparison
2. Check [Desktop PKN CLAUDE.md](../pkn/CLAUDE.md) for shared concepts
3. Search OpenAI docs for API issues
4. Test in mobile browser (not desktop DevTools)

**MOBILE-FIRST, SIMPLIFIED, CLOUD-POWERED**
