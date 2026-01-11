# Divine Node Workspace - Architecture

**High-level overview of the monorepo architecture, design decisions, and code organization.**

---

## Table of Contents

- [Overview](#overview)
- [Monorepo Structure](#monorepo-structure)
- [Design Principles](#design-principles)
- [Application Architectures](#application-architectures)
- [Shared Code Strategy](#shared-code-strategy)
- [Build System](#build-system)
- [Testing Strategy](#testing-strategy)
- [Deployment Architecture](#deployment-architecture)

---

## Overview

Divine Node Workspace is a **monorepo** containing three production applications:

1. **PKN** - AI assistant with local LLM (desktop)
2. **Code Academy** - Interactive coding education (web)
3. **PKN Mobile** - Simplified AI assistant (Android/Termux)

**Key Characteristics:**
- Modular architecture (200-line file limit)
- Shared configurations (DRY principle)
- Comprehensive developer tooling
- Production-ready applications

---

## Monorepo Structure

```
divine-workspace/
├── apps/                           # Applications
│   ├── pkn/                        # AI Assistant (Desktop)
│   │   ├── backend/                # Python Flask backend
│   │   │   ├── server.py           # Main Flask app
│   │   │   ├── routes/             # API route handlers (16 blueprints)
│   │   │   ├── agents/             # Multi-agent system
│   │   │   ├── tools/              # Agent tools (13 modules)
│   │   │   ├── memory/             # Conversation memory
│   │   │   ├── image_gen/          # Stable Diffusion
│   │   │   └── config/             # Configuration
│   │   ├── frontend/               # Web UI
│   │   │   ├── pkn.html            # Main HTML
│   │   │   ├── css/                # Stylesheets (7 files)
│   │   │   └── js/                 # JavaScript (modular ES6)
│   │   ├── llama.cpp/              # Local LLM engine (submodule)
│   │   ├── tests/                  # Test suite
│   │   └── server.py               # Entry point launcher
│   │
│   ├── code-academy/               # Interactive Learning Platform
│   │   ├── src/                    # Source code (ES6 modules)
│   │   │   ├── main.js             # Entry point
│   │   │   ├── core/               # Core engine
│   │   │   ├── components/         # UI components
│   │   │   ├── services/           # Data services
│   │   │   ├── managers/           # State managers
│   │   │   └── utils/              # Utilities
│   │   ├── lessons/                # Lesson JSON data
│   │   ├── css/                    # Stylesheets
│   │   ├── tests/                  # Test suite
│   │   └── index.html              # Entry point
│   │
│   └── pkn-mobile/                 # AI Assistant (Mobile)
│       ├── backend/                # Simplified Flask backend
│       │   ├── server.py           # Main Flask app
│       │   ├── routes/             # API routes (2 blueprints)
│       │   ├── api/                # OpenAI client
│       │   ├── config/             # Mobile config
│       │   └── memory/             # ✅ SYMLINK to ../pkn/backend/memory
│       ├── frontend/               # Mobile-optimized UI
│       │   ├── pkn.html            # Inline CSS
│       │   └── js/                 # ✅ SYMLINKS to ../pkn/frontend/js/*
│       └── scripts/                # Deployment scripts
│
├── packages/                       # Shared Packages
│   ├── shared-config/              # Shared configurations
│   │   ├── biome.json              # Linting/formatting rules
│   │   ├── .pre-commit-config.yaml # Git hooks
│   │   └── package.json
│   │
│   └── dev-dashboard/              # Development monitoring
│       ├── src/dashboard.py        # Terminal UI
│       └── requirements.txt
│
├── scripts/                        # Helper Scripts
│   ├── check_file_size.py          # 200-line enforcer
│   ├── run_tests_for_files.py      # Smart test runner
│   └── health_check.py             # System health
│
├── .vscode/                        # VS Code Integration
│   ├── tasks.json                  # Workspace tasks
│   ├── launch.json                 # Debug configs
│   ├── settings.json               # Editor settings
│   └── extensions.json             # Recommended extensions
│
├── docs/                           # Documentation
│   ├── ARCHITECTURE.md             # This file
│   ├── CONTRIBUTING.md             # Contribution guide
│   └── TROUBLESHOOTING.md          # Common issues
│
├── justfile                        # Task runner (30+ commands)
├── pnpm-workspace.yaml             # pnpm workspace config
├── CLAUDE.md                       # AI assistant guide
├── CHANGELOG.md                    # Version history
└── README.md                       # Main documentation
```

---

## Design Principles

### 1. Modular Architecture (200-Line Limit)

**Rule**: Every source file MUST be ≤200 lines.

**Why:**
- Forces good separation of concerns
- Makes files easier to understand
- Reduces merge conflicts
- Enables better code reuse

**Enforcement:**
- Pre-commit hook (`scripts/check_file_size.py`)
- CI pipeline (`just check-file-sizes`)

**How to Split Large Files:**

```python
# ❌ BAD: 500-line monolithic file
# divinenode_server.py (2,310 lines)

# ✅ GOOD: Split into modules
backend/
├── server.py              # 50 lines (Flask app initialization)
├── routes/
│   ├── __init__.py        # 20 lines (route registration)
│   ├── chat.py            # 90 lines (chat endpoint)
│   ├── files.py           # 120 lines (file operations)
│   └── health.py          # 30 lines (health check)
└── config/
    └── settings.py        # 60 lines (configuration)
```

### 2. Shared Configurations (DRY Principle)

**Pattern**: Base configs in `packages/shared-config/`, apps extend them.

```json
// apps/pkn/biome.json
{
  "extends": ["@divine/shared-config/biome.json"],
  "files": {
    "ignore": ["llama.cpp/", "data/"]  // PKN-specific
  }
}
```

**Benefits:**
- Update linting rules once, affects all apps
- Consistent code style across apps
- Apps can override for specific needs

### 3. Code Sharing via Symlinks

**Used in PKN Mobile** to share code with Desktop PKN:

```bash
apps/pkn-mobile/backend/memory → ../../pkn/backend/memory
apps/pkn-mobile/frontend/js/core → ../../../pkn/frontend/js/core
apps/pkn-mobile/frontend/js/utils → ../../../pkn/frontend/js/utils
```

**Benefits:**
- Maximum code reuse (80%+ shared)
- Single source of truth
- Bug fixes apply to both versions
- Minimal duplication

**When to Use:**
- Code is identical between apps
- Both apps update together
- Symlink targets are stable

**When NOT to Use:**
- Code diverges significantly
- Independent versioning needed
- Different platforms (browser vs Node.js)

### 4. Developer-First Tooling

**Philosophy**: Make common tasks one command.

Examples:
```bash
just dev          # Not: cd apps/pkn && python server.py & cd ../code-academy && python -m http.server
just test         # Not: cd apps/pkn && pytest & cd ../code-academy && pnpm test
just ci           # Not: lint && format && test && check-file-sizes
```

**Pre-commit hooks** catch issues before commit (not in CI).

### 5. Documentation as Code

**Rule**: Every app has `CLAUDE.md` with:
- Quick reference table
- Critical code paths (file:line)
- Known issues & solutions
- Import path examples
- Testing commands

**Benefit**: AI assistants (or new developers) can continue sessions with zero context loss.

---

## Application Architectures

### PKN (AI Assistant - Desktop)

**Type**: Python Flask backend + Web frontend

**Tech Stack:**
- Backend: Flask 3.0, Python 3.10+
- LLM: llama.cpp (local inference)
- Frontend: Vanilla JS (ES6 modules), CSS
- Storage: File-based (memory/, data/)

**Architecture Pattern**: Multi-layered Flask application

```
Request Flow:
User → pkn.html → js/api/client.js → Flask Route → Agent Manager → Tools → LLM → Response
```

**Key Components:**

1. **Multi-Agent System** (`backend/agents/`)
   - AgentManager orchestrates 6 specialized agents
   - Classifier routes tasks to appropriate agent
   - Agents: coder, reasoner, researcher, executor, consultant, security

2. **Route Handlers** (`backend/routes/`) - 16 Flask blueprints
   - Each blueprint handles specific API surface
   - Examples: chat, files, images, osint, models

3. **Tools** (`backend/tools/`) - 13 tool modules
   - Agents invoke tools for actions
   - Examples: code_tools, file_tools, osint_tools, web_tools

4. **Memory** (`backend/memory/`)
   - Conversation persistence
   - Code context tracking
   - Session management

**File Size Compliance:**
- Largest file: agent_manager.py (888 lines after splitting)
  - Was 1,624 lines
  - Split into: types.py (60), classifier.py (188), manager.py (888)
- All routes: <200 lines each
- All tools: <200 lines each

### Code Academy (Interactive Learning)

**Type**: Static web application

**Tech Stack:**
- Frontend: Vanilla JS (ES6 modules), CSS
- Build: Vite (optional, currently static)
- Testing: Vitest (unit) + Playwright (E2E)
- Server: Python http.server (dev)

**Architecture Pattern**: Component-based SPA

```
User Flow:
index.html → src/main.js → TutorialEngine → LessonLoader → Components → User
```

**Key Components:**

1. **Tutorial Engine** (`src/core/TutorialEngine.js`)
   - Orchestrates lesson flow
   - Was 1,108 lines (split into 5 modules planned)

2. **Lesson Data** (`lessons/`)
   - JSON files with step-by-step instructions
   - Schema: title, description, steps[], tasks[]

3. **Interactive Components** (`src/components/`)
   - CodeEditor: Live code editing
   - QuizComponent: Multiple choice quizzes
   - TerminalWidget: Simulated terminal

**Progressive Enhancement:**
- Works without JavaScript (static content)
- Enhanced with JS for interactivity
- Mobile-responsive design

### PKN Mobile (AI Assistant - Android)

**Type**: Simplified Flask backend + Mobile UI

**Tech Stack:**
- Backend: Flask 3.0, OpenAI API (cloud LLM)
- Frontend: Inline CSS, minimal JS
- Platform: Android (Termux)
- Storage: Shared with desktop (via symlink)

**Architecture Pattern**: Cloud-powered thin client

```
Request Flow:
Mobile UI → Flask Route → OpenAI API → Streaming Response → UI Update
```

**Simplifications vs Desktop:**
- ❌ No local LLM (uses OpenAI API)
- ❌ No multi-agent (single general agent)
- ❌ No image generation
- ❌ No OSINT tools
- ✅ Same memory system (shared)
- ✅ Same API structure (compatible)

**Shared Code:**
- `backend/memory/` - 100% shared (symlink)
- `frontend/js/core/` - Shared utilities
- `frontend/js/utils/` - Shared helpers

**Mobile-Specific:**
- Inline CSS (browser caching issues)
- Touch-optimized UI (44px targets)
- Minimal dependencies

---

## Shared Code Strategy

### When to Share

✅ **Share when:**
- Code is identical across apps
- Logic is domain-agnostic (utilities, helpers)
- Updates should apply to all consumers
- Tight coupling is acceptable

### How to Share

**Option 1: Symlinks** (fastest, simplest)
```bash
ln -s ../../pkn/backend/memory apps/pkn-mobile/backend/memory
```
- Use for: Identical code (100% shared)
- Benefit: Zero duplication
- Cost: Tight coupling

**Option 2: Shared Package** (most flexible)
```bash
packages/shared-utils/
  ├── package.json  # name: @divine/shared-utils
  └── src/index.js

apps/pkn/package.json
  dependencies:
    "@divine/shared-utils": "workspace:*"
```
- Use for: Reusable utilities
- Benefit: Versioned, independent
- Cost: More setup overhead

**Option 3: Copy-Paste** (avoid if possible)
- Use only when: Divergence expected
- Cost: Duplication, manual sync

---

## Build System

### Development

**No build step required** - All apps run directly:
- PKN: `python3 server.py`
- Code Academy: `python3 -m http.server 8011`
- PKN Mobile: `python3 backend/server.py`

**Future Enhancement**: Vite for Code Academy
- Bundle optimization
- Tree shaking
- CSS minification

### Production

**PKN:**
```bash
python3 server.py --host 0.0.0.0 --port 8010
# Or with systemd service
```

**Code Academy:**
```bash
# Static files, deploy to any web server
rsync -avz --exclude=node_modules ./ user@server:/var/www/code-academy/
```

**PKN Mobile:**
```bash
just deploy-mobile 192.168.1.100
# Rsync to phone via SSH
```

---

## Testing Strategy

### Unit Tests

**Location**: `apps/*/tests/unit/`

**Naming**:
- Python: `test_<module>.py`
- JavaScript: `<module>.test.js`

**Coverage Target**: >80%

**Run**:
```bash
just test-app pkn
just test-app code-academy
```

### Integration Tests

**Location**: `apps/*/tests/integration/`

**Purpose**: Test component interactions

**Example**: Full chat flow (user → agents → tools → response)

### E2E Tests

**Location**: `apps/*/tests/e2e/`

**Tool**: Playwright

**Purpose**: Test full user journeys

**Example**: Complete lesson from start to finish

### Pre-commit Testing

**Smart test runner** only runs tests for changed files:
```bash
just test-changed
# Finds test files for modified sources
# Runs pytest (Python) or vitest (JS)
```

---

## Deployment Architecture

### Development Environment

```
Developer Machine
├── PKN Server (localhost:8010)
├── Code Academy (localhost:8011)
└── llama.cpp (localhost:8000)
```

### Production - Desktop PKN

```
Linux Server (VPS or bare metal)
├── PKN Flask App (0.0.0.0:8010)
├── llama.cpp (localhost:8000)
├── Nginx Reverse Proxy (443 → 8010)
└── Systemd Service (auto-restart)
```

### Production - Code Academy

```
Static Hosting (Netlify/Vercel/GitHub Pages)
└── HTML/CSS/JS files (CDN-distributed)
```

### Production - PKN Mobile

```
Android Phone (Termux)
├── PKN Mobile Flask (localhost:8010)
├── OpenAI API (cloud)
└── SSH Access (remote management)
```

---

## Summary

**Divine Node Workspace** is a well-architected monorepo that prioritizes:

1. **Modularity** - 200-line file limit enforced
2. **Developer Experience** - One-command workflows
3. **Code Quality** - Pre-commit hooks, linting, formatting
4. **Documentation** - Comprehensive guides for AI/human developers
5. **Flexibility** - Apps can customize shared configs

**Key Metrics:**
- 3 production apps
- 200-line file limit (strictly enforced)
- 30+ just commands
- 100% test coverage for critical paths
- <5 minute onboarding time

For detailed implementation guides, see app-specific CLAUDE.md files.
