# PKN Documentation Index

**Last Updated**: 2026-01-11
**Total Docs**: 13 in root + 20 organized + 49 archived

---

## 📚 Essential Docs (Root Directory)

### Getting Started
- [README.md](README.md) - Project overview and introduction
- [QUICKSTART_GUIDE.md](QUICKSTART_GUIDE.md) - Get PKN running in 5 minutes
- [QUICKSTART_TOOLS.md](QUICKSTART_TOOLS.md) - Quick tool reference
- [CHANGELOG.md](CHANGELOG.md) - Version history and release notes

### Configuration
- [API_KEYS_SETUP.md](API_KEYS_SETUP.md) - Configure API keys (OpenAI, Anthropic)
- [PWA_GUIDE.md](PWA_GUIDE.md) - Progressive Web App installation
- [MOBILE_BUILD_GUIDE.md](MOBILE_BUILD_GUIDE.md) - Mobile/Termux deployment

### Reference
- [TOOLS_GUIDE.md](TOOLS_GUIDE.md) - Comprehensive tool reference
- [UI_vs_CLI_TOOLS.md](UI_vs_CLI_TOOLS.md) - UI vs CLI comparison
- [CREDITS.md](CREDITS.md) - Attributions and credits

### Development
- [CLAUDE.md](CLAUDE.md) - **AI development guide (START HERE)**
- [TODO.md](TODO.md) - Current tasks and roadmap
- [DOCS_INDEX.md](DOCS_INDEX.md) - This file

---

## 🏗️ Technical Documentation (docs/)

### Build & Deployment (`docs/build/`)
Detailed build instructions and deployment guides:
- [BUILD_README.md](docs/build/BUILD_README.md) - Comprehensive build guide
- [BUILD_ON_ANDROID.md](docs/build/BUILD_ON_ANDROID.md) - Android build process
- [CAPACITOR_SETUP.md](docs/build/CAPACITOR_SETUP.md) - Capacitor configuration
- [TERMUX_SETUP.md](docs/build/TERMUX_SETUP.md) - Termux deployment
- [TRANSFER_TO_ANDROID.md](docs/build/TRANSFER_TO_ANDROID.md) - Android transfer guide
- [ANDROID_COMPATIBILITY.md](docs/build/ANDROID_COMPATIBILITY.md) - Android notes
- [ANDROID_VS_PC_MODELS.md](docs/build/ANDROID_VS_PC_MODELS.md) - Model comparison

### Architecture (`docs/architecture/`)
System design and architecture documentation:
- [MODULAR_STRUCTURE.md](docs/architecture/MODULAR_STRUCTURE.md) - Modular architecture
- [ULTIMATE_AGENT_ARCHITECTURE.md](docs/architecture/ULTIMATE_AGENT_ARCHITECTURE.md) - Agent system design
- [MULTIAGENT_ROADMAP.md](docs/architecture/MULTIAGENT_ROADMAP.md) - Multi-agent roadmap
- [AGENTIC_QUALITIES.md](docs/architecture/AGENTIC_QUALITIES.md) - Agent design philosophy
- [CYBERSECURITY_AGENT.md](docs/architecture/CYBERSECURITY_AGENT.md) - Cybersecurity agent spec

### Development (`docs/development/`)
Developer guides and advanced features:
- [DEV_TOOLS_README.md](docs/development/DEV_TOOLS_README.md) - Development tools
- [ADVANCED_FEATURES_GUIDE.md](docs/development/ADVANCED_FEATURES_GUIDE.md) - Advanced features
- [CLAUDE_API_SETUP.md](docs/development/CLAUDE_API_SETUP.md) - Claude API setup
- [PKN_CLI_README.md](docs/development/PKN_CLI_README.md) - CLI tools guide
- [OSINT_README.md](docs/development/OSINT_README.md) - OSINT tools documentation
- [PLUGIN_TEST_CHECKLIST.md](docs/development/PLUGIN_TEST_CHECKLIST.md) - Plugin testing
- [TEST_PLUGINS.md](docs/development/TEST_PLUGINS.md) - Plugin tests
- [UNCENSORED_IMAGE_MODELS.md](docs/development/UNCENSORED_IMAGE_MODELS.md) - Image models

---

## 📦 Archived Documentation (archive/docs/)

### Session History (`archive/docs/sessions/`)
Historical development session notes (20 files):
- SESSION_*.md - Development session summaries
- *_COMPLETE.md - Feature completion reports
- *_SUMMARY.md - Session wrap-ups
- *_FIX*.md - Bug fix documentation

### Old Build Artifacts (`archive/docs/old-builds/`)
Historical build logs and test results (5 files):
- APK_BUILD_LOG.md - Old build logs
- ANDROID_CLEANUP_GUIDE.md - Old cleanup guides
- ANDROID_PACKAGE_READY.md - Old build status
- COMPREHENSIVE_AUDIT.md - Old audits
- PLUGIN_TEST_RESULTS.md - Old test results

### Planning Documents (`archive/docs/planning/`)
Future planning and vision documents (4 files):
- FUTURE_IMPROVEMENTS.md - Future enhancement plans
- AI_HANDOFF_GUIDE.md - AI handoff notes
- YOUR_FREE_SYSTEM.md - Philosophy and vision
- RESTORE_INSTRUCTIONS.md - Old restore procedures

---

## 🔍 Finding What You Need

| I want to... | Read this |
|--------------|-----------|
| **Get started quickly** | [QUICKSTART_GUIDE.md](QUICKSTART_GUIDE.md) |
| **Understand the codebase** | [CLAUDE.md](CLAUDE.md) ⭐ |
| **Build for Android** | [MOBILE_BUILD_GUIDE.md](MOBILE_BUILD_GUIDE.md) |
| **Use PKN's tools** | [TOOLS_GUIDE.md](TOOLS_GUIDE.md) |
| **Configure API keys** | [API_KEYS_SETUP.md](API_KEYS_SETUP.md) |
| **Learn the architecture** | [docs/architecture/](docs/architecture/) |
| **Build from source** | [docs/build/BUILD_README.md](docs/build/BUILD_README.md) |
| **Develop features** | [docs/development/](docs/development/) |
| **See what changed** | [CHANGELOG.md](CHANGELOG.md) |
| **Check current tasks** | [TODO.md](TODO.md) |
| **Find old session notes** | [archive/docs/sessions/](archive/docs/sessions/) |

---

## 📂 Directory Structure

```
apps/pkn/
├── README.md                       # Project overview
├── QUICKSTART_GUIDE.md             # Quick start
├── CLAUDE.md                       # AI dev guide ⭐
├── DOCS_INDEX.md                   # This file
├── [9 other essential docs]
│
├── docs/                           # Technical documentation
│   ├── build/                      # Build & deployment (7 docs)
│   ├── architecture/               # System design (5 docs)
│   ├── development/                # Dev guides (8 docs)
│   └── README.md                   # Docs navigation
│
└── archive/                        # Historical documentation
    └── docs/
        ├── sessions/               # Session history (20 docs)
        ├── old-builds/             # Old build artifacts (5 docs)
        └── planning/               # Planning docs (4 docs)
```

---

## 📊 Documentation Statistics

| Category | Count | Location |
|----------|-------|----------|
| Essential (Root) | 13 files | `*.md` |
| Build Docs | 7 files | `docs/build/` |
| Architecture | 5 files | `docs/architecture/` |
| Development | 8 files | `docs/development/` |
| Session History | 20 files | `archive/docs/sessions/` |
| Old Builds | 5 files | `archive/docs/old-builds/` |
| Planning | 4 files | `archive/docs/planning/` |
| **Total** | **62 files** | - |

---

## 📝 Documentation Standards

### Root Directory (Essential Docs Only)
- **User-facing**: Guides for getting started, using features
- **Quick reference**: API keys, tools, quick start
- **Maximum**: ~15 files to prevent clutter

### docs/ (Technical Documentation)
- **build/**: Build instructions, deployment, platform-specific
- **architecture/**: System design, agent architecture, roadmaps
- **development/**: Developer guides, advanced features, testing

### archive/docs/ (Historical Documentation)
- **sessions/**: Old session summaries and completion reports
- **old-builds/**: Historical build logs and test results
- **planning/**: Future planning and vision documents

---

## 🎯 Quick Start Paths

### New Users
1. [README.md](README.md) - Overview
2. [QUICKSTART_GUIDE.md](QUICKSTART_GUIDE.md) - Installation
3. [TOOLS_GUIDE.md](TOOLS_GUIDE.md) - Using tools

### Developers
1. [CLAUDE.md](CLAUDE.md) - Development guide ⭐
2. [docs/architecture/](docs/architecture/) - System design
3. [docs/development/](docs/development/) - Dev guides

### Mobile Users
1. [MOBILE_BUILD_GUIDE.md](MOBILE_BUILD_GUIDE.md) - Mobile setup
2. [docs/build/TERMUX_SETUP.md](docs/build/TERMUX_SETUP.md) - Termux details
3. [docs/build/ANDROID_COMPATIBILITY.md](docs/build/ANDROID_COMPATIBILITY.md) - Compatibility notes

---

_Documentation maintained by all contributors. Update this index when adding new docs._

**Last cleanup**: 2026-01-11 - Reduced from 48 to 13 root docs, organized 20 into docs/, archived 29.
