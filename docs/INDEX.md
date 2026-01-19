# Divine Workspace Documentation Index

**Central hub for all documentation. Start here.**

Last updated: 2026-01-18

---

## Quick Links

### For AI Assistants (Claude Code)
- [Root CLAUDE.md](../CLAUDE.md) - Workspace-wide instructions and agent selection
- [PKN CLAUDE.md](../apps/pkn/CLAUDE.md) - Desktop PKN application specifics
- [PKN Mobile CLAUDE.md](../apps/pkn-mobile/CLAUDE.md) - Mobile PKN deployment guide
- [Code Academy CLAUDE.md](../apps/code-academy/CLAUDE.md) - Learning platform specifics
- [Scripture Alarm CLAUDE.md](../apps/scripture-alarm/CLAUDE.md) - Devotional app

### Architecture & Design
- [Architecture Overview](./ARCHITECTURE.md) - Monorepo structure and system design
- [Shadow OSINT](./SHADOW_OSINT.md) - 35 OSINT tools reference

### Development Workflow
- [Contributing Guide](./CONTRIBUTING.md) - How to contribute to the workspace
- [Troubleshooting](./TROUBLESHOOTING.md) - Common issues and solutions

---

## Documentation Map

| Document | Purpose | Primary Audience |
|----------|---------|------------------|
| **CLAUDE.md files** | AI assistant instructions and context | Claude Code |
| **ARCHITECTURE.md** | System design and monorepo structure | Developers |
| **SHADOW_OSINT.md** | OSINT toolkit reference (35 tools) | Security/OSINT users |
| **CONTRIBUTING.md** | Development workflow and standards | Contributors |
| **TROUBLESHOOTING.md** | Common issues and debugging | Everyone |
| **INDEX.md** (this file) | Central documentation hub | Everyone |

---

## Documentation by Application

### PKN (Desktop AI Assistant)

**Main Documentation Hub:**
- [PKN Docs Index](../apps/pkn/docs/README.md) - Complete PKN documentation map

**Essential Guides:**
- [PKN CLAUDE.md](../apps/pkn/CLAUDE.md) - AI development guide
- [Agent Configuration](../apps/pkn/docs/AGENT_CONFIGURATION.md) - 9 specialized agents
- [Tool Execution Framework](../apps/pkn/docs/TOOL_EXECUTION_FRAMEWORK.md) - 13 tool modules

**Architecture:**
- [Modular Structure](../apps/pkn/docs/architecture/MODULAR_STRUCTURE.md) - Backend architecture
- [Ultimate Agent Architecture](../apps/pkn/docs/architecture/ULTIMATE_AGENT_ARCHITECTURE.md) - Multi-agent system
- [Multi-Agent Roadmap](../apps/pkn/docs/architecture/MULTIAGENT_ROADMAP.md) - Development roadmap
- [Agentic Qualities](../apps/pkn/docs/architecture/AGENTIC_QUALITIES.md) - Design philosophy
- [Cybersecurity Agent](../apps/pkn/docs/architecture/CYBERSECURITY_AGENT.md) - Security agent specs

**Build & Deployment:**
- [Build README](../apps/pkn/docs/build/BUILD_README.md) - Comprehensive build guide
- [Build on Android](../apps/pkn/docs/build/BUILD_ON_ANDROID.md) - Android-specific builds
- [Termux Setup](../apps/pkn/docs/build/TERMUX_SETUP.md) - Termux deployment
- [Transfer to Android](../apps/pkn/docs/build/TRANSFER_TO_ANDROID.md) - Device transfer guide
- [Android Compatibility](../apps/pkn/docs/build/ANDROID_COMPATIBILITY.md) - Compatibility notes
- [Android vs PC Models](../apps/pkn/docs/build/ANDROID_VS_PC_MODELS.md) - Model comparison
- [Capacitor Setup](../apps/pkn/docs/build/CAPACITOR_SETUP.md) - Mobile framework setup

**Development:**
- [Dev Tools README](../apps/pkn/docs/development/DEV_TOOLS_README.md) - Development utilities
- [Advanced Features Guide](../apps/pkn/docs/development/ADVANCED_FEATURES_GUIDE.md) - Advanced features
- [Claude API Setup](../apps/pkn/docs/development/CLAUDE_API_SETUP.md) - Cloud API configuration
- [PKN CLI README](../apps/pkn/docs/development/PKN_CLI_README.md) - Command-line tools
- [OSINT README](../apps/pkn/docs/development/OSINT_README.md) - OSINT tools documentation
- [Plugin Test Checklist](../apps/pkn/docs/development/PLUGIN_TEST_CHECKLIST.md) - Testing procedures
- [Test Plugins](../apps/pkn/docs/development/TEST_PLUGINS.md) - Plugin test suite
- [Uncensored Image Models](../apps/pkn/docs/development/UNCENSORED_IMAGE_MODELS.md) - Image generation

**Archive:**
- [Agent Testing Archive](../apps/pkn/docs/archive/agent-testing-2026-01-14/) - Historical test results

---

### PKN Mobile (Android/Termux PWA)

**Main Documentation Hub:**
- [PKN Mobile Docs Index](../apps/pkn-mobile/docs/README.md) - Quick reference for mobile deployment

**Essential Guides:**
- [PKN Mobile CLAUDE.md](../apps/pkn-mobile/CLAUDE.md) - AI development guide and configuration
- [Deployment Guide](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md) - Complete setup instructions
- [Troubleshooting Guide](../apps/pkn-mobile/docs/TROUBLESHOOTING_MOBILE.md) - Mobile-specific issues

**Key Features:**
- Local-first architecture (Ollama by default, cloud optional)
- Mobile-responsive UI with PWA support
- Uncensored models for security agent
- 7B models optimized for mobile hardware
- Full 9-agent system with 13 tool modules

---

### Code Academy (Interactive Learning Platform)

**Main Documentation:**
- [Code Academy CLAUDE.md](../apps/code-academy/CLAUDE.md) - Vanilla JS learning platform

**Additional Resources:**
- [README](../apps/code-academy/README.md) - Project overview
- [Tools README](../apps/code-academy/README_TOOLS.md) - Development tools
- Session documentation in `docs/sessions/` (setup, tooling, verification)

---

### Scripture Alarm (Devotional App)

**Documentation:**
- [Scripture Alarm CLAUDE.md](../apps/scripture-alarm/CLAUDE.md) - Android alarm app

---

## Cross-Reference Guide

When documentation references other documents, use these links:

| Reference Need | Link Target |
|----------------|-------------|
| Architecture details | [ARCHITECTURE.md](./ARCHITECTURE.md) |
| Agent configuration (PKN) | [AGENT_CONFIGURATION.md](../apps/pkn/docs/AGENT_CONFIGURATION.md) |
| Tool modules (PKN) | [TOOL_EXECUTION_FRAMEWORK.md](../apps/pkn/docs/TOOL_EXECUTION_FRAMEWORK.md) |
| OSINT toolkit | [SHADOW_OSINT.md](./SHADOW_OSINT.md) |
| Contributing guidelines | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Troubleshooting issues | [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) |
| Build instructions (PKN) | [BUILD_README.md](../apps/pkn/docs/build/BUILD_README.md) |
| Mobile deployment (PKN) | [Mobile Deployment Guide](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md) |
| Mobile troubleshooting | [Mobile Troubleshooting](../apps/pkn-mobile/docs/TROUBLESHOOTING_MOBILE.md) |

---

## Common Tasks & Where to Find Help

### I want to...

**Understand the workspace structure:**
→ Start with [ARCHITECTURE.md](./ARCHITECTURE.md)

**Build PKN from source:**
→ Read [PKN Build README](../apps/pkn/docs/build/BUILD_README.md)

**Deploy PKN to Android/Termux:**
→ Follow [Mobile Deployment Guide](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md)
→ Or [PKN Mobile Docs Index](../apps/pkn-mobile/docs/README.md) for quick reference

**Configure PKN agents:**
→ See [Agent Configuration](../apps/pkn/docs/AGENT_CONFIGURATION.md)

**Use OSINT tools:**
→ Reference [SHADOW_OSINT.md](./SHADOW_OSINT.md)

**Contribute to the project:**
→ Start with [CONTRIBUTING.md](./CONTRIBUTING.md)

**Fix a bug or issue:**
→ Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)

**Understand multi-agent architecture:**
→ Read [Ultimate Agent Architecture](../apps/pkn/docs/architecture/ULTIMATE_AGENT_ARCHITECTURE.md)

**Write new tools for agents:**
→ See [Tool Execution Framework](../apps/pkn/docs/TOOL_EXECUTION_FRAMEWORK.md)

**Set up development environment:**
→ Follow [Dev Tools README](../apps/pkn/docs/development/DEV_TOOLS_README.md)

**Work with Code Academy:**
→ Start with [Code Academy CLAUDE.md](../apps/code-academy/CLAUDE.md)

---

## Documentation Standards

### For CLAUDE.md Files

**Purpose:** Provide context and instructions for AI assistants (Claude Code)

**Should Include:**
- Project overview
- Architecture summary
- Key file locations
- Development commands
- Known issues and recent fixes
- Important patterns and conventions
- Critical rules and warnings

### For Technical Documentation

**Purpose:** Document system design, APIs, and implementation details

**Should Include:**
- Clear purpose statement
- Table of contents
- Code examples
- Visual diagrams (when helpful)
- Related documentation links
- Last updated date

### For Guides

**Purpose:** Step-by-step instructions for specific tasks

**Should Include:**
- Prerequisites
- Numbered steps
- Commands with expected output
- Troubleshooting section
- Next steps

---

## Documentation Maintenance

### When to Update Docs

**Always update when:**
- Adding new features or tools
- Changing architecture or file structure
- Fixing bugs that affect documented behavior
- Adding new applications to workspace
- Discovering new solutions to known issues

**Update these docs:**
- Relevant CLAUDE.md files (for AI context)
- ARCHITECTURE.md (for structural changes)
- TROUBLESHOOTING.md (for bug fixes)
- This INDEX.md (for new documentation files)

### Documentation File Locations

**Root Level** (`/home/gh0st/dvn/divine-workspace/`):
- `CLAUDE.md` - Workspace-wide AI instructions
- `docs/INDEX.md` - This file
- `docs/ARCHITECTURE.md` - System design
- `docs/SHADOW_OSINT.md` - OSINT reference
- `docs/CONTRIBUTING.md` - Contribution guide
- `docs/TROUBLESHOOTING.md` - Common issues

**App Level** (`apps/{app-name}/`):
- `CLAUDE.md` - App-specific AI instructions
- `docs/` - App-specific technical documentation
- `README.md` - User-facing overview

---

## Archives

Historical documentation preserved for reference:

### Workspace Archives
- [Project Purge 2026-01-11](./archives/purge-2026-01-11/) - Cleanup documentation

---

## Related Resources

### GitHub Repository
[divine-workspace](https://github.com/CovertCloak06/divine-workspace)

### Task Runner
- [justfile](../justfile) - Development task commands

### Configuration Files
- [Root CLAUDE.md](../CLAUDE.md) - AI agent selection rules
- [Architecture Standards](/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md) - Cross-project standards

---

## Documentation Statistics

| Category | Count | Location |
|----------|-------|----------|
| **Root Docs** | 5 | `docs/` |
| **PKN Docs** | 20+ | `apps/pkn/docs/` |
| **PKN Mobile Docs** | 4 | `apps/pkn-mobile/docs/`, `CLAUDE.md` |
| **Code Academy Docs** | 5+ | `apps/code-academy/` |
| **CLAUDE.md Files** | 5 | Various app directories |
| **Archives** | 6+ | `docs/archives/` |

---

## Version History

| Date | Change | Author |
|------|--------|--------|
| 2026-01-18 | Created comprehensive documentation index | Claude Code |

---

**Need help?** Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) or review the relevant CLAUDE.md file for your app.
