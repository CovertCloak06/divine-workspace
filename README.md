# Divine Node Workspace

**Production-ready monorepo for AI-powered applications**

A modular, well-documented monorepo containing PKN (AI assistant), Code Academy (interactive learning platform), and PKN Mobile (Android deployment) with world-class developer tooling.

## 🚀 Quick Start

```bash
# Clone repository
git clone <repository-url>
cd divine-workspace

# Initial setup (one-time)
just setup

# Start all dev servers
just dev

# Access applications
# PKN: http://localhost:8010
# Code Academy: http://localhost:8011
```

## 📦 What's Inside

### Applications (`apps/`)

| App | Description | Tech Stack | Status |
|-----|-------------|------------|--------|
| **PKN** | AI assistant with multi-agent system | Python, Flask, llama.cpp | ✅ Production |
| **Code Academy** | Interactive coding education platform | HTML, CSS, Vanilla JS | ✅ Production |
| **PKN Mobile** | Simplified PKN for Android/Termux | Python, Flask, OpenAI API | ✅ Production |

### Packages (`packages/`)

| Package | Purpose |
|---------|---------|
| **shared-config** | Shared Biome & pre-commit configs |
| **dev-dashboard** | Terminal UI for service monitoring |

### Infrastructure

- **Pre-commit hooks** - Automated code quality checks
- **VS Code integration** - Tasks, debugging, settings
- **Comprehensive justfile** - 30+ development commands
- **Helper scripts** - Health checks, test runners, file size enforcement

## 🛠️ Development

### Prerequisites

- **Node.js** 18+ (with pnpm)
- **Python** 3.10+
- **just** (command runner)
- **Git**

Optional:
- **pre-commit** (git hooks)
- **Biome** (linting/formatting)

### Common Commands

```bash
# Development
just dev                    # Start all dev servers
just dev-app pkn            # Start specific app
just stop                   # Stop all servers

# Code Quality
just lint                   # Lint all code
just format                 # Format all code
just ci                     # Full CI pipeline

# Testing
just test                   # Run all tests
just test-app pkn           # Test specific app
just test-changed           # Test changed files only

# Health & Monitoring
just health                 # Check system health
just check-tools            # Show tool versions
just check-file-sizes       # Verify 200-line limits

# Utilities
just add-app my-app         # Create new app
just backup                 # Backup workspace
just clean                  # Remove build artifacts

# See all commands
just --list
```

### VS Code Tasks

Open Command Palette (`Ctrl+Shift+P`) and search for "Tasks":
- **PKN: Start Server** - Launch PKN dev server
- **Code Academy: Dev Server** - Launch Code Academy
- **All: Health Check** - Run system health check
- **All: Run CI** - Run full CI pipeline

Press `Ctrl+Shift+B` for default build task.

## 📐 Architecture

### Monorepo Structure

```
divine-workspace/
├── apps/                   # Applications
│   ├── pkn/                # AI assistant (local LLM)
│   ├── code-academy/       # Interactive learning platform
│   └── pkn-mobile/         # Mobile PKN (OpenAI API)
├── packages/               # Shared packages
│   ├── shared-config/      # Shared configs
│   └── dev-dashboard/      # Dev monitoring
├── scripts/                # Helper scripts
├── .vscode/                # VS Code workspace config
├── justfile                # Task runner (30+ commands)
├── pnpm-workspace.yaml     # pnpm workspace config
└── CLAUDE.md               # AI assistant guide
```

### Design Principles

1. **Modular Architecture** - All files ≤200 lines
2. **Shared Configs** - DRY principle for configurations
3. **Developer First** - Comprehensive tooling and documentation
4. **Type Safety** - Linting and validation everywhere
5. **Fast Feedback** - Pre-commit hooks catch issues early

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

## 🧪 Testing

```bash
# Run all tests
just test

# Test specific app
just test-app pkn
just test-app code-academy

# Test only changed files (pre-commit)
just test-changed

# Watch mode (if supported)
cd apps/code-academy && pnpm test:watch
```

### Test Coverage

- **PKN**: Unit tests for agents, routes, tools
- **Code Academy**: Unit + E2E tests with Vitest + Playwright
- **Shared Scripts**: Validation tests for helper scripts

## 🚢 Deployment

### PKN (Desktop)

```bash
cd apps/pkn
python3 server.py --host 0.0.0.0 --port 8010

# Or with pkn_control.sh
./pkn_control.sh start-all
```

### Code Academy (Static Site)

```bash
cd apps/code-academy
python3 -m http.server 8011

# Or deploy to static hosting
# (Netlify, Vercel, GitHub Pages)
```

### PKN Mobile (Android/Termux)

```bash
# Deploy to phone via SSH
just deploy-mobile 192.168.1.100

# Or manually on phone
cd apps/pkn-mobile
export OPENAI_API_KEY=sk-...
python3 backend/server.py
```

See app-specific README files for detailed deployment instructions.

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [CLAUDE.md](CLAUDE.md) | AI assistant development guide |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture overview |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contribution guidelines |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues & solutions |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

### App-Specific Docs

- [apps/pkn/CLAUDE.md](apps/pkn/CLAUDE.md) - PKN development guide
- [apps/code-academy/CLAUDE.md](apps/code-academy/CLAUDE.md) - Code Academy guide
- [apps/pkn-mobile/CLAUDE.md](apps/pkn-mobile/CLAUDE.md) - Mobile PKN guide
- [apps/pkn-mobile/docs/DIFFERENCES.md](apps/pkn-mobile/docs/DIFFERENCES.md) - Desktop vs Mobile

## 🔧 Troubleshooting

### Common Issues

**Server won't start**
```bash
# Check port is free
lsof -i :8010
lsof -i :8011

# Kill existing processes
just stop

# Check logs
just logs-pkn
```

**Pre-commit hooks failing**
```bash
# Run hooks manually to see errors
just pre-commit-all

# Update hooks
just pre-commit-update

# Skip hooks (emergency only)
git commit --no-verify
```

**Import errors**
```bash
# Reinstall dependencies
just setup

# Or per-app
just setup-pkn
just setup-code-academy
```

**File size violations**
```bash
# Check which files are too large
just check-file-sizes

# Split large files into modules
# See ARCHITECTURE.md for patterns
```

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

**Quick Checklist:**
1. Run `just ci` before committing
2. Keep files under 200 lines
3. Write tests for new features
4. Update documentation
5. Follow existing code style

## 📜 License

MIT

## 🙏 Acknowledgments

Built with:
- **Flask** - Python web framework
- **llama.cpp** - Local LLM inference
- **Biome** - Fast linting & formatting
- **just** - Command runner
- **pnpm** - Fast package manager
- **pre-commit** - Git hooks framework
- **Rich** - Terminal UI library

---

**Maintained with ❤️ by the Divine Node team**

For questions or issues, see [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) or open an issue.
