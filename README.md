# Divine Node Workspace

**THE MASTER TEMPLATE - Use this for ALL projects**

## 🚀 Quick Start

```bash
# Setup
just setup

# Develop
just dev

# Build
just build

# Deploy
just deploy-vercel <app-name>
```

## 📖 Full Documentation

See [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md) for complete documentation.

## 🛠️ Tools

- **pnpm**: Package manager (3x faster than npm)
- **Turborepo**: Monorepo build system with caching
- **just**: Task runner (THE ONLY ONE)
- **Biome**: Linter + Formatter (100x faster than ESLint+Prettier)
- **pre-commit**: Git hooks (better than Husky)
- **mise**: Tool version management
- **DevContainer**: Reproducible development environment

## 📁 Structure

```
apps/           # Applications
packages/       # Shared packages
.devcontainer/  # VS Code DevContainer
```

## 🎯 Commands

```bash
just              # List all commands
just dev          # Start all dev servers
just build        # Build all apps
just test         # Run all tests
just ci           # Full CI check
just clean        # Clean artifacts
just health       # Check tools
```

## 📚 Learn More

- [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md) - Complete guide
- [pnpm Workspaces](https://pnpm.io/workspaces)
- [Turborepo](https://turbo.build/repo/docs)
- [just](https://just.systems/man/en/)

---

**This is the way. Use it religiously.**
