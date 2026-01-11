# CLAUDE.md - Divine Node Workspace

**READ THIS BEFORE MAKING ANY CHANGES**

## ⚠️ ABSOLUTE RULES - NO EXCEPTIONS

### 1. **ALWAYS USE THIS MONOREPO TEMPLATE**
- NEVER create standalone projects
- ALWAYS use `/home/gh0st/dvn/divine-workspace` as the template
- Copy it for new projects, don't create from scratch

### 2. **BEST TOOLS ONLY - FIRST TIME**
This template has THE BEST tools. If you find something better:
1. Update THIS template FIRST
2. Document why it's better
3. Then use it everywhere

### 3. **NO REDUNDANCY**
- ONE task runner: `just`
- ONE linter: `Biome`
- ONE package manager: `pnpm`
- NO exceptions

### 4. **MONOREPO STRUCTURE**
```
divine-workspace/
├── apps/              # Applications (code-academy, pkn, etc.)
├── packages/          # Shared code (configs, UI, utils)
├── .devcontainer/     # Dev environment
├── justfile           # THE ONLY task runner
├── turbo.json         # Build configuration
└── pnpm-workspace.yaml
```

### 5. **FILE SIZE LIMIT: 200 LINES**
- If a file exceeds 200 lines, STOP
- Extract to separate modules
- Move to packages/ if shared
- NO EXCEPTIONS

## 🛠️ Tools Stack (LOCKED IN)

| Category | Tool | Why | Status |
|----------|------|-----|--------|
| Package Manager | pnpm | 3x faster than npm | ✅ |
| Build System | Turborepo | Monorepo caching | ✅ |
| Linter/Formatter | Biome | 100x faster than ESLint | ✅ |
| Task Runner | just | Simple, fast | ✅ |
| Git Hooks | pre-commit | Better than Husky | ✅ |
| Tool Versions | mise | Multi-tool manager | ✅ |
| Dev Environment | DevContainer | Reproducible | ✅ |

## 🚫 BANNED TOOLS

- ❌ npm (use pnpm)
- ❌ ESLint + Prettier (use Biome)
- ❌ Husky (use pre-commit)
- ❌ Makefile (use just)
- ❌ Taskfile (use just)
- ❌ Invoke (use just)

## 📋 Workflow

### Adding a New App

```bash
just add-app my-app
cd apps/my-app
# Setup package.json
pnpm install
just dev-app my-app
```

### Adding Shared Code

```bash
just add-pkg shared-utils
cd packages/shared-utils
# Create code
# Use in apps with @divine/shared-utils
```

### Daily Development

```bash
just dev          # Start all dev servers
# ... make changes ...
just ci           # Run all checks before committing
git commit        # pre-commit hooks run automatically
```

## 🏗️ Architecture Principles

### 1. **Shared Configs**
ALL configs live in `packages/shared-config/`:
- biome.json
- .pre-commit-config.yaml
- tsconfig.json

Apps EXTEND, never duplicate.

### 2. **Workspace Dependencies**
```json
{
  "dependencies": {
    "@divine/shared-utils": "workspace:*"
  }
}
```

### 3. **Turborepo Caching**
- All builds cached
- Only rebuild what changed
- Share cache across machines (future)

## 🎯 Commands Reference

```bash
just                     # List all commands
just setup               # Initial setup
just dev                 # All dev servers
just dev-app <name>      # Single app
just build               # Build all
just build-app <name>    # Build one
just test                # Test all
just lint                # Lint all
just format              # Format all
just ci                  # Full CI
just clean               # Remove artifacts
just health              # Check tools
just add-app <name>      # New app
just add-pkg <name>      # New package
just deploy-vercel <app> # Deploy
```

## 📖 Required Reading

1. [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md) - Master template guide
2. [Turborepo Docs](https://turbo.build/repo/docs)
3. [pnpm Workspaces](https://pnpm.io/workspaces)

## 🔄 Migration Path

### Moving Existing Projects

```bash
# 1. Copy project to apps/
cp -r /path/to/old-project apps/new-name

# 2. Update package.json name
{
  "name": "@divine/new-name"
}

# 3. Remove old tooling
rm -rf node_modules package-lock.json
rm Makefile Taskfile.yml tasks.py

# 4. Install with pnpm
pnpm install

# 5. Extend shared configs
# apps/new-name/biome.json
{
  "extends": ["@divine/shared-config/biome.json"]
}

# 6. Test
just dev-app new-name
```

## ✅ Pre-Push Checklist

Before EVERY push:

```bash
just ci
```

This runs:
1. Lint (Biome)
2. Format check
3. Tests (all)
4. Build (all)

If it passes, you're good to push.

## 🚨 Common Mistakes

### ❌ Creating standalone projects
**Don't**: `mkdir my-new-project && cd my-new-project && npm init`
**Do**: `just add-app my-new-project`

### ❌ Duplicating configs
**Don't**: Copy biome.json to every app
**Do**: Extend from @divine/shared-config

### ❌ Using multiple task runners
**Don't**: Create Makefile + Taskfile + package scripts
**Do**: Use `just` only

### ❌ Monolithic files
**Don't**: Keep 1000-line files
**Do**: Split at 200 lines, extract to packages/

## 🎓 Philosophy

### Why Monorepo?
- Share code easily
- Update deps once, affects all
- Build only what changed
- Deploy everything together
- ONE source of truth

### Why These Tools?
- **pnpm**: Fastest, strictest, disk-efficient
- **Turborepo**: Best monorepo tooling
- **Biome**: Fastest linter+formatter, one tool
- **just**: Simplest task runner
- **pre-commit**: Best git hooks
- **mise**: Manages all tool versions
- **DevContainer**: Perfect reproducibility

### Why Strict Rules?
- No analysis paralysis
- No tool proliferation
- No config drift
- No "works on my machine"
- Maximum productivity

## 📞 When in Doubt

1. Read [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md)
2. Run `just health` to check tools
3. Run `just ci` before committing
4. Don't deviate from the template

---

**THIS IS THE WAY. NO EXCEPTIONS.**

_Last updated: 2026-01-11_
