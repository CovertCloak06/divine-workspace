# 🏗️ DIVINE NODE MASTER BUILD TEMPLATE

**COPY THIS FOR EVERY NEW PROJECT - NO EXCEPTIONS**

## ⚠️ MANDATORY: Use This Template For ALL Projects

This is THE CORRECT WAY to start any Divine Node project. No more asking, no more guessing.

---

## 🚀 Quick Start (New Project)

```bash
# 1. Clone this template
cp -r /home/gh0st/dvn/divine-workspace /home/gh0st/your-new-project

# 2. Setup
cd /home/gh0st/your-new-project
just setup

# 3. Start coding
just dev
```

---

## 📁 Monorepo Structure

```
divine-workspace/
├── apps/                           # All applications
│   ├── code-academy/               # Example: Code learning platform
│   ├── your-next-app/              # Add new apps here
│   └── another-app/
├── packages/                       # Shared packages
│   ├── shared-config/              # Shared configs (Biome, pre-commit)
│   ├── shared-ui/                  # Shared UI components
│   └── shared-utils/               # Shared utilities
├── .devcontainer/                  # VS Code DevContainer
│   ├── devcontainer.json
│   ├── docker-compose.yml
│   └── Dockerfile
├── .mise.toml                      # Tool version management
├── justfile                        # THE ONLY task runner
├── turbo.json                      # Turborepo configuration
├── pnpm-workspace.yaml             # pnpm workspace config
├── package.json                    # Root package.json
└── BUILD_TEMPLATE.md               # This file
```

---

## 🛠️ Tools Stack (NON-NEGOTIABLE)

### Core Tools
| Tool | Why | Installed |
|------|-----|-----------|
| **pnpm** | 3x faster than npm, strict mode | ✅ |
| **Turborepo** | Monorepo build system, caching | ✅ |
| **Biome** | 100x faster linter+formatter | ✅ |
| **just** | THE ONLY task runner | ✅ |
| **mise** | Tool version manager | ✅ |
| **pre-commit** | Git hooks (better than Husky) | ✅ |
| **DevContainer** | Reproducible dev environment | ✅ |

### NO MORE
- ❌ npm (use pnpm)
- ❌ Makefile (use just)
- ❌ Taskfile (use just)
- ❌ Invoke (use just)
- ❌ Husky (use pre-commit)
- ❌ ESLint+Prettier (use Biome)

---

## 🎯 Commands (just)

```bash
just                  # Show all commands
just setup            # Initial setup
just dev              # Start all dev servers
just dev-app <name>   # Start specific app
just build            # Build all apps
just build-app <name> # Build specific app
just test             # Run all tests
just lint             # Lint all code
just format           # Format all code
just ci               # Full CI check
just clean            # Remove artifacts
just health           # Check tools
just add-app <name>   # Create new app
just add-pkg <name>   # Create new package
```

---

## 📦 Adding a New App

```bash
# 1. Create app
just add-app my-new-app

# 2. Add package.json
cd apps/my-new-app
pnpm init

# 3. Add to name in package.json
{
  "name": "@divine/my-new-app",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "lint": "biome lint src/",
    "format": "biome format --write src/"
  }
}

# 4. Install dependencies
pnpm install

# 5. Start developing
just dev-app my-new-app
```

---

## 📦 Adding a Shared Package

```bash
# 1. Create package
just add-pkg shared-utils

# 2. Add package.json
cd packages/shared-utils
pnpm init

# 3. Set name
{
  "name": "@divine/shared-utils",
  "version": "1.0.0",
  "main": "index.js",
  "exports": {
    ".": "./index.js"
  }
}

# 4. Use in apps
# apps/code-academy/package.json
{
  "dependencies": {
    "@divine/shared-utils": "workspace:*"
  }
}
```

---

## 🔧 Shared Configurations

ALL apps inherit from `packages/shared-config`:

### Biome (Linting + Formatting)

```json
// apps/your-app/biome.json
{
  "extends": ["@divine/shared-config/biome.json"]
}
```

### pre-commit (Git Hooks)

```bash
# Root .pre-commit-config.yaml
# Symlink or copy from packages/shared-config/
ln -s packages/shared-config/.pre-commit-config.yaml .pre-commit-config.yaml
```

---

## 🐳 DevContainer Usage

### Open in VS Code

1. Install "Dev Containers" extension
2. Open workspace in VS Code
3. Command Palette → "Dev Containers: Reopen in Container"
4. Everything auto-installs, ready to code

### Benefits

- ✅ Same environment for everyone
- ✅ No "works on my machine"
- ✅ Auto-installs all tools
- ✅ Isolated from host system

---

## 🔄 Workflow

### Daily Development

```bash
# 1. Start dev server
just dev

# 2. Make changes
# ... edit code ...

# 3. Lint and format (auto on save in DevContainer)
just lint
just format

# 4. Test
just test

# 5. Commit (pre-commit hooks run automatically)
git add .
git commit -m "feat: add new feature"

# 6. Push
git push
```

### Before Pushing

```bash
# Run full CI locally
just ci

# If all passes, push
git push
```

---

## 🚢 Deployment

### Vercel

```bash
# Deploy specific app
just deploy-vercel code-academy
```

### Netlify

```bash
# Deploy specific app
just deploy-netlify code-academy
```

### Docker

```bash
# Build images
just docker-build

# Start containers
just docker-up
```

---

## 📐 Architecture Rules

### 1. **Monorepo Always**
- NEVER create standalone projects
- Always add to workspace

### 2. **Shared Configs**
- ONE Biome config for all
- ONE pre-commit config for all
- Apps extend, don't duplicate

### 3. **Workspace Dependencies**
- Use `workspace:*` for internal packages
- Share code via packages/

### 4. **File Size Limits**
- Max 200 lines per file
- Extract to packages/ if bigger
- Use `just lint` to check

### 5. **ONE Task Runner**
- Only `just`
- No Makefile, Taskfile, npm scripts for tasks
- npm scripts only for app-specific builds

---

## 🎓 Best Practices

### DO

- ✅ Use pnpm for everything
- ✅ Run `just ci` before pushing
- ✅ Keep files under 200 lines
- ✅ Share configs via packages/
- ✅ Use DevContainer
- ✅ Version tools with mise

### DON'T

- ❌ Use npm
- ❌ Create Makefiles
- ❌ Duplicate configs
- ❌ Create monolithic files
- ❌ Skip pre-commit hooks
- ❌ Add multiple task runners

---

## 🔍 Troubleshooting

### "pnpm not found"

```bash
npm install -g pnpm
```

### "just not found"

```bash
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin
```

### "mise not found"

```bash
curl https://mise.run | sh
```

### "DevContainer won't build"

```bash
# Rebuild without cache
just clean
# In VS Code: Dev Containers: Rebuild Container
```

### "Turborepo not caching"

```bash
# Clear Turbo cache
pnpm exec turbo run build --force
```

---

## 📚 References

- [pnpm Workspaces](https://pnpm.io/workspaces)
- [Turborepo Docs](https://turbo.build/repo/docs)
- [just Manual](https://just.systems/man/en/)
- [mise Documentation](https://mise.jdx.dev/)
- [Biome Documentation](https://biomejs.dev/)
- [pre-commit](https://pre-commit.com/)
- [DevContainers](https://containers.dev/)

---

## ✅ Checklist: Starting a New Project

- [ ] Copy this template
- [ ] Run `just setup`
- [ ] Open in DevContainer (VS Code)
- [ ] Create new app with `just add-app <name>`
- [ ] Configure app package.json
- [ ] Add app-specific dependencies
- [ ] Extend shared configs
- [ ] Run `just dev-app <name>`
- [ ] Make it awesome
- [ ] Run `just ci` before committing
- [ ] Deploy with `just deploy-vercel <app>`

---

## 🎯 This Is The Way

**NEVER deviate from this template.**

- If you need a new tool, add it here FIRST
- If you find a better tool, update this template
- If you're about to create a Makefile, STOP and use just
- If you're about to use npm, STOP and use pnpm

**This template is your source of truth. Use it religiously.**

---

_Last updated: 2026-01-11_
_Template version: 1.0.0_
