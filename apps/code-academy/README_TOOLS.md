# 🛠️ Development Tools Guide

This project uses **best-in-class tools** for maximum productivity and quality.

## Quick Start

```bash
# Install everything
task setup              # or: invoke setup

# Start development
task dev                # or: npm run dev

# Run tests
task test               # or: npm test

# Full CI check (run before pushing)
task ci                 # or: invoke ci
```

## 📦 Tool Stack

### Core Tools (JavaScript)

| Tool | Purpose | Why Best? |
|------|---------|-----------|
| **Biome** | Linting + Formatting | 100x faster than ESLint+Prettier combined |
| **Vite** | Build tool | Fastest, esbuild-based |
| **Vitest** | Unit testing | Fast, Vite-native |
| **Playwright** | E2E testing | Modern, reliable, multi-browser |
| **Plop** | Code generation | Industry standard scaffolding |

### Automation Tools (Python)

| Tool | Purpose | Why Best? |
|------|---------|-----------|
| **pre-commit** | Git hooks | Language-agnostic, better than Husky |
| **Taskfile** | Task automation | Modern, Go-based, better than Make |
| **Invoke** | Python tasks | More flexible than shell scripts |
| **Cookiecutter** | Project templates | Industry standard |

### Deployment

| Platform | Use Case | Deploy Command |
|----------|----------|----------------|
| **Vercel** | Production | `npm run deploy:vercel` |
| **Netlify** | Alternative | `npm run deploy:netlify` |
| **Docker** | Containers | `task docker:up` |

## 🚀 Available Commands

### Task (Recommended)

```bash
task                    # Show all available tasks
task install            # Install dependencies
task dev                # Start dev server
task build              # Production build
task test               # Run all tests
task lint               # Lint code
task format             # Format code
task clean              # Clean artifacts
task docker:build       # Build Docker image
task docker:up          # Start containers
task ci                 # Full CI check locally
task health             # Check tool versions
```

### Invoke (Python)

```bash
invoke --list           # List all tasks
invoke dev              # Start dev server
invoke build            # Production build
invoke test             # Run tests
invoke lint --fix       # Lint and auto-fix
invoke format-code      # Format code
invoke ci               # Full CI check
invoke docker-build     # Build Docker image
invoke security         # Security audit
invoke health           # Health check
```

### Make (Legacy compatibility)

```bash
make help               # Show available commands
make dev                # Start development
make build              # Production build
make test               # Run tests
make docker-up          # Start Docker
```

### npm scripts

```bash
npm run dev             # Start dev server
npm run build           # Production build
npm test                # Run unit tests
npm run test:e2e        # Run E2E tests
npm run lint            # Lint with Biome
npm run format          # Format with Biome
npm run generate        # Generate code
```

## 🔧 Code Generation

### Generate Component

```bash
task generate:component
# or
npm run generate:component
```

Generates:
- `src/[type]s/ComponentName.js`
- `tests/unit/ComponentName.test.js`

### Generate Lesson

```bash
task generate:lesson
# or
npm run generate:lesson
```

Generates:
- `lessons/[category]/lesson-id.json`

## 🐳 Docker

### Development

```bash
task docker:dev
# or
docker-compose --profile dev up
```

### Production

```bash
task docker:build      # Build image
task docker:up         # Start containers
task docker:logs       # View logs
task docker:down       # Stop containers
```

## 🔒 Git Hooks (pre-commit)

Automatically runs on commit:
- Biome linting and formatting
- JSON/YAML validation
- Secret detection
- Conventional commit validation

### Manual execution

```bash
pre-commit run --all-files          # Run all hooks
task pre-commit                     # Same thing
pre-commit autoupdate               # Update hook versions
```

## 🚢 Deployment

### Vercel

```bash
npm run deploy:vercel
# or
task deploy:vercel
# or
invoke deploy-vercel
```

### Netlify

```bash
npm run deploy:netlify
# or
invoke deploy-netlify
```

### Docker Production

```bash
task docker:build
task docker:up
```

Accessible at `http://localhost:8011`

## 📊 Health Check

Check all tools are installed:

```bash
task health
# or
invoke health
```

Expected output:
```
✅ Node.js          v20.x.x
✅ npm              10.x.x
✅ Python           3.10.x
✅ pre-commit       4.5.1
✅ task             3.46.4
✅ invoke           2.2.1
```

## 🔄 CI/CD

### Local CI Check (before pushing)

```bash
task ci
# or
invoke ci
```

Runs:
1. Lint
2. Format check
3. Tests (unit + E2E)
4. Production build

### GitHub Actions

Automatically runs on push:
- Lint Code
- Run Tests
- E2E Tests
- Build Application
- Security Audit
- Lighthouse CI
- Accessibility Tests

## 📝 Workflow Examples

### Adding a new feature

```bash
# 1. Generate component
task generate:component

# 2. Develop with hot reload
task dev

# 3. Run tests
task test

# 4. Full CI check
task ci

# 5. Commit (hooks run automatically)
git add .
git commit -m "feat: add new component"

# 6. Push
git push
```

### Deploying

```bash
# Option 1: Vercel
npm run deploy:vercel

# Option 2: Netlify
npm run deploy:netlify

# Option 3: Docker
task docker:build
task docker:up
```

## 🆘 Troubleshooting

### pre-commit not running

```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

### Task not found

```bash
# Install task
curl -sL https://taskfile.dev/install.sh | sh -s -- -b ~/.local/bin
```

### Python tools not found

```bash
pip3 install --user -r requirements.txt
```

## 📚 Further Reading

- [Biome Documentation](https://biomejs.dev/)
- [Vite Documentation](https://vitejs.dev/)
- [pre-commit Documentation](https://pre-commit.com/)
- [Taskfile Documentation](https://taskfile.dev/)
- [Invoke Documentation](https://www.pyinvoke.org/)
- [Playwright Documentation](https://playwright.dev/)
- [Vercel Documentation](https://vercel.com/docs)
- [Netlify Documentation](https://docs.netlify.com/)

---

**Remember:** These are the BEST tools available. No upgrades or replacements needed.
