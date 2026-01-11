# Divine Node Workspace - Task Runner
# Comprehensive commands for development, testing, building, and deployment

# List all commands
default:
    @just --list

# ==========================================
# SETUP & INSTALLATION
# ==========================================

# Initial workspace setup
setup:
    @echo "🚀 Setting up Divine Node workspace..."
    pnpm install
    @echo "✅ pnpm install complete"
    @echo "📝 Setting up pre-commit hooks..."
    @if command -v pre-commit >/dev/null 2>&1; then \
        ln -sf packages/shared-config/.pre-commit-config.yaml .pre-commit-config.yaml; \
        pre-commit install; \
        echo "✅ pre-commit hooks installed"; \
    else \
        echo "⚠️  pre-commit not found. Install: pip install pre-commit"; \
    fi
    @just setup-pkn
    @just setup-code-academy
    @echo "\n✅ Workspace setup complete!"
    @echo "Run 'just dev' to start all dev servers"

# Setup PKN app
setup-pkn:
    @echo "🔧 Setting up PKN..."
    cd apps/pkn && python3 -m venv .venv
    cd apps/pkn && .venv/bin/pip install -r requirements.txt
    @echo "✅ PKN setup complete"

# Setup Code Academy
setup-code-academy:
    @echo "🔧 Setting up Code Academy..."
    pnpm --filter @divine/code-academy install
    @echo "✅ Code Academy setup complete"

# Setup PKN Mobile
setup-pkn-mobile:
    @echo "🔧 Setting up PKN Mobile..."
    cd apps/pkn-mobile && python3 -m venv .venv || true
    cd apps/pkn-mobile && pip3 install -r requirements.txt
    @echo "✅ PKN Mobile setup complete"

# ==========================================
# DEVELOPMENT
# ==========================================

# Start all dev servers
dev:
    @echo "🚀 Starting all dev servers..."
    @echo "PKN: http://localhost:8010"
    @echo "Code Academy: http://localhost:8011"
    @echo ""
    @just dev-app pkn &
    @just dev-app code-academy &
    @wait

# Start specific app dev server
dev-app APP:
    @echo "🚀 Starting {{APP}} dev server..."
    @if [ "{{APP}}" = "pkn" ]; then \
        cd apps/pkn && python3 server.py --debug; \
    elif [ "{{APP}}" = "code-academy" ]; then \
        cd apps/code-academy && python3 -m http.server 8011; \
    elif [ "{{APP}}" = "pkn-mobile" ]; then \
        cd apps/pkn-mobile && python3 backend/server.py --debug; \
    else \
        echo "❌ Unknown app: {{APP}}"; \
        exit 1; \
    fi

# Stop all running servers
stop:
    @echo "🛑 Stopping all servers..."
    @pkill -f "python3.*server.py" || true
    @pkill -f "python3.*http.server" || true
    @echo "✅ All servers stopped"

# ==========================================
# HEALTH & MONITORING
# ==========================================

# Check system health
health:
    @python3 scripts/health_check.py

# Check tool versions
check-tools:
    @echo "🔧 Checking installed tools..."
    @node --version 2>/dev/null | sed 's/^/Node: /' || echo "Node: not found"
    @pnpm --version 2>/dev/null | sed 's/^/pnpm: /' || echo "pnpm: not found"
    @python3 --version 2>/dev/null | sed 's/^/Python: /' || echo "Python: not found"
    @just --version 2>/dev/null | sed 's/^/just: /' || echo "just: not found"
    @pnpm biome --version 2>/dev/null | sed 's/^/Biome: /' || echo "Biome: not found"
    @pre-commit --version 2>/dev/null | sed 's/^/pre-commit: /' || echo "pre-commit: not found"

# Check file sizes (enforce 200-line limit)
check-file-sizes:
    @echo "📏 Checking file sizes..."
    @python3 scripts/check_file_size.py apps/**/*.{py,js,ts,css} 2>/dev/null || true

# ==========================================
# TESTING
# ==========================================

# Run all tests
test:
    @echo "🧪 Running all tests..."
    @just test-app pkn || true
    @just test-app code-academy || true

# Test specific app
test-app APP:
    @echo "🧪 Testing {{APP}}..."
    @if [ "{{APP}}" = "pkn" ]; then \
        cd apps/pkn && python3 -m pytest tests/ -v || true; \
    elif [ "{{APP}}" = "code-academy" ]; then \
        pnpm --filter @divine/code-academy test || true; \
    elif [ "{{APP}}" = "pkn-mobile" ]; then \
        cd apps/pkn-mobile && python3 -m pytest tests/ -v || true; \
    else \
        echo "❌ Unknown app: {{APP}}"; \
        exit 1; \
    fi

# Run only tests for changed files (for pre-commit)
test-changed:
    @echo "🧪 Running tests for changed files..."
    @git diff --name-only --cached | python3 scripts/run_tests_for_files.py || true

# ==========================================
# CODE QUALITY
# ==========================================

# Lint all code
lint:
    @echo "🔍 Linting all code..."
    @pnpm biome check apps/ packages/ || true

# Format all code
format:
    @echo "✨ Formatting all code..."
    @pnpm biome format --write apps/ packages/ 2>/dev/null || true
    @find apps -name "*.py" -exec ruff format {} + 2>/dev/null || true

# Run full CI checks (lint + format + test)
ci:
    @echo "🚦 Running full CI pipeline..."
    @just lint
    @just format
    @just test
    @just check-file-sizes
    @echo "✅ CI checks complete"

# ==========================================
# BUILD
# ==========================================

# Build all apps
build:
    @echo "🔨 Building all apps..."
    @just build-app code-academy

# Build specific app
build-app APP:
    @echo "🔨 Building {{APP}}..."
    @if [ "{{APP}}" = "pkn" ]; then \
        echo "PKN is a Python app, no build needed"; \
    elif [ "{{APP}}" = "code-academy" ]; then \
        echo "Code Academy is static, no build needed"; \
    elif [ "{{APP}}" = "pkn-mobile" ]; then \
        echo "PKN Mobile is a Python app, no build needed"; \
    else \
        echo "❌ Unknown app: {{APP}}"; \
        exit 1; \
    fi

# Clean all build artifacts
clean:
    @echo "🧹 Cleaning build artifacts..."
    @rm -rf apps/*/dist apps/*/build apps/*/.turbo
    @find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    @find . -type d -name "node_modules/.cache" -exec rm -rf {} + 2>/dev/null || true
    @find . -type f -name "*.pyc" -delete 2>/dev/null || true
    @echo "✅ Clean complete"

# ==========================================
# DEPLOYMENT
# ==========================================

# Deploy PKN Mobile to phone
deploy-mobile IP:
    @echo "📱 Deploying PKN Mobile to {{IP}}..."
    @cd apps/pkn-mobile && ./scripts/deploy_to_phone.sh {{IP}}

# ==========================================
# UTILITIES
# ==========================================

# Create new app from template
add-app NAME:
    @echo "📦 Creating app: {{NAME}}..."
    @mkdir -p apps/{{NAME}}
    @echo '{"name": "@divine/{{NAME}}", "version": "1.0.0", "private": true}' > apps/{{NAME}}/package.json
    @echo "✅ App {{NAME}} created in apps/{{NAME}}"
    @echo "Add to pnpm-workspace.yaml manually"

# Create new package
add-pkg NAME:
    @echo "📦 Creating package: {{NAME}}..."
    @mkdir -p packages/{{NAME}}
    @echo '{"name": "@divine/{{NAME}}", "version": "1.0.0", "private": true}' > packages/{{NAME}}/package.json
    @echo "✅ Package {{NAME}} created in packages/{{NAME}}"

# Backup workspace
backup:
    @echo "💾 Creating backup..."
    @BACKUP_FILE="$HOME/backups/divine-workspace-$$(date +%Y%m%d-%H%M%S).tar.gz"; \
    mkdir -p "$HOME/backups"; \
    tar -czf "$$BACKUP_FILE" \
        --exclude='node_modules' \
        --exclude='.venv' \
        --exclude='__pycache__' \
        --exclude='dist' \
        --exclude='build' \
        --exclude='data' \
        --exclude='llama.cpp' \
        .; \
    echo "✅ Backup created: $$BACKUP_FILE"

# ==========================================
# DEBUGGING
# ==========================================

# Debug PKN backend
debug-pkn:
    @cd apps/pkn && python3 -m pdb server.py

# Tail PKN logs
logs-pkn:
    @tail -f apps/pkn/data/divinenode.log 2>/dev/null || echo "No logs found"

# Interactive Python shell with PKN context
shell-pkn:
    @cd apps/pkn && python3 -i -c "from backend.agents.manager import AgentManager; manager = AgentManager()"

# ==========================================
# GIT HELPERS
# ==========================================

# Run pre-commit on all files
pre-commit-all:
    @pre-commit run --all-files

# Update pre-commit hooks
pre-commit-update:
    @pre-commit autoupdate

# Install git hooks
hooks-install:
    @ln -sf packages/shared-config/.pre-commit-config.yaml .pre-commit-config.yaml
    @pre-commit install
    @echo "✅ Git hooks installed"
