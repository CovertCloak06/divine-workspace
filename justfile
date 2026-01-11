# Divine Node Workspace - Master Justfile
# THE ONLY TASK RUNNER - All others removed

# Default: Show available commands
default:
    @just --list

# Setup: Initial project setup
setup:
    @echo "📦 Installing pnpm if needed..."
    @command -v pnpm >/dev/null 2>&1 || npm install -g pnpm
    @echo "📥 Installing dependencies..."
    pnpm install
    @echo "🔧 Installing git hooks..."
    pnpm exec pre-commit install
    pnpm exec pre-commit install --hook-type commit-msg
    @echo "✅ Setup complete!"

# Dev: Start all development servers
dev:
    pnpm dev

# Dev specific app
dev-app app:
    pnpm --filter {{app}} dev

# Build: Build all apps
build:
    pnpm build

# Build specific app
build-app app:
    pnpm --filter {{app}} build

# Test: Run all tests
test:
    pnpm test

# Test specific app
test-app app:
    pnpm --filter {{app}} test

# Lint: Lint all code
lint:
    pnpm lint

# Lint specific app
lint-app app:
    pnpm --filter {{app}} lint

# Format: Format all code
format:
    pnpm format

# Format specific app
format-app app:
    pnpm --filter {{app}} format

# Clean: Remove build artifacts
clean:
    @echo "🧹 Cleaning..."
    rm -rf apps/*/dist apps/*/build apps/*/.next
    rm -rf packages/*/dist packages/*/build
    rm -rf node_modules apps/*/node_modules packages/*/node_modules
    @echo "✅ Clean complete!"

# CI: Run full CI checks
ci:
    pnpm lint
    pnpm format:check
    pnpm test
    pnpm build

# Docker: Build all Docker images
docker-build:
    @echo "🐳 Building Docker images..."
    @for app in apps/*; do \
        if [ -f "$$app/Dockerfile" ]; then \
            echo "Building $$app..."; \
            docker build -t $$(basename $$app) $$app; \
        fi \
    done

# Docker: Start all containers
docker-up:
    docker-compose up -d

# Docker: Stop all containers
docker-down:
    docker-compose down

# Deploy: Deploy specific app to Vercel
deploy-vercel app:
    pnpm --filter {{app}} deploy:vercel

# Deploy: Deploy specific app to Netlify
deploy-netlify app:
    pnpm --filter {{app}} deploy:netlify

# Health: Check all tools
health:
    @echo "📊 Tool Health Check"
    @echo "Node:     $(node --version)"
    @echo "pnpm:     $(pnpm --version)"
    @echo "Python:   $(python3 --version)"
    @echo "mise:     $(mise --version)"
    @echo "just:     $(just --version)"
    @echo "turbo:    $(pnpm exec turbo --version)"
    @echo "✅ All tools installed"

# Add: Create new app from template
add-app name:
    @echo "🚀 Creating new app: {{name}}"
    mkdir -p apps/{{name}}
    @echo "✅ App created at apps/{{name}}"

# Add: Create new package
add-pkg name:
    @echo "📦 Creating new package: {{name}}"
    mkdir -p packages/{{name}}
    @echo "✅ Package created at packages/{{name}}"

# Update: Update all dependencies
update:
    pnpm update -r

# Graph: Show dependency graph
graph:
    pnpm exec turbo run build --graph

# Prune: Remove unused dependencies
prune:
    pnpm prune
