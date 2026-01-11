.PHONY: help install dev build test lint format clean docker-build docker-up docker-down release

# Default target
help:
	@echo "Divine Node Code Academy - Available Commands:"
	@echo ""
	@echo "  make install       - Install dependencies"
	@echo "  make dev           - Start development server"
	@echo "  make build         - Build for production"
	@echo "  make test          - Run all tests"
	@echo "  make lint          - Lint code"
	@echo "  make format        - Format code"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-up     - Start Docker containers"
	@echo "  make docker-down   - Stop Docker containers"
	@echo "  make release       - Create a release"
	@echo ""

# Install dependencies
install:
	npm ci

# Development server
dev:
	npm run dev

# Production build
build:
	npm run build

# Run all tests
test:
	npm run test
	npm run test:e2e

# Lint code
lint:
	npm run lint

# Format code
format:
	npm run format

# Clean build artifacts
clean:
	rm -rf dist build coverage playwright-report .nyc_output
	find . -name "*.log" -type f -delete

# Docker commands
docker-build:
	docker-compose build app

docker-up:
	docker-compose up -d app

docker-down:
	docker-compose down

docker-dev:
	docker-compose --profile dev up dev

# Release
release:
	npm run release

# Full CI check (run before pushing)
ci-check: lint test build
	@echo "✅ All CI checks passed!"
