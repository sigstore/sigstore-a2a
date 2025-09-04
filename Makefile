# AgentUp Development Makefile
# Useful commands for testing, template generation, and development

.PHONY: help install install-dev check-deps test lint lint-fix format format-check
.PHONY: security build build-check dev-setup dev-test

# Default target
help: ## Show this help message
	@echo "AgentUp Development Commands"
	@echo "=========================="
	@echo ""
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Environment setup
install: ## Install dependencies with uv
	uv sync --all-extras
	@echo "Dependencies installed"

install-dev: ## Install development dependencies
	uv sync --all-extras --dev
	uv pip install -e .
	@echo "Development environment ready"

check-deps: ## Check for missing dependencies
	uv pip check
	@echo "All dependencies satisfied"


# Testing commands
test: ## Run all tests (unit + integration + e2e)
	@echo "Running comprehensive test suite..."
	uv run pytest tests/ -v

# Code quality
lint: ## Run linting checks
	uv run ruff check sigstore_a2a/ tests/

lint-fix: ## Fix linting issues automatically
	uv run ruff check --fix sigstore_a2a/ tests/
	uv run ruff format sigstore_a2a/ tests/

format: ## Format code with ruff
	uv run ruff format sigstore_a2a/ tests/

format-check: ## Check code formatting
	uv run ruff format --check sigstore_a2a/ tests/

# Security scanning
security: ## Run bandit security scan
	uv run bandit -r sigstore_a2a/ -ll

# Build and release
build: ## Build package
	uv build
	@echo "Package built in dist/"

build-check: ## Check package build
	uv run twine check dist/*

# Quick development workflows
dev-setup: install-dev ## Complete development setup
	@echo "Running complete development setup..."
	make check-deps
	make test-fast
	@echo "Development environment ready!"

dev-test: ## Quick development test cycle
	@echo "Running development test cycle..."
	make lint-fix
	make test-fast
	make template-test-syntax
	@echo "Development tests passed!"

