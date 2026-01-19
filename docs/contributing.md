# Contributing

Thank you for your interest in contributing to `sigstore-a2a`!

## Development Setup

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager

### Clone and Install

```bash
git clone https://github.com/sigstore/sigstore-a2a.git
cd sigstore-a2a
uv sync --dev
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=sigstore_a2a

# Run specific test file
uv run pytest tests/test_models.py
```

### Linting and Formatting

```bash
# Run linter
uv run ruff check sigstore_a2a/ tests/

# Auto-fix issues
uv run ruff check --fix sigstore_a2a/ tests/

# Format code
uv run ruff format sigstore_a2a/ tests/

# Type checking
uv run mypy sigstore_a2a/
```

Or use the Makefile:

```bash
make lint
make format
```

## Building Documentation

```bash
# Install docs dependencies
uv sync --group docs

# Serve docs locally
uv run mkdocs serve

# Build docs
uv run mkdocs build
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with a descriptive message
6. Push to your fork
7. Open a Pull Request

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```
feat(signer): add support for custom OIDC client
fix(verifier): handle missing certificate extensions
docs: update API reference
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings (Google style)
- Keep functions focused and small

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

