# sigstore-a2a

**Keyless signing library for A2A Agent Cards using Sigstore and SLSA provenance.**

[![PyPI version](https://badge.fury.io/py/sigstore-a2a.svg)](https://badge.fury.io/py/sigstore-a2a)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

`sigstore-a2a` provides cryptographic signing and verification for [A2A (Agent-to-Agent) Protocol](https://google.github.io/A2A/) Agent Cards using [Sigstore's](https://sigstore.dev) keyless signing infrastructure.

### Key Features

- **Keyless Signing**: No need to manage private keys - uses Sigstore's OIDC-based signing
- **SLSA Provenance**: Optional build provenance attestations for supply chain security
- **CI/CD Integration**: Works seamlessly with GitHub Actions, GitLab CI, and other CI systems
- **Verification**: Cryptographic verification of Agent Card signatures with identity constraints

## Quick Example

### Signing an Agent Card

```python
from sigstore_a2a import AgentCardSigner

signer = AgentCardSigner()
signed_card = signer.sign_agent_card("agent-card.json")
```

### Verifying a Signed Agent Card

```python
from sigstore_a2a import AgentCardVerifier

verifier = AgentCardVerifier(
    identity="user@example.com",
    oidc_issuer="https://accounts.google.com"
)
result = verifier.verify_file("signed-agent-card.json")

if result.valid:
    print("Signature verified!")
```

### CLI Usage

```bash
# Sign an Agent Card
sigstore-a2a sign agent-card.json --output signed-card.json

# Verify a signed Agent Card
sigstore-a2a verify signed-card.json --identity-provider https://token.actions.githubusercontent.com

# Serve a signed Agent Card
sigstore-a2a serve signed-card.json --port 8080
```

## Installation

```bash
pip install sigstore-a2a
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv add sigstore-a2a
```

## Next Steps

- [Getting Started](getting-started.md) - Detailed setup and usage guide
- [CLI Reference](cli.md) - Complete CLI documentation
- [API Reference](api/index.md) - Python API documentation

