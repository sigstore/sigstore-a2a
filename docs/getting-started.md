# Getting Started

This guide will help you get started with `sigstore-a2a` for signing and verifying A2A Agent Cards.

## Installation

### Using pip

```bash
pip install sigstore-a2a
```

### Using uv (recommended)

```bash
uv add sigstore-a2a
```

### From source

```bash
git clone https://github.com/sigstore/sigstore-a2a.git
cd sigstore-a2a
uv sync
```

## Basic Concepts

### What is an Agent Card?

An Agent Card is a JSON document that describes an A2A (Agent-to-Agent) protocol agent. It contains metadata about the agent's capabilities, endpoints, and authentication requirements.

### Why Sign Agent Cards?

Signing Agent Cards provides:

1. **Authenticity**: Verify the Agent Card comes from a trusted source
2. **Integrity**: Detect any tampering with the Agent Card
3. **Non-repudiation**: The signer cannot deny having signed the card
4. **Supply Chain Security**: Track provenance of Agent Cards

### Keyless Signing with Sigstore

`sigstore-a2a` uses [Sigstore](https://sigstore.dev) for keyless signing:

- No private keys to manage or rotate
- Identity-based signing using OIDC (OpenID Connect)
- Signatures are logged to a transparency log (Rekor)
- Certificates are issued by Fulcio CA

## Signing an Agent Card

### Using the CLI

```bash
# Basic signing (will prompt for authentication)
sigstore-a2a sign agent-card.json

# Sign with a specific output path
sigstore-a2a sign agent-card.json --output signed-card.json

# Sign using ambient CI credentials (in GitHub Actions, GitLab CI, etc.)
sigstore-a2a sign agent-card.json --use_ambient_credentials

# Sign with SLSA provenance
sigstore-a2a sign agent-card.json --provenance --repository owner/repo
```

### Using the Python API

```python
from sigstore_a2a import AgentCardSigner

# Create a signer
signer = AgentCardSigner()

# Sign from a file
signed_card = signer.sign_agent_card("agent-card.json")

# Or sign from a dictionary
card_data = {
    "name": "My Agent",
    "url": "https://agent.example.com",
    # ... other fields
}
signed_card = signer.sign_agent_card(card_data)

# Save the signed card
import json
with open("signed-card.json", "w") as f:
    json.dump(signed_card.model_dump(by_alias=True), f, indent=2)
```

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Sign Agent Card
  run: |
    sigstore-a2a sign agent-card.json \
      --use_ambient_credentials \
      --output signed-card.json \
      --repository ${{ github.repository }}
```

## Verifying a Signed Agent Card

### Using the CLI

```bash
# Basic verification
sigstore-a2a verify signed-card.json \
  --identity-provider https://token.actions.githubusercontent.com

# Verify with repository constraint
sigstore-a2a verify signed-card.json \
  --identity-provider https://token.actions.githubusercontent.com \
  --repository owner/repo

# Verify with workflow constraint
sigstore-a2a verify signed-card.json \
  --identity-provider https://token.actions.githubusercontent.com \
  --repository owner/repo \
  --workflow "Release"
```

### Using the Python API

```python
from sigstore_a2a import AgentCardVerifier
from sigstore_a2a.verifier import IdentityConstraints

# Create a verifier
verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com"
)

# Define constraints
constraints = IdentityConstraints(
    repository="owner/repo",
    workflow="Release"
)

# Verify the signed card
result = verifier.verify_file("signed-card.json", constraints)

if result.valid:
    print("✓ Signature verified!")
    print(f"  Signed by: {result.identity.get('subject')}")
else:
    print("✗ Verification failed:")
    for error in result.errors:
        print(f"  - {error}")
```

## Serving a Signed Agent Card

The `serve` command starts an HTTP server that serves the Agent Card at the standard A2A discovery endpoints:

```bash
sigstore-a2a serve signed-card.json --host 0.0.0.0 --port 8080
```

This makes the Agent Card available at:

- `/.well-known/agent.json` - The Agent Card (without signature)
- `/.well-known/agent.signed.json` - The complete signed Agent Card

## Staging vs Production

By default, `sigstore-a2a` uses Sigstore's production infrastructure. For testing, you can use the staging environment:

```bash
# CLI
sigstore-a2a sign agent-card.json --staging

# Python
signer = AgentCardSigner(staging=True)
verifier = AgentCardVerifier(staging=True)
```

!!! warning "Staging Environment"
    The staging environment is for testing only. Signatures created in staging should not be used in production.

## Custom Trust Configuration

For private Sigstore deployments (e.g., [RHTAS](https://www.redhat.com/en/technologies/cloud-computing/red-hat-trusted-artifact-signer)), you can provide a custom trust configuration:

```bash
sigstore-a2a sign agent-card.json --trust_config /path/to/trust-config.json
```

```python
from pathlib import Path

signer = AgentCardSigner(trust_config=Path("/path/to/trust-config.json"))
```

