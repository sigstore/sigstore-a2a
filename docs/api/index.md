# API Reference

This section contains the Python API documentation for `sigstore-a2a`.

## Core Classes

The library provides three main classes:

### [AgentCardSigner](signer.md)

Signs A2A Agent Cards using Sigstore keyless signing.

```python
from sigstore_a2a import AgentCardSigner

signer = AgentCardSigner()
signed_card = signer.sign_agent_card("agent-card.json")
```

### [AgentCardVerifier](verifier.md)

Verifies signed A2A Agent Cards.

```python
from sigstore_a2a import AgentCardVerifier

verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com"
)
result = verifier.verify_file("signed-card.json")
```

### [ProvenanceBuilder](models.md#provenancebuilder)

Builds SLSA provenance attestations.

```python
from sigstore_a2a import ProvenanceBuilder

provenance = ProvenanceBuilder().from_github_actions().build()
```

## Module Structure

```
sigstore_a2a/
├── __init__.py          # Main exports
├── signer.py            # AgentCardSigner
├── verifier.py          # AgentCardVerifier
├── provenance.py        # ProvenanceBuilder
├── cli/                 # CLI implementation
│   ├── main.py
│   ├── sign.py
│   ├── verify.py
│   └── serve.py
├── models/              # Data models
│   ├── agent_card.py
│   ├── signature.py
│   └── provenance.py
└── utils/               # Utilities
    ├── ci.py
    └── crypto.py
```

## Quick Links

- [AgentCardSigner](signer.md) - Signing API
- [AgentCardVerifier](verifier.md) - Verification API  
- [Models](models.md) - Data models and types

