# AgentCardVerifier

The `AgentCardVerifier` class provides methods for verifying signed A2A Agent Cards using Sigstore.

## Overview

```python
from sigstore_a2a import AgentCardVerifier

verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com"
)
result = verifier.verify_file("signed-card.json")

if result.valid:
    print("Signature verified!")
```

## API Reference

::: sigstore_a2a.verifier.AgentCardVerifier
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - verify_signed_card
        - verify_file

::: sigstore_a2a.verifier.IdentityConstraints
    options:
      show_root_heading: true
      show_source: true

::: sigstore_a2a.verifier.VerificationResult
    options:
      show_root_heading: true
      show_source: true

## Usage Examples

### Basic Verification

```python
from sigstore_a2a import AgentCardVerifier

verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com"
)

result = verifier.verify_file("signed-card.json")

if result.valid:
    print("✓ Signature verified!")
    print(f"  Agent: {result.agent_card.name}")
    print(f"  Signed by: {result.identity.get('subject')}")
else:
    print("✗ Verification failed:")
    for error in result.errors:
        print(f"  - {error}")
```

### Verification with Constraints

```python
from sigstore_a2a import AgentCardVerifier
from sigstore_a2a.verifier import IdentityConstraints

verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com"
)

# Define constraints
constraints = IdentityConstraints(
    repository="sigstore/sigstore-a2a",
    workflow="Release"
)

result = verifier.verify_file("signed-card.json", constraints)
```

### Verifying with Google Identity

```python
verifier = AgentCardVerifier(
    identity="user@example.com",
    oidc_issuer="https://accounts.google.com"
)

result = verifier.verify_file("signed-card.json")
```

### Using Staging Environment

```python
verifier = AgentCardVerifier(
    oidc_issuer="https://token.actions.githubusercontent.com",
    staging=True
)
```

### Using Custom Trust Configuration

```python
from pathlib import Path

verifier = AgentCardVerifier(
    oidc_issuer="https://my-idp.example.com",
    trust_config=Path("/path/to/trust-config.json")
)
```

### Extracting Identity Information

```python
result = verifier.verify_file("signed-card.json")

if result.valid:
    identity = result.identity
    
    print(f"Issuer: {identity.get('issuer')}")
    print(f"Subject: {identity.get('subject')}")
    print(f"Repository: {identity.get('github_workflow_repository')}")
    print(f"Workflow: {identity.get('github_workflow_name')}")
    print(f"Commit SHA: {identity.get('github_workflow_sha')}")
```

## Identity Providers

Common OIDC issuers for verification:

| Provider | Issuer URL |
|----------|-----------|
| GitHub Actions | `https://token.actions.githubusercontent.com` |
| Google | `https://accounts.google.com` |
| Microsoft | `https://login.microsoftonline.com/{tenant}/v2.0` |
| GitLab | `https://gitlab.com` |

