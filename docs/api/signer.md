# AgentCardSigner

The `AgentCardSigner` class provides methods for signing A2A Agent Cards using Sigstore's keyless signing infrastructure.

## Overview

```python
from sigstore_a2a import AgentCardSigner

# Create a signer with default settings
signer = AgentCardSigner()

# Sign an agent card
signed_card = signer.sign_agent_card("agent-card.json")
```

## API Reference

::: sigstore_a2a.signer.AgentCardSigner
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - sign_agent_card
        - sign_file

## Usage Examples

### Basic Signing

```python
from sigstore_a2a import AgentCardSigner

signer = AgentCardSigner()

# Sign from a file path
signed_card = signer.sign_agent_card("agent-card.json")

# Sign from a dictionary
card_data = {
    "name": "My Agent",
    "url": "https://agent.example.com",
    "protocolVersion": "0.2.9"
}
signed_card = signer.sign_agent_card(card_data)
```

### Using Ambient Credentials (CI/CD)

```python
signer = AgentCardSigner(use_ambient_credentials=True)
signed_card = signer.sign_agent_card("agent-card.json")
```

### Using a Pre-obtained Identity Token

```python
import os

signer = AgentCardSigner(
    identity_token=os.environ.get("OIDC_TOKEN")
)
signed_card = signer.sign_agent_card("agent-card.json")
```

### Using Staging Environment

```python
signer = AgentCardSigner(staging=True)
signed_card = signer.sign_agent_card("agent-card.json")
```

### Using Custom Trust Configuration

```python
from pathlib import Path

signer = AgentCardSigner(
    trust_config=Path("/path/to/trust-config.json")
)
signed_card = signer.sign_agent_card("agent-card.json")
```

### Signing with Provenance

```python
from sigstore_a2a import AgentCardSigner, ProvenanceBuilder

# Build provenance
provenance = ProvenanceBuilder().from_github_actions().build()

# Sign with provenance
signer = AgentCardSigner()
signed_card = signer.sign_agent_card(
    "agent-card.json",
    provenance_bundle=provenance
)
```

### Saving Signed Cards

```python
import json

signer = AgentCardSigner()
signed_card = signer.sign_agent_card("agent-card.json")

# Save to file
with open("signed-card.json", "w") as f:
    json.dump(signed_card.model_dump(by_alias=True), f, indent=2)

# Or use sign_file for convenience
output_path = signer.sign_file(
    "agent-card.json",
    output_path="signed-card.json"
)
```

