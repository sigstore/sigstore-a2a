# Models

This page documents the data models used by `sigstore-a2a`.

## SignedAgentCard

The `SignedAgentCard` model represents a signed A2A Agent Card with its attestations.

::: sigstore_a2a.models.signature.SignedAgentCard
    options:
      show_root_heading: true
      show_source: true

## Attestations

The `Attestations` model contains the signature bundle and optional provenance.

::: sigstore_a2a.models.signature.Attestations
    options:
      show_root_heading: true
      show_source: true

## SLSAProvenance

The `SLSAProvenance` model represents SLSA build provenance.

::: sigstore_a2a.models.provenance.SLSAProvenance
    options:
      show_root_heading: true
      show_source: true

## ProvenanceBuilder

The `ProvenanceBuilder` class helps construct SLSA provenance attestations.

::: sigstore_a2a.provenance.ProvenanceBuilder
    options:
      show_root_heading: true
      show_source: true

## Usage Examples

### Working with SignedAgentCard

```python
from sigstore_a2a.models.signature import SignedAgentCard
import json

# Load a signed card
with open("signed-card.json") as f:
    data = json.load(f)

signed_card = SignedAgentCard.model_validate(data)

# Access the agent card
print(f"Agent: {signed_card.agent_card.name}")
print(f"URL: {signed_card.agent_card.url}")

# Access attestations
print(f"Has signature: {signed_card.attestations.signature_bundle is not None}")
print(f"Has provenance: {signed_card.attestations.provenance_bundle is not None}")
```

### Building Provenance

```python
from sigstore_a2a import ProvenanceBuilder

# From GitHub Actions environment
provenance = ProvenanceBuilder().from_github_actions().build()

# Manual construction
provenance = ProvenanceBuilder() \
    .set_builder("https://github.com/sigstore/sigstore-a2a") \
    .set_repository("owner/repo") \
    .set_commit_sha("abc123") \
    .set_workflow_ref(".github/workflows/release.yml") \
    .build()
```

### Serializing Models

```python
import json
from sigstore_a2a import AgentCardSigner

signer = AgentCardSigner()
signed_card = signer.sign_agent_card("agent-card.json")

# Serialize to JSON
json_str = json.dumps(
    signed_card.model_dump(by_alias=True),
    indent=2,
    default=str
)

# Save to file
with open("output.json", "w") as f:
    f.write(json_str)
```

