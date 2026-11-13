# sigstore-a2a

> ⚠️ **Warning:** Prototype code - not for production use. Code is not reviewed and has not undergone a security audit.

A Python library and CLI tool for signing and verifying A2A (Agent-to-Agent) AgentCards using
[Sigstore](https://sigstore.dev/) keyless signing or traditional EC key signing, with optional
[SLSA](https://slsa.dev/) provenance attestations.

## Overview

This library enables verifiable supply chain security for A2A agents by providing:

- **Sigstore keyless signing** of A2A Agent Cards using Sigstore's infrastructure (default)
- **EC key signing** using traditional elliptic curve private keys (secp256r1, secp384r1, secp521r1)
- **SLSA provenance generation** to link Agent Cards to their source repositories and build workflows
- **Identity verification** to establish trust in agent origins
- **Discovery integration** for serving signed Agent Cards at well-known endpoints

## Requirements

- Python 3.11+
- UV package manager (recommended) or pip

## Installation

```bash
# Install from source using UV (recommended)
git clone https://github.com/sigstore/sigstore-a2a
cd sigstore-a2a
uv sync --prerelease=allow

# Alternative: Install from source using pip
pip install -e .
```

## Getting Started

### Signing with an EC Key

For environments where Sigstore OIDC is unavailable, sign with a standard EC private key:

```bash
# Generate an EC key pair
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem

# Sign an Agent Card
sigstore-a2a sign key agent-card.json --private-key private.pem

# Verify with the matching public key
sigstore-a2a verify key agent-card.signed.json --public-key public.pem

# Sign with SLSA provenance
sigstore-a2a sign key agent-card.json --private-key private.pem --provenance
```

### Signing with Sigstore (Keyless)

In CI/CD environments with OIDC credentials, Sigstore keyless signing is the default:

```bash
# Sign using ambient CI/CD OIDC credentials (default method)
sigstore-a2a sign agent-card.json --use_ambient_credentials

# Verify with identity constraints
sigstore-a2a verify signed-card.json \
  --identity dev@example.com \
  --identity_provider https://accounts.google.com
```

### Library Usage

```python
# --- EC key signing ---
from sigstore_a2a import ECKeyAgentCardSigner, ECKeyAgentCardVerifier
from pathlib import Path

signer = ECKeyAgentCardSigner(private_key_path=Path("private.pem"))
signed = signer.sign_agent_card("agent-card.json")

verifier = ECKeyAgentCardVerifier(public_key_path=Path("public.pem"))
result = verifier.verify_signed_card(signed)

if result.valid:
    print(f"Verified: {result.agent_card.name}")
else:
    print(f"Failed: {result.errors}")

# --- Sigstore keyless signing ---
from sigstore_a2a import AgentCardSigner, AgentCardVerifier

signer = AgentCardSigner(use_ambient_credentials=True)
signed = signer.sign_agent_card("agent-card.json")

verifier = AgentCardVerifier(
    identity="dev@example.com",
    oidc_issuer="https://accounts.google.com",
)
result = verifier.verify_signed_card(signed)
```

## CLI Reference

The CLI uses subcommands under `sign` and `verify` to select the signing method.
If no method is specified, Sigstore keyless signing is used by default.

```
sigstore-a2a sign <method> [options] AGENT_CARD
sigstore-a2a verify <method> [options] SIGNED_CARD
```

### sign key

Sign using an EC private key:

```bash
sigstore-a2a sign key agent-card.json --private-key key.pem
sigstore-a2a sign key agent-card.json --private-key key.pem -o signed.json
sigstore-a2a sign key agent-card.json --private-key key.pem --provenance
sigstore-a2a sign key agent-card.json --private-key key.pem \
  --provenance --repository owner/repo --commit_sha abc123
```

### sign sigstore

Sign using Sigstore keyless signing (default when no method is given):

```bash
# These are equivalent:
sigstore-a2a sign agent-card.json
sigstore-a2a sign sigstore agent-card.json

# With options:
sigstore-a2a sign agent-card.json --use_ambient_credentials
sigstore-a2a sign agent-card.json --staging
sigstore-a2a sign agent-card.json --identity_token "$TOKEN"
sigstore-a2a sign agent-card.json --provenance --repository owner/repo
```

### verify key

Verify using an EC public key:

```bash
sigstore-a2a verify key signed-card.json --public-key pubkey.pem
```

### verify sigstore

Verify using Sigstore (default when no method is given):

```bash
# These are equivalent:
sigstore-a2a verify signed-card.json \
  --identity dev@example.com \
  --identity_provider https://accounts.google.com

sigstore-a2a verify sigstore signed-card.json \
  --identity dev@example.com \
  --identity_provider https://accounts.google.com

# With constraints:
sigstore-a2a verify signed-card.json \
  --identity "https://github.com/owner/repo/.github/workflows/ci.yml@refs/heads/main" \
  --identity_provider https://token.actions.githubusercontent.com \
  --repository owner/repo \
  --workflow ci
```

### serve

Serve a signed Agent Card at well-known endpoints:

```bash
# Serve with Sigstore verification on startup
sigstore-a2a serve signed-card.json --port 8080

# Serve with EC key verification on startup
sigstore-a2a serve signed-card.json --public-key pubkey.pem

# Serve without verification
sigstore-a2a serve signed-card.json --no-verify
```

### trust-instance

Bootstrap trust for a private Sigstore instance:

```bash
sigstore-a2a trust-instance root.json --instance https://sigstore.example.com
```

## Agent Card Structure

Signed Agent Cards wrap the original card with cryptographic attestations:

```json
{
  "agentCard": {
    "name": "Example Agent",
    "description": "An example AI agent",
    "version": "1.0.0",
    "supportedInterfaces": [{"url": "https://example.com/agent"}],
    "skills": [...]
  },
  "attestations": {
    "signatureBundle": {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "verificationMaterial": { ... },
      "dsseEnvelope": { ... }
    },
    "provenanceBundle": { ... }
  }
}
```

The `signatureBundle` uses the Sigstore bundle format for both Sigstore keyless and EC key signatures.

## GitHub Actions Integration

```yaml
name: Build and Sign Agent Card
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  sign-agent-card:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install sigstore-a2a
        run: pip install sigstore-a2a

      - name: Sign Agent Card
        run: |
          sigstore-a2a sign agent-card.json \
            --use_ambient_credentials \
            --provenance \
            --repository ${{ github.repository }} \
            --commit_sha ${{ github.sha }} \
            --output signed-agent-card.json

      - name: Verify signature
        run: |
          sigstore-a2a verify signed-agent-card.json \
            --identity "https://github.com/${{ github.repository }}/.github/workflows/${{ github.workflow }}.yml@refs/heads/main" \
            --identity_provider https://token.actions.githubusercontent.com \
            --repository ${{ github.repository }}

      - uses: actions/upload-artifact@v4
        with:
          name: signed-agent-card
          path: signed-agent-card.json
```

## API Reference

### ECKeyAgentCardSigner

```python
class ECKeyAgentCardSigner:
    def __init__(self, private_key_path: Path, password: bytes | None = None)
    def sign_agent_card(self, agent_card, provenance_bundle=None) -> SignedAgentCard
    def sign_file(self, input_path, output_path=None, provenance_bundle=None) -> Path
```

Supported curves: secp256r1, secp384r1, secp521r1.

### ECKeyAgentCardVerifier

```python
class ECKeyAgentCardVerifier:
    def __init__(self, public_key_path: Path)
    def verify_signed_card(self, signed_card) -> VerificationResult
    def verify_file(self, file_path) -> VerificationResult
```

### AgentCardSigner

```python
class AgentCardSigner:
    def __init__(self, identity_token=None, staging=False, trust_config=None,
                 instance=None, client_id=None, client_secret=None,
                 use_ambient_credentials=False)
    def sign_agent_card(self, agent_card, provenance_bundle=None) -> SignedAgentCard
    def sign_file(self, input_path, output_path=None, provenance_bundle=None) -> Path
```

### AgentCardVerifier

```python
class AgentCardVerifier:
    def __init__(self, identity=None, oidc_issuer=None, staging=False,
                 trust_config=None, instance=None)
    def verify_signed_card(self, signed_card, constraints=None) -> VerificationResult
    def verify_file(self, file_path, constraints=None) -> VerificationResult
```

### VerificationResult

- `valid`: Whether verification succeeded
- `agent_card`: Verified AgentCard (extracted from the authenticated DSSE payload)
- `raw_card_data`: Raw predicate dict, preserving fields that may not map to the current protobuf schema
- `certificate`: Signing certificate (Sigstore only)
- `identity`: Extracted identity information (Sigstore only)
- `errors`: List of verification errors

### ProvenanceBuilder

```python
class ProvenanceBuilder:
    def __init__(self, build_type="https://github.com/actions/workflow@v1")
    def build_provenance(self, agent_card, source_repo=None, commit_sha=None,
                         workflow_ref=None) -> SLSAProvenance
```

## Troubleshooting

### OIDC Token Issues (Sigstore)

In CI/CD environments, ensure:
- `id-token: write` permission is set
- Repository has OIDC enabled
- Workflow runs in trusted environment

### EC Key Issues

- Key must be an elliptic curve key (RSA and other types are rejected)
- Supported curves: secp256r1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- Key format: PEM encoded

## License

Apache License 2.0

## Related Projects

- [Sigstore](https://sigstore.dev/) - Keyless signing infrastructure
- [SLSA](https://slsa.dev/) - Supply chain security framework
- [A2A Protocol](https://a2a-protocol.org) - Agent-to-Agent communication specification
