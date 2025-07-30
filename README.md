# sigstore-a2a

> ⚠️ **Warning:** Prototype code - not for production use. Code is not reviewed and has not undergone a security audit.

A Python library and CLI tool for keyless signing of A2A (Agent-to-Agent) AgentCards using
[Sigstore](https://sigstore.dev/) and [SLSA](https://slsa.dev/) provenance attestations.

## Overview

This library enables verifiable supply chain security for A2A agents by providing:

- **Keyless signing** of A2A Agent Cards using Sigstore's infrastructure
- **SLSA provenance generation** to link Agent Cards to their source repositories and build workflows
- **Identity verification** to establish trust in agent origins
- **Discovery integration** for serving signed Agent Cards at well-known endpoints

## Requirements

- Python 3.11+
- UV package manager (recommended) or pip

## Installation

```bash
# Install from source using UV (recommended)
git clone https://github.com/RedDotRocket/sigstore-a2a
cd sigstore-a2a
uv sync --prerelease=allow

# Alternative: Install from source using pip
pip install -e .
```

## Getting Started

### Signing in CI/CD

The library uses ambient OIDC credentials from CI/CD environments like GitHub Actions to perform keyless signing. This creates a verifiable link between your Agent Card and the source code repository:

```bash
# Sign an Agent Card using CI/CD OIDC credentials
sigstore-a2a sign agent-card.json --output signed-agent-card.json

# Sign with explicit repository binding
sigstore-a2a sign agent-card.json --repository $GITHUB_REPOSITORY

# Verify with repository constraint
sigstore-a2a verify signed-agent-card.json --repository owner/repo
```

### Library Usage

```python
from sigstore-a2a.signer import AgentCardSigner
from sigstore-a2a.verifier import AgentCardVerifier
from sigstore-a2a.provenance import ProvenanceBuilder

# Signing (requires OIDC credentials from CI/CD)
signer = AgentCardSigner()
provenance_builder = ProvenanceBuilder()

provenance = provenance_builder.build_provenance("agent-card.json")
signed_card = signer.sign_agent_card("agent-card.json", provenance_bundle=provenance)

# Verify a signed Agent Card
verifier = AgentCardVerifier()
result = verifier.verify_signed_card(signed_card)

if result.valid:
    print(f"Valid signature from {result.identity}")
else:
    print(f"Invalid signature: {result.errors}")
```

## Agent Card Structure

Agent Cards are extended with cryptographic verification material:

```json
{
  "agentCard": {
    "protocolVersion": "0.2.9",
    "name": "Example Agent",
    "description": "An example AI agent",
    "url": "https://example.com/agent",
    "version": "1.0.0",
    "capabilities": {...},
    "skills": [...]
  },
  "verificationMaterial": {
    "signatureBundle": {
      "signature": "base64-encoded-signature",
      "certificate": "-----BEGIN CERTIFICATE-----...",
      "transparencyLogEntry": {...},
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "provenanceBundle": {
      "provenance": {
        "subject": [...],
        "runDetails": {...},
        "buildDefinition": {...}
      }
    }
  }
}
```

## GitHub Actions Integration

Setting up automated Agent Card signing in GitHub Actions creates a secure and auditable process for publishing AI agents. The workflow below demonstrates how to integrate sigstore-a2a into your CI/CD pipeline, ensuring that every Agent Card published from your repository carries cryptographic proof of its origin.

The key to this integration is the OIDC (OpenID Connect) token that GitHub Actions provides. This token contains claims about the repository, workflow, and actor that triggered the build, which Sigstore embeds into the signing certificate. This creates an immutable link between your Agent Card and its source code.

```yaml
name: Build and Sign Agent Card
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write  # Required for Sigstore OIDC token
  contents: read   # Required to checkout repository

jobs:
  sign-agent-card:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install UV package manager
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          echo "$HOME/.cargo/bin" >> $GITHUB_PATH

      - name: Install sigstore-a2a
        run: |
          uv sync --prerelease=allow

      - name: Sign Agent Card
        env:
          UV_PRERELEASE: allow
        run: |
          uv run sigstore-a2a sign agent-card.json \
            --output signed-agent-card.json \
            --repository ${{ github.repository }}

      - name: Verify signature locally
        env:
          UV_PRERELEASE: allow
        run: |
          uv run sigstore-a2a verify signed-agent-card.json \
            --repository ${{ github.repository }} \
            --workflow "${{ github.workflow }}"

      - name: Upload signed Agent Card
        uses: actions/upload-artifact@v4
        with:
          name: signed-agent-card
          path: signed-agent-card.json
          retention-days: 30

      - name: Display signature information
        env:
          UV_PRERELEASE: allow
        run: |
          echo "Agent Card signed successfully!"
          echo "Repository: ${{ github.repository }}"
          echo "Workflow: ${{ github.workflow }}"
          echo "SHA: ${{ github.sha }}"
          echo "Actor: ${{ github.actor }}"
```

### Understanding the Signing Process

When your GitHub Actions workflow runs, several important things happen during the signing process. First, GitHub generates an OIDC token that contains metadata about the workflow execution, including the repository name, workflow name, commit SHA, and the user or system that triggered the run. The sigstore-a2a library detects this token automatically and uses it to authenticate with Sigstore's certificate authority "fulcio".

Sigstore then issues a short-lived X.509 certificate that embeds the OIDC claims as certificate extensions. This certificate is used to sign your Agent Card using standard cryptographic algorithms. The signature, certificate, and a reference to the transparency log entry are all bundled together in the signed Agent Card file.

The transparency log entry in Rekor provides public auditability. Anyone can verify that a signature was created at a specific time and tied to a specific repository and workflow, even if the signing certificate has expired. This creates a permanent, tamper-evident record of your Agent Card's provenance.

## Verification and Trust

Agent Card verification is a critical component of the A2A security model. When you receive a signed Agent Card, you can cryptographically verify its authenticity and establish trust based on its provenance. The verification process checks both the signature validity and the identity claims embedded in the signing certificate. It then helps you tie back the 
card to a specific repository, workflow, and actor that created it.

### Basic Verification

The simplest verification check confirms that the signature is valid and the Agent Card hasn't been tampered with:

```bash
# Basic signature verification
uv run sigstore-a2a verify signed-agent-card.json

# Verification with verbose output
uv run sigstore-a2a --verbose verify signed-agent-card.json
```

When verification succeeds, you'll see details about the signing identity, including the repository, workflow, and other metadata from the CI/CD environment where the Agent Card was signed.

### Identity Constraints

Yyou'll typically want to enforce identity constraints that ensure the Agent Card came from a trusted source. These constraints allow you to specify exactly which repositories, workflows, or actors you trust:

```bash
# Verify that the card came from a specific repository
uv run sigstore-a2a verify signed-agent-card.json --repository myorg/trusted-repo

# Verify repository and workflow
uv run sigstore-a2a verify signed-agent-card.json \
  --repository myorg/trusted-repo \
  --workflow "Build and Sign Agent Card"

# Multiple constraints including actor
uv run sigstore-a2a verify signed-agent-card.json \
  --repository myorg/trusted-repo \
  --workflow "Build and Sign Agent Card" \
  --actor trusted-user
```


Identity constraints provide defense against several attack scenarios. They prevent an attacker who has compromised a different repository from creating Agent Cards that appear to come from your trusted source. They also ensure that Agent Cards are only created through approved CI/CD workflows, not through manual processes that might bypass security controls.

### Transparency Log Verification

Every signature created with Sigstore is automatically logged in the public Rekor transparency log. This provides an additional layer of security by creating a tamper-evident record of when the signature was created. You can search the transparency log to verify that a signature was properly logged:

```bash
# The transparency log entry is automatically verified during signature verification
# Additional tooling like rekor-cli can be used for direct transparency log queries

# Example: Search for entries from a specific repository
rekor-cli search --rekor-url https://rekor.sigstore.dev \
  --type dsse \
  --query "repository:myorg/trusted-repo"
```

The transparency log serves multiple purposes in the security model. It provides public auditability, allowing anyone to verify that signatures were created at specific times. It also enables detection of backdated signatures or other anomalies that might indicate compromise. For Agent Cards, this creates a public record of when each version was signed and published.

### Keyless Signing Security

Traditional code signing requires managing long-lived private keys, which creates operational overhead and security risks. Sigstore's keyless signing eliminates these concerns by using short-lived certificates tied to OIDC identity tokens. When you sign an Agent Card in GitHub Actions, the process uses an OIDC token that is valid for only the duration of your workflow run. This token is automatically exchanged for a signing certificate that expires within minutes.

This approach provides several security benefits. There are no long-lived secrets to manage or protect. The signing identity is cryptographically tied to your CI/CD environment, making it nearly impossible for an attacker to forge signatures without compromising your entire development infrastructure. The short certificate lifetime means that even if a certificate were somehow compromised, its window of misuse would be extremely limited.

### Supply Chain Protection

Agent Cards represent code and AI models that will be executed in distributed environments, making supply chain security critical. The combination of Sigstore signatures and SLSA provenance creates a verifiable chain of custody from source code to deployed agent.

When you sign an Agent Card, the signature embeds metadata about the exact source code revision, the build environment, and the CI/CD workflow used. This creates an immutable link between the Agent Card and its origins. Consumers can verify not just that the signature is valid, but that the Agent Card came from a trusted repository and was built using an approved process.

### Verification Best Practices

For production deployments, always use identity constraints when verifying Agent Cards. A basic signature verification only confirms that the signature is cryptographically valid, but doesn't establish whether you should trust the signer. Identity constraints allow you to specify exactly which repositories, workflows, and actors you trust.

Consider implementing a policy where Agent Cards must come from repositories within your organization and must be built using standardized workflows. This prevents the use of Agent Cards that might have been signed by external parties or through non-standard processes.

The transparency log provides an additional verification layer that should be leveraged in high-security environments. By checking that signatures are properly logged in Rekor, you can detect attempts to backdate signatures or other anomalies that might indicate compromise.

### Operational Security

When setting up signing workflows, ensure that your GitHub repository has appropriate branch protection rules and required status checks. The security of your Agent Card signatures is only as strong as the security of your development environment.

Consider using environment-specific signing, where Agent Cards intended for production are only signed from protected branches, while development versions can be signed from feature branches. This can be implemented using different repository constraints in your verification policies.

## API Reference

### AgentCardSigner

```python
class AgentCardSigner:
    def __init__(self, issuer=None, identity_token=None, staging=False)
    def sign_agent_card(self, agent_card, provenance_bundle=None) -> SignedAgentCard
    def sign_file(self, input_path, output_path=None, provenance_bundle=None) -> Path
```

**Parameters:**
- `staging`: Use Sigstore staging environment
- `issuer`: Custom OIDC issuer (optional)
- `identity_token`: Pre-obtained OIDC token (optional)

### AgentCardVerifier

```python
class AgentCardVerifier:
    def __init__(self, staging=False)
    def verify_signed_card(self, signed_card, constraints=None) -> VerificationResult
    def verify_file(self, file_path, constraints=None) -> VerificationResult
```

**Parameters:**
- `staging`: Use Sigstore staging environment
- `constraints`: IdentityConstraints object for repository/workflow verification

### ProvenanceBuilder

```python
class ProvenanceBuilder:
    def __init__(self, build_type="https://github.com/actions/workflow@v1")
    def build_provenance(self, agent_card, source_repo=None, commit_sha=None) -> SLSAProvenance
    def create_subject(self, agent_card, name=None) -> ProvenanceSubject
```

## CLI Reference

The sigstore-a2a command-line interface provides comprehensive tooling for signing, verifying, and serving Agent Cards. Each command supports both testing and production modes, allowing for seamless development and deployment workflows.

### Signing Commands

```bash
# Sign in CI/CD environment
sigstore-a2a sign agent-card.json --repository owner/repo --output signed-card.json

# Sign with SLSA provenance
sigstore-a2a sign agent-card.json --repository owner/repo --commit-sha abc123

# Use staging environment
sigstore-a2a sign agent-card.json --staging
```

### Verification Commands

```bash
# Basic verification
sigstore-a2a verify signed-card.json

# Verification with constraints
sigstore-a2a verify signed-card.json --repository owner/repo --workflow build

# Verbose output with identity details
sigstore-a2a --verbose verify signed-card.json
```

### Utility Commands

```bash
# Serve Agent Card at well-known endpoint
sigstore-a2a serve signed-card.json --port 8080

# Check dependencies and environment
sigstore-a2a check-deps

# Run demo with example Agent Card
sigstore-a2a demo
```

## Troubleshooting

### OIDC Token Issues

In CI/CD environments, ensure:
- `id-token: write` permission is set
- Repository has OIDC enabled
- Workflow runs in trusted environment

Note: This library requires real OIDC credentials and does not support local signing outside of CI/CD environments.

## License

Apache License 2.0

## Related Projects

- [Sigstore](https://sigstore.dev/) - Keyless signing infrastructure
- [SLSA](https://slsa.dev/) - Supply chain security framework
- [A2A Protocol](https://a2a-protocol.org) - Agent-to-Agent communication specification