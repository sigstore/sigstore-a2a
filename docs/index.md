# Home

## Introduction

A Python library and CLI tool for keyless signing of A2A (Agent-to-Agent) AgentCards using
[Sigstore](https://sigstore.dev/) and [SLSA](https://slsa.dev/) provenance attestations.

This library enables verifiable supply chain security for A2A agents by providing:

- **Keyless signing** of A2A Agent Cards using Sigstore's infrastructure
- **SLSA provenance generation** to link Agent Cards to their source repositories and build workflows
- **Identity verification** to establish trust in agent origins
- **Discovery integration** for serving signed Agent Cards at well-known endpoints
