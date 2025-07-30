"""
sigstore-a2a: Keyless signing library for A2A Agent Cards.

This library provides tools for signing and verifying A2A Agent Cards using
Sigstore's keyless signing infrastructure with SLSA provenance attestations.
"""

__version__ = "0.4.0"


def __getattr__(name: str):
    """Lazy imports to avoid dependency issues."""
    if name == "AgentCardSigner":
        from .signer import AgentCardSigner

        return AgentCardSigner
    elif name == "AgentCardVerifier":
        from .verifier import AgentCardVerifier

        return AgentCardVerifier
    elif name == "ProvenanceBuilder":
        from .provenance import ProvenanceBuilder

        return ProvenanceBuilder
    else:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
