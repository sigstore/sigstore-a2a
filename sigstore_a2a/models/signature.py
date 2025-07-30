from datetime import datetime
from typing import Any

from a2a.types import AgentCard
from pydantic import BaseModel, Field

from .provenance import SLSAProvenance


class SignatureBundle(BaseModel):
    """Sigstore signature bundle containing signature and verification materials."""

    signature: str = Field(..., description="Base64-encoded signature")
    certificate: str = Field(..., description="X.509 certificate in PEM format")
    certificate_chain: list[str] | None = Field(
        None, alias="certificateChain", description="X.509 certificate chain in PEM format"
    )
    transparency_log_entry: dict[str, Any] | None = Field(
        None, alias="transparencyLogEntry", description="Rekor transparency log entry"
    )
    timestamp: datetime = Field(..., description="Timestamp when signature was created")

    model_config = {"populate_by_name": True}


class VerificationMaterial(BaseModel):
    """Verification material for Agent Card signatures."""

    signature_bundle: SignatureBundle = Field(..., alias="signatureBundle", description="Sigstore signature bundle")
    provenance_bundle: SLSAProvenance | None = Field(
        None, alias="provenanceBundle", description="SLSA provenance attestation"
    )

    model_config = {"populate_by_name": True}


class SignedAgentCard(BaseModel):
    """Agent Card with cryptographic signature and provenance."""

    agent_card: AgentCard = Field(..., alias="agentCard", description="The A2A Agent Card")
    verification_material: VerificationMaterial = Field(
        ..., alias="verificationMaterial", description="Cryptographic verification material"
    )

    model_config = {"populate_by_name": True}

    @property
    def name(self) -> str:
        """Get the agent name."""
        return self.agent_card.name

    @property
    def version(self) -> str:
        """Get the agent version."""
        return self.agent_card.version

    @property
    def url(self) -> str:
        """Get the agent URL."""
        return str(self.agent_card.url)

    @property
    def signature_timestamp(self) -> datetime:
        """Get the signature timestamp."""
        return self.verification_material.signature_bundle.timestamp
