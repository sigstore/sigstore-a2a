from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class DigestSet(BaseModel):
    """A set of cryptographic digests for an artifact."""

    sha256: str | None = Field(None, description="SHA-256 digest")
    sha1: str | None = Field(None, description="SHA-1 digest")
    sha512: str | None = Field(None, description="SHA-512 digest")


class ProvenanceSubject(BaseModel):
    """Subject of the provenance attestation."""

    name: str = Field(..., description="Name of the subject artifact")
    digest: DigestSet = Field(..., description="Cryptographic digests of the subject")


class BuilderIdentity(BaseModel):
    """Identity of the builder that produced the artifact."""

    id: str = Field(..., description="Unique identifier for the builder")
    version: dict[str, str] | None = Field(None, description="Builder version information")


class ExternalParameters(BaseModel):
    """External parameters provided to the build."""

    source: dict[str, Any] | None = Field(None, description="Source repository information")
    config: dict[str, Any] | None = Field(None, description="Build configuration")
    vars: dict[str, Any] | None = Field(None, description="Environment variables")


class InternalParameters(BaseModel):
    """Internal parameters used by the builder."""

    entries: list[dict[str, Any]] | None = Field(None, description="Internal build entries")


class ResolvedDependency(BaseModel):
    """A resolved dependency used during the build."""

    uri: str = Field(..., description="URI identifying the dependency")
    digest: DigestSet = Field(..., description="Cryptographic digests of the dependency")
    name: str | None = Field(None, description="Human-readable name")
    download_location: HttpUrl | None = Field(
        None, alias="downloadLocation", description="Location where dependency was downloaded"
    )
    media_type: str | None = Field(None, alias="mediaType", description="Media type of the dependency")


class ProvenanceBuildDefinition(BaseModel):
    """Build definition describing how the artifact was produced."""

    build_type: str = Field(..., alias="buildType", description="URI identifying the type of build")
    external_parameters: ExternalParameters = Field(
        ..., alias="externalParameters", description="External parameters provided to the build"
    )
    internal_parameters: InternalParameters | None = Field(
        None, alias="internalParameters", description="Internal parameters used by the builder"
    )
    resolved_dependencies: list[ResolvedDependency] | None = Field(
        None, alias="resolvedDependencies", description="Dependencies resolved during the build"
    )


class RunDetails(BaseModel):
    """Details about the build execution."""

    builder: BuilderIdentity = Field(..., description="Identity of the builder")
    build_definition: ProvenanceBuildDefinition = Field(
        ..., alias="buildDefinition", description="Definition of how the build was performed"
    )
    invocation: dict[str, Any] | None = Field(None, description="Details about the build invocation")
    metadata: dict[str, Any] | None = Field(None, description="Additional metadata about the build")


class SLSAProvenance(BaseModel):
    """SLSA provenance attestation following SLSA v1.1 specification."""

    # Envelope fields
    payload_type: str = Field(
        default="application/vnd.in-toto+json", alias="_type", description="Type of the attestation payload"
    )
    subject: list[ProvenanceSubject] = Field(..., description="Subjects of the attestation")
    predicate_type: str = Field(
        default="https://slsa.dev/provenance/v1",
        alias="predicateType",
        description="URI identifying the predicate type",
    )

    # Predicate fields (SLSA provenance)
    run_details: RunDetails = Field(..., alias="runDetails", description="Details about the build execution")
    build_definition: ProvenanceBuildDefinition = Field(
        ..., alias="buildDefinition", description="Definition of how the build was performed"
    )

    model_config = {"populate_by_name": True}


class ProvenanceBundle(BaseModel):
    """Bundle containing provenance attestation and signature."""

    provenance: SLSAProvenance = Field(..., description="SLSA provenance attestation")
    signature: str = Field(..., description="Digital signature of the provenance")
    certificate: str = Field(..., description="X.509 certificate used for signing")
    certificate_chain: list[str] | None = Field(None, alias="certificateChain", description="X.509 certificate chain")
    timestamp: datetime = Field(..., description="Timestamp when signature was created")

    model_config = {"populate_by_name": True}
