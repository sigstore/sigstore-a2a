import json
from datetime import datetime
from pathlib import Path
from typing import Any

from a2a.types import AgentCard

from .models.provenance import (
    BuilderIdentity,
    DigestSet,
    ExternalParameters,
    ProvenanceBuildDefinition,
    ProvenanceSubject,
    RunDetails,
    SLSAProvenance,
)
from .utils.ci import get_ci_context
from .utils.crypto import canonicalize_json, compute_digest


class ProvenanceBuilder:
    """Builds SLSA provenance attestations for Agent Cards."""

    def __init__(self, build_type: str = "https://github.com/actions/workflow@v1"):
        """Initialize provenance builder.

        Args:
            build_type: URI identifying the build type
        """
        self.build_type = build_type

    def create_subject(
        self, agent_card: AgentCard | dict[str, Any] | str | Path, name: str | None = None
    ) -> ProvenanceSubject:
        """Create provenance subject from Agent Card.

        Args:
            agent_card: Agent card to create subject for
            name: Optional name for the subject (defaults to agent name)

        Returns:
            Provenance subject with digests
        """
        # Parse agent card
        if isinstance(agent_card, str | Path):
            if Path(agent_card).exists():
                with open(agent_card) as f:
                    card_data = json.load(f)
            else:
                card_data = json.loads(str(agent_card))
        elif isinstance(agent_card, dict):
            card_data = agent_card
        elif isinstance(agent_card, AgentCard):
            card_data = agent_card.model_dump(by_alias=True)
        else:
            raise ValueError(f"Invalid agent card type: {type(agent_card)}")

        # Canonicalize for consistent hashing
        canonical_data = canonicalize_json(card_data)

        # Compute digests
        digest_set = DigestSet(
            sha256=compute_digest(canonical_data, "sha256"),
            sha1=compute_digest(canonical_data, "sha1"),
            sha512=compute_digest(canonical_data, "sha512"),
        )

        # Use agent name if not provided
        if name is None:
            parsed_card = AgentCard.model_validate(card_data)
            name = f"{parsed_card.name}-{parsed_card.version}"

        return ProvenanceSubject(name=name, digest=digest_set)

    def create_build_definition(
        self,
        source_repo: str | None = None,
        commit_sha: str | None = None,
        workflow_ref: str | None = None,
        external_params: dict[str, Any] | None = None,
    ) -> ProvenanceBuildDefinition:
        """Create build definition from build context.

        Args:
            source_repo: Source repository (e.g., "owner/repo")
            commit_sha: Git commit SHA
            workflow_ref: Workflow reference
            external_params: Additional external parameters

        Returns:
            Build definition
        """
        # Get CI context if available
        ci_context = get_ci_context()

        # Use CI context to fill in missing values
        if source_repo is None and "repository" in ci_context:
            source_repo = ci_context["repository"]

        if commit_sha is None and "commit_sha" in ci_context:
            commit_sha = ci_context["commit_sha"]

        if workflow_ref is None and ci_context.get("ci_provider") == "github-actions":
            workflow_ref = f"{ci_context.get('repository')}/.github/workflows/{ci_context.get('workflow_name', 'unknown')}.yml@{ci_context.get('ref', 'unknown')}"

        # Build external parameters
        ext_params = external_params or {}

        if source_repo:
            ext_params["source"] = {"repository": source_repo, "ref": ci_context.get("ref"), "path": "/"}

            if commit_sha:
                ext_params["source"]["revision"] = commit_sha

        if workflow_ref:
            ext_params["workflow"] = {"ref": workflow_ref, "repository": source_repo}

        # Add CI-specific parameters
        if ci_context.get("ci_provider") == "github-actions":
            ext_params["github"] = {
                "event_name": ci_context.get("event_name"),
                "run_id": ci_context.get("run_id"),
                "run_number": ci_context.get("run_number"),
                "run_attempt": ci_context.get("run_attempt"),
                "actor": ci_context.get("actor"),
                "job": ci_context.get("job"),
            }

        return ProvenanceBuildDefinition(
            buildType=self.build_type,
            externalParameters=ExternalParameters(
                source=ext_params.get("source"), config=ext_params.get("config"), vars=ext_params.get("vars")
            ),
        )

    def create_builder_identity(
        self, builder_id: str | None = None, version: dict[str, str] | None = None
    ) -> BuilderIdentity:
        """Create builder identity.

        Args:
            builder_id: Unique identifier for the builder
            version: Builder version information

        Returns:
            Builder identity
        """
        # Use CI context to determine builder
        ci_context = get_ci_context()

        if builder_id is None:
            if ci_context.get("ci_provider") == "github-actions":
                builder_id = f"https://github.com/{ci_context.get('repository', 'unknown')}/actions"
            else:
                builder_id = f"unknown-builder-{ci_context.get('ci_provider', 'local')}"

        if version is None:
            version = {}
            if ci_context.get("ci_provider") == "github-actions":
                version["github_actions"] = "1.0"  # Could be more specific

        return BuilderIdentity(id=builder_id, version=version)

    def build_provenance(
        self,
        agent_card: AgentCard | dict[str, Any] | str | Path,
        source_repo: str | None = None,
        commit_sha: str | None = None,
        workflow_ref: str | None = None,
        builder_id: str | None = None,
        external_params: dict[str, Any] | None = None,
    ) -> SLSAProvenance:
        """Build complete SLSA provenance for an Agent Card.

        Args:
            agent_card: Agent card to create provenance for
            source_repo: Source repository
            commit_sha: Git commit SHA
            workflow_ref: Workflow reference
            builder_id: Builder identifier
            external_params: Additional external parameters

        Returns:
            Complete SLSA provenance attestation
        """
        # Create subject
        subject = self.create_subject(agent_card)

        # Create build definition
        build_definition = self.create_build_definition(
            source_repo=source_repo, commit_sha=commit_sha, workflow_ref=workflow_ref, external_params=external_params
        )

        # Create builder identity
        builder = self.create_builder_identity(builder_id=builder_id)

        # Create run details
        run_details = RunDetails(
            builder=builder,
            buildDefinition=build_definition,
            invocation={"configSource": build_definition.external_parameters.model_dump(exclude_none=True)},
            metadata={
                "buildInvocationId": get_ci_context().get("run_id"),
                "buildStartedOn": datetime.utcnow().isoformat() + "Z",
                "completeness": {"parameters": True, "environment": False, "materials": False},
                "reproducible": False,
            },
        )

        # Create SLSA provenance
        provenance = SLSAProvenance(subject=[subject], runDetails=run_details, buildDefinition=build_definition)

        return provenance
