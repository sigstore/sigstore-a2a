# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from cryptography import x509
from sigstore.models import ClientTrustConfig
from sigstore.verify import Verifier
from sigstore.verify.policy import (
    AllOf,
    GitHubWorkflowName,
    GitHubWorkflowRepository,
    Identity,
    OIDCIssuer,
    UnsafeNoOp,
)

from .models.signature import SignedAgentCard


class IdentityConstraints:
    """Identity constraints for signature verification."""

    def __init__(
        self,
        repository: str | None = None,
        workflow: str | None = None,
        identity: str | None = None,
        identity_provider: str | None = None,
    ):
        """Initialize identity constraints.

        Args:
            repository: Required repository (e.g., "owner/repo")
            workflow: Required workflow name or path
            identity: Required identity
            identity_provider: Required OIDC issuer
        """
        self.repository = repository
        self.workflow = workflow
        self.identity = identity
        self.identity_provider = identity_provider


class VerificationResult:
    """Result of Agent Card verification."""

    def __init__(
        self,
        valid: bool,
        agent_card: AgentCard | None = None,
        certificate: x509.Certificate | None = None,
        identity: dict[str, Any] | None = None,
        errors: list[str] | None = None,
    ):
        """Initialize verification result.

        Args:
            valid: Whether verification succeeded
            agent_card: Verified agent card (if valid)
            certificate: Signing certificate
            identity: Extracted identity information
            errors: List of verification errors
        """
        self.valid = valid
        self.agent_card = agent_card
        self.certificate = certificate
        self.identity = identity or {}
        self.errors = errors or []

    def __bool__(self) -> bool:
        """Return True if verification was successful."""
        return self.valid


class AgentCardVerifier:
    """Verifies signed A2A Agent Cards using Sigstore."""

    def __init__(
        self,
        identity: str | None = None,
        oidc_issuer: str | None = None,
        staging: bool = False,
        trust_config: Path | None = None,
    ):
        """Initialize the Agent Card verifier.

        Args:
            identity: The expected identity that has signed the model
            oidc_issuer: The expected OpenID Connect issuer that provided
                the certificate used for the signature
            staging: Use Sigstore staging environment
            trust_config: A path to a custom trust configuration
        """
        self.identity = identity
        self.oidc_issuer = oidc_issuer
        self.staging = staging
        self.trust_config = trust_config

        self._verifier: Verifier | None = None

    def _get_verifier(self) -> Verifier:
        """
        Retrieves or creates a Sigstore verifier instance based on the configuration.

        The method prioritizes the staging environment if enabled, falls back to a
        custom trust configuration, and defaults to the production environment.
        This ensures the correct root of trust is used for verification.
        """
        if self._verifier is not None:
            return self._verifier

        if self.staging:
            self._verifier = Verifier.staging()
        elif self.trust_config:
            trust_config = ClientTrustConfig.from_json(
                self.trust_config.read_text()
            )
            self._verifier = Verifier(trusted_root=trust_config.trusted_root)
        else:
            self._verifier = Verifier.production()

        return self._verifier

    def _build_policy(self, constraints: IdentityConstraints | None):
        """Build a sigstore verification policy from constraints.

        Uses the Identity policy (checking both signer identity and issuer) when
        possible, falls back to OIDCIssuer-only, and adds GitHub-specific policies
        for repository/workflow constraints.  When no constraints are available,
        falls back to the verifier-level identity/oidc_issuer attributes.
        """
        policies = []

        # Resolve identity/issuer: constraints take precedence, then verifier defaults
        cert_identity = (constraints.identity if constraints else None) or self.identity
        issuer = (constraints.identity_provider if constraints else None) or self.oidc_issuer

        # Build the core identity policy
        if cert_identity and issuer:
            policies.append(Identity(identity=cert_identity, issuer=issuer))
        elif cert_identity:
            policies.append(Identity(identity=cert_identity))
        elif issuer:
            policies.append(OIDCIssuer(issuer))

        # Add GitHub-specific constraint policies
        if constraints:
            if constraints.repository:
                policies.append(GitHubWorkflowRepository(constraints.repository))
            if constraints.workflow:
                policies.append(GitHubWorkflowName(constraints.workflow))

        if not policies:
            return UnsafeNoOp()
        if len(policies) == 1:
            return policies[0]
        return AllOf(policies)

    def _extract_identity(self, certificate: x509.Certificate) -> dict[str, Any]:
        """Extract identity information from certificate.

        Args:
            certificate: X.509 certificate

        Returns:
            Dictionary containing identity information
        """
        identity: dict[str, Any] = {}

        # Extract subject alternative names
        try:
            san_ext = certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.RFC822Name):
                    identity["email"] = name.value
                    identity["subject"] = name.value  # Use email as subject
                elif isinstance(name, x509.UniformResourceIdentifier):
                    identity["uri"] = name.value
                    identity["subject"] = name.value  # Use URI as subject
        except x509.ExtensionNotFound:
            pass

        # Extract OIDC issuer from certificate (Sigstore-specific)
        try:
            # Look for Sigstore OIDC issuer extension
            for ext in certificate.extensions:
                if ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.1":  # Sigstore issuer OID
                    identity["issuer"] = ext.value.value.decode()
                elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.2":  # GitHub workflow trigger
                    identity["github_workflow_trigger"] = ext.value.value.decode()
                elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.3":  # GitHub workflow SHA
                    identity["github_workflow_sha"] = ext.value.value.decode()
                elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.4":  # GitHub workflow name
                    identity["github_workflow_name"] = ext.value.value.decode()
                elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.5":  # GitHub workflow repository
                    identity["github_workflow_repository"] = ext.value.value.decode()
                elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.6":  # GitHub workflow ref
                    identity["github_workflow_ref"] = ext.value.value.decode()
        except Exception:
            # Ignore extension parsing errors
            pass

        return identity

    def _parse_signed_card(self, signed_card: SignedAgentCard | dict[str, Any] | str | Path) -> SignedAgentCard:
        """Parse input into a validated SignedAgentCard, raising on failure."""
        if isinstance(signed_card, SignedAgentCard):
            return signed_card

        if isinstance(signed_card, str | Path):
            path = Path(signed_card)
            card_data = json.loads(path.read_text()) if path.exists() else json.loads(str(signed_card))
        elif isinstance(signed_card, dict):
            card_data = signed_card
        else:
            raise TypeError(f"Invalid signed card type: {type(signed_card)}")

        return SignedAgentCard.model_validate(card_data)

    def _extract_verified_card(self, payload: bytes) -> AgentCard:
        """Extract the agent card from the verified DSSE payload.

        After sigstore verifies the DSSE signature, the statement payload is
        the authenticated data.  We parse the agent card from the statement's
        predicate rather than trusting the outer SignedAgentCard wrapper, which
        could have been tampered with independently of the bundle.
        """
        statement = json.loads(payload)
        signed_predicate = statement.get("predicate")
        if signed_predicate is None or not isinstance(signed_predicate, dict):
            raise ValueError("DSSE statement does not contain a valid predicate")
        return AgentCard.model_validate(signed_predicate)

    def verify_signed_card(
        self,
        signed_card: SignedAgentCard | dict[str, Any] | str | Path,
        constraints: IdentityConstraints | None = None,
    ) -> VerificationResult:
        """Verify a signed Agent Card.

        Args:
            signed_card: Signed agent card to verify
            constraints: Optional identity constraints

        Returns:
            Verification result
        """
        # 1. Parse input
        try:
            parsed_signed_card = self._parse_signed_card(signed_card)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Invalid signed card: {e}"])

        sig_bundle = parsed_signed_card.attestations.signature_bundle

        # 2. Build verification policy from constraints (handles None safely)
        policy = self._build_policy(constraints)

        # 3. Sigstore DSSE verification
        verifier = self._get_verifier()
        try:
            _payload_type, payload = verifier.verify_dsse(sig_bundle, policy)
        except Exception as e:
            cert_identity = self._extract_identity(sig_bundle.signing_certificate)
            error_msg = f"Signature verification failed: {e}"
            if cert_identity:
                error_msg += f" (Certificate identity: issuer={cert_identity.get('issuer')}, subject={cert_identity.get('subject')})"
            return VerificationResult(valid=False, errors=[error_msg])

        # 4. Extract the verified agent card from the authenticated DSSE payload.
        #    This is the source of truth, not the outer wrapper, which could
        #    have been modified independently of the Sigstore bundle.
        try:
            verified_card = self._extract_verified_card(payload)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Failed to parse agent card from DSSE payload: {e}"])

        # 5. Extract identity from certificate
        identity = self._extract_identity(sig_bundle.signing_certificate)

        return VerificationResult(
            valid=True, agent_card=verified_card, certificate=sig_bundle.signing_certificate, identity=identity
        )

    def verify_file(self, file_path: str | Path, constraints: IdentityConstraints | None = None) -> VerificationResult:
        """Verify a signed Agent Card file.

        Args:
            file_path: Path to signed Agent Card file
            constraints: Optional identity constraints

        Returns:
            Verification result
        """
        return self.verify_signed_card(file_path, constraints)
