import json
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from cryptography import x509
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import AnyOf

from .models.signature import SignedAgentCard


class IdentityConstraints:
    """Identity constraints for signature verification."""

    def __init__(
        self,
        repository: str | None = None,
        workflow: str | None = None,
        actor: str | None = None,
        issuer: str | None = None,
    ):
        """Initialize identity constraints.

        Args:
            repository: Required repository (e.g., "owner/repo")
            workflow: Required workflow name or path
            actor: Required actor/user
            issuer: Required OIDC issuer
        """
        self.repository = repository
        self.workflow = workflow
        self.actor = actor
        self.issuer = issuer


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

    def __init__(self, staging: bool = False):
        """Initialize the Agent Card verifier.

        Args:
            staging: Use Sigstore staging environment
        """
        self.staging = staging
        self._verifier: Verifier | None = None

    def _get_verifier(self) -> Verifier:
        """Get or create a Sigstore verifier instance."""
        if self._verifier is None:
            if self.staging:
                self._verifier = Verifier.staging()
            else:
                self._verifier = Verifier.production()
        return self._verifier

    def _extract_identity(self, certificate: x509.Certificate) -> dict[str, Any]:
        """Extract identity information from certificate.

        Args:
            certificate: X.509 certificate

        Returns:
            Dictionary containing identity information
        """
        identity = {}

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

    def _check_constraints(self, identity: dict[str, Any], constraints: IdentityConstraints) -> list[str]:
        """Check identity against constraints.

        Args:
            identity: Extracted identity information
            constraints: Required constraints

        Returns:
            List of constraint violations (empty if all pass)
        """
        errors = []

        if constraints.repository:
            repo = identity.get("github_workflow_repository")
            if not repo or repo != constraints.repository:
                errors.append(f"Repository constraint failed: expected {constraints.repository}, got {repo}")

        if constraints.workflow:
            workflow = identity.get("github_workflow_name")
            if not workflow or workflow != constraints.workflow:
                errors.append(f"Workflow constraint failed: expected {constraints.workflow}, got {workflow}")

        if constraints.actor:
            # Actor might be in the URI or email
            uri = identity.get("uri", "")
            email = identity.get("email", "")
            if constraints.actor not in uri and constraints.actor not in email:
                errors.append(f"Actor constraint failed: {constraints.actor} not found in identity")

        if constraints.issuer:
            issuer = identity.get("issuer")
            if not issuer or issuer != constraints.issuer:
                errors.append(f"Issuer constraint failed: expected {constraints.issuer}, got {issuer}")

        return errors

    def verify_signed_card(
        self, signed_card: SignedAgentCard | dict[str, Any] | str | Path, constraints: IdentityConstraints | None = None
    ) -> VerificationResult:
        """Verify a signed Agent Card.

        Args:
            signed_card: Signed agent card to verify
            constraints: Optional identity constraints

        Returns:
            Verification result
        """
        try:
            # Parse signed card input
            if isinstance(signed_card, str | Path):
                if Path(signed_card).exists():
                    with open(signed_card) as f:
                        card_data = json.load(f)
                else:
                    card_data = json.loads(str(signed_card))
            elif isinstance(signed_card, dict):
                card_data = signed_card
            elif isinstance(signed_card, SignedAgentCard):
                card_data = signed_card.model_dump(by_alias=True)
            else:
                return VerificationResult(valid=False, errors=[f"Invalid signed card type: {type(signed_card)}"])

            # Validate signed card structure
            try:
                parsed_signed_card = SignedAgentCard.model_validate(card_data)
            except Exception as e:
                return VerificationResult(valid=False, errors=[f"Invalid signed card structure: {e}"])

            # Extract agent card and signature bundle
            agent_card = parsed_signed_card.agent_card
            sig_bundle = parsed_signed_card.verification_material.signature_bundle

            # Canonicalize agent card for verification
            # canonical_data = canonicalize_json(agent_card.model_dump(by_alias=True))

            # Sigstore verification
            try:
                # Try to reconstruct bundle from signature (which should be JSON in real mode)
                bundle = Bundle.from_json(sig_bundle.signature)
            except Exception as e:
                return VerificationResult(valid=False, errors=[f"Failed to parse Sigstore bundle: {e}"])

            # Verify with GitHub Actions OIDC issuer validation
            verifier = self._get_verifier()
            try:
                # Use OIDCIssuer to validate that the certificate came from GitHub Actions
                # This is more reliable than trying to match specific identity strings
                from sigstore.verify.policy import OIDCIssuer

                policy = AnyOf([OIDCIssuer("https://token.actions.githubusercontent.com")])

                # Verify the bundle
                subject, payload = verifier.verify_dsse(bundle, policy)
            except Exception as e:
                # If verification fails, include the actual identity for debugging
                try:
                    actual_identity = self._extract_identity(bundle.signing_certificate)
                    error_msg = f"Signature verification failed: {e}"
                    if actual_identity:
                        error_msg += f" (Certificate identity: issuer={actual_identity.get('issuer')}, subject={actual_identity.get('subject')})"
                    return VerificationResult(valid=False, errors=[error_msg])
                except Exception:
                    return VerificationResult(valid=False, errors=[f"Signature verification failed: {e}"])

            # Extract identity from certificate
            identity = self._extract_identity(bundle.signing_certificate)

            # Add transparency log information if available
            if hasattr(bundle, 'log_entry') and bundle.log_entry:
                if hasattr(bundle.log_entry, 'log_index'):
                    log_index = bundle.log_entry.log_index
                    identity['transparency_log_index'] = log_index
                    identity['transparency_log_url'] = f"https://search.sigstore.dev/?logIndex={log_index}"

            # Check constraints if provided
            constraint_errors = []
            if constraints:
                constraint_errors = self._check_constraints(identity, constraints)

            if constraint_errors:
                return VerificationResult(
                    valid=False,
                    agent_card=agent_card,
                    certificate=bundle.signing_certificate,
                    identity=identity,
                    errors=constraint_errors,
                )

            return VerificationResult(
                valid=True, agent_card=agent_card, certificate=bundle.signing_certificate, identity=identity
            )

        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Verification failed: {e}"])

    def verify_file(self, file_path: str | Path, constraints: IdentityConstraints | None = None) -> VerificationResult:
        """Verify a signed Agent Card file.

        Args:
            file_path: Path to signed Agent Card file
            constraints: Optional identity constraints

        Returns:
            Verification result
        """
        return self.verify_signed_card(file_path, constraints)
