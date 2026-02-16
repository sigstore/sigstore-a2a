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

"""Tests for verifier fixes: _build_policy, payload integrity, constraints=None handling."""

import json
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError
from sigstore.verify.policy import (
    AllOf,
    GitHubWorkflowName,
    GitHubWorkflowRepository,
    Identity,
    OIDCIssuer,
    UnsafeNoOp,
)

from sigstore_a2a.verifier import AgentCardVerifier, IdentityConstraints

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

CARD_DATA = {
    "protocolVersion": "0.2.9",
    "name": "Test Agent",
    "description": "A test agent",
    "url": "https://example.com/agent",
    "version": "1.0.0",
    "capabilities": {"streaming": False, "pushNotifications": False},
    "defaultInputModes": ["application/json"],
    "defaultOutputModes": ["application/json"],
    "skills": [
        {
            "id": "test-skill",
            "name": "Test Skill",
            "description": "A test skill",
            "tags": ["test"],
        }
    ],
}


def _make_dsse_payload(predicate: dict) -> bytes:
    """Create an in-toto statement payload containing the given predicate."""
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "Test Agent", "digest": {"sha256": "deadbeef"}}],
        "predicateType": "https://a2a.openwallet.dev/agentcard/v1",
        "predicate": predicate,
    }
    return json.dumps(statement).encode()


# ---------------------------------------------------------------------------
# _build_policy tests
# ---------------------------------------------------------------------------


class TestBuildPolicy:
    """Test that _build_policy produces the correct sigstore policy."""

    def test_constraints_none_no_verifier_defaults_returns_unsafe_noop(self):
        """Bug #3: constraints=None must not crash; returns UnsafeNoOp when
        neither constraints nor verifier-level identity/issuer are set."""
        verifier = AgentCardVerifier()
        policy = verifier._build_policy(None)
        assert isinstance(policy, UnsafeNoOp)

    def test_constraints_none_falls_back_to_verifier_identity_and_issuer(self):
        """When constraints are None, the policy should use the verifier's
        constructor-level identity and oidc_issuer."""
        verifier = AgentCardVerifier(
            identity="dev@example.com",
            oidc_issuer="https://accounts.google.com",
        )
        policy = verifier._build_policy(None)
        assert isinstance(policy, Identity)

    def test_identity_and_issuer_produces_identity_policy(self):
        """Bug #2: When both identity and issuer are given, use Identity (not
        just OIDCIssuer)."""
        verifier = AgentCardVerifier()
        constraints = IdentityConstraints(
            identity="dev@example.com",
            identity_provider="https://accounts.google.com",
        )
        policy = verifier._build_policy(constraints)
        assert isinstance(policy, Identity)

    def test_issuer_only_produces_oidc_issuer_policy(self):
        verifier = AgentCardVerifier()
        constraints = IdentityConstraints(
            identity_provider="https://accounts.google.com"
        )
        policy = verifier._build_policy(constraints)
        assert isinstance(policy, OIDCIssuer)

    def test_identity_only_produces_identity_policy(self):
        verifier = AgentCardVerifier()
        constraints = IdentityConstraints(identity="dev@example.com")
        policy = verifier._build_policy(constraints)
        assert isinstance(policy, Identity)

    def test_github_constraints_produce_allof(self):
        """Repository and workflow constraints should combine into AllOf."""
        verifier = AgentCardVerifier()
        constraints = IdentityConstraints(
            identity="dev@example.com",
            identity_provider="https://accounts.google.com",
            repository="owner/repo",
            workflow="ci",
        )
        policy = verifier._build_policy(constraints)
        assert isinstance(policy, AllOf)

    def test_github_constraints_include_correct_policy_types(self):
        verifier = AgentCardVerifier()
        constraints = IdentityConstraints(
            identity="dev@example.com",
            identity_provider="https://accounts.google.com",
            repository="owner/repo",
            workflow="ci",
        )
        policy = verifier._build_policy(constraints)
        assert isinstance(policy, AllOf)
        child_types = {type(p) for p in policy._children}
        assert Identity in child_types
        assert GitHubWorkflowRepository in child_types
        assert GitHubWorkflowName in child_types

    def test_constraints_override_verifier_defaults(self):
        """Constraint-level values take precedence over verifier defaults."""
        verifier = AgentCardVerifier(
            identity="old@example.com",
            oidc_issuer="https://old-issuer.com",
        )
        constraints = IdentityConstraints(
            identity="new@example.com",
            identity_provider="https://new-issuer.com",
        )
        policy = verifier._build_policy(constraints)
        # Should be Identity (not just OIDCIssuer), built from constraint values
        assert isinstance(policy, Identity)


# ---------------------------------------------------------------------------
# _extract_verified_card tests
# ---------------------------------------------------------------------------


class TestExtractVerifiedCard:
    """Test that _extract_verified_card parses the agent card from the
    authenticated DSSE payload (the source of truth after sigstore
    verification)."""

    def test_valid_payload_returns_agent_card(self):
        """A valid DSSE payload with a proper predicate should return an AgentCard."""
        verifier = AgentCardVerifier()
        payload = _make_dsse_payload(CARD_DATA)

        card = verifier._extract_verified_card(payload)
        assert card.name == "Test Agent"
        assert card.version == "1.0.0"

    def test_empty_predicate_raises(self):
        verifier = AgentCardVerifier()
        payload = _make_dsse_payload({})

        with pytest.raises(ValidationError):
            verifier._extract_verified_card(payload)

    def test_missing_predicate_raises(self):
        verifier = AgentCardVerifier()
        statement = json.dumps({"_type": "...", "subject": []}).encode()

        with pytest.raises(ValueError, match="does not contain a valid predicate"):
            verifier._extract_verified_card(statement)

    def test_malformed_json_raises(self):
        verifier = AgentCardVerifier()
        with pytest.raises(json.JSONDecodeError):
            verifier._extract_verified_card(b"not-json")


# ---------------------------------------------------------------------------
# verify_signed_card integration tests (with mocked sigstore backend)
# ---------------------------------------------------------------------------


def _mock_bundle(card_data: dict):
    """Create a mock Bundle whose verify_dsse returns a matching payload."""
    bundle = MagicMock()
    bundle.signing_certificate = _mock_certificate()
    bundle._payload = _make_dsse_payload(card_data)
    return bundle


def _mock_certificate():
    """Create a minimal mock X.509 certificate with no extensions."""
    from cryptography import x509 as crypto_x509

    cert = MagicMock()
    cert.extensions = MagicMock()
    cert.extensions.get_extension_for_oid = MagicMock(
        side_effect=crypto_x509.ExtensionNotFound(
            "Extension not found", crypto_x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    )
    cert.extensions.__iter__ = MagicMock(return_value=iter([]))
    return cert


class TestVerifySignedCard:
    """Integration tests for verify_signed_card with mocked sigstore backend.

    We mock _parse_signed_card and _get_verifier on the instance to avoid
    needing real Sigstore bundles, while still exercising the full
    verify_signed_card logic (policy building, DSSE verification, payload
    integrity check, identity extraction).
    """

    def _setup_verifier(self, *, card_data=None, dsse_predicate=None, verify_raises=None):
        """Create a verifier with mocked parse + sigstore backend.

        Args:
            card_data: agent card dict (defaults to CARD_DATA)
            dsse_predicate: what the signed DSSE payload predicate contains
                            (defaults to agent_card.model_dump)
            verify_raises: if set, verify_dsse will raise this exception
        """
        from a2a.types import AgentCard

        data = card_data or CARD_DATA
        agent_card = AgentCard.model_validate(data)
        card_json = agent_card.model_dump(by_alias=True, mode="json")

        # Build a mock signed card returned by _parse_signed_card
        mock_signed_card = MagicMock()
        mock_signed_card.agent_card = agent_card
        mock_signed_card.attestations.signature_bundle = _mock_bundle(card_json)

        # Build a mock sigstore Verifier
        mock_sig_verifier = MagicMock()
        if verify_raises:
            mock_sig_verifier.verify_dsse.side_effect = verify_raises
        else:
            predicate = dsse_predicate if dsse_predicate is not None else card_json
            mock_sig_verifier.verify_dsse.return_value = (
                "application/vnd.in-toto+json",
                _make_dsse_payload(predicate),
            )

        verifier = AgentCardVerifier()
        verifier._parse_signed_card = MagicMock(return_value=mock_signed_card)
        verifier._get_verifier = MagicMock(return_value=mock_sig_verifier)
        return verifier

    def test_constraints_none_does_not_crash(self):
        """Bug #3: calling verify_signed_card with constraints=None must not
        raise AttributeError."""
        verifier = self._setup_verifier()
        result = verifier.verify_signed_card({"agentCard": CARD_DATA}, constraints=None)

        assert result.valid is True

    def test_verified_card_comes_from_dsse_payload_not_wrapper(self):
        """Bug #1: The returned agent card must come from the authenticated
        DSSE payload, not the outer wrapper (which could be tampered)."""
        different_name = CARD_DATA.copy()
        different_name["name"] = "Signed Name"

        # The DSSE payload contains "Signed Name", wrapper contains "Test Agent"
        verifier = self._setup_verifier(dsse_predicate=different_name)
        result = verifier.verify_signed_card({"agentCard": CARD_DATA}, constraints=None)

        # Verification succeeds because the DSSE signature is valid
        assert result.valid is True
        # The returned card is from the authenticated payload, not the wrapper
        assert result.agent_card.name == "Signed Name"

    def test_sigstore_verification_failure_reports_error(self):
        """When sigstore's verify_dsse raises, we get a clear error."""
        verifier = self._setup_verifier(verify_raises=Exception("certificate expired"))
        result = verifier.verify_signed_card({"agentCard": CARD_DATA}, constraints=None)

        assert result.valid is False
        assert any("certificate expired" in e for e in result.errors)

    def test_successful_verification_returns_agent_card_and_identity(self):
        verifier = self._setup_verifier()
        result = verifier.verify_signed_card({"agentCard": CARD_DATA}, constraints=None)

        assert result.valid is True
        assert result.agent_card is not None
        assert result.agent_card.name == "Test Agent"

    def test_invalid_input_type_returns_error(self):
        verifier = AgentCardVerifier()
        result = verifier.verify_signed_card(12345)  # type: ignore[arg-type]
        assert result.valid is False
        assert any("Invalid signed card" in e for e in result.errors)

    def test_malformed_dict_returns_error(self):
        verifier = AgentCardVerifier()
        result = verifier.verify_signed_card({"not": "a signed card"})
        assert result.valid is False
        assert any("Invalid signed card" in e for e in result.errors)


# ---------------------------------------------------------------------------
# _parse_signed_card tests
# ---------------------------------------------------------------------------


class TestParseSignedCard:
    """Test _parse_signed_card handles all input types."""

    def test_signed_card_instance_returned_directly(self):
        """Bug #12: a SignedAgentCard instance should not be round-tripped."""
        mock_card = MagicMock(spec=["agent_card", "attestations", "model_dump"])
        # Make isinstance check work
        mock_card.__class__ = type(
            "SignedAgentCard",
            (),
            {},
        )

        # Directly test that a real SignedAgentCard is not re-parsed
        from sigstore_a2a.models.signature import SignedAgentCard

        verifier = AgentCardVerifier()

        sentinel = MagicMock(spec=SignedAgentCard)
        sentinel.__class__ = SignedAgentCard
        result = verifier._parse_signed_card(sentinel)
        assert result is sentinel

    def test_invalid_type_raises_type_error(self):
        verifier = AgentCardVerifier()
        with pytest.raises(TypeError, match="Invalid signed card type"):
            verifier._parse_signed_card(42)  # type: ignore[arg-type]
