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

"""Backward and forward compatibility tests for AgentCard schema versions.

Maintains historic AgentCard fixtures from different a2a-sdk versions and
verifies that the current code can parse, serialize, and verify cards from
all supported schema versions. This is the sigstore-a2a equivalent of
model-transparency's historic signature tests.

Fixture layout:
    tests/historic/v0_2_x/   -- cards signed with a2a-sdk 0.2.x (Pydantic)
    tests/historic/v1_0/     -- cards using a2a-sdk 1.x (protobuf)
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from a2a.types import AgentCard
from google.protobuf.json_format import MessageToDict, ParseDict

from sigstore_a2a.models.signature import SignedAgentCard
from sigstore_a2a.verifier import AgentCardVerifier

FIXTURES_DIR = Path(__file__).parent / "historic"

# ---------------------------------------------------------------------------
# Historic fixture data — fields unique to each schema version
# ---------------------------------------------------------------------------

V0_2_X_ONLY_FIELDS = [
    "protocolVersion",
    "url",
    "preferredTransport",
    "additionalInterfaces",
    "security",
    "supportsAuthenticatedExtendedCard",
]

V1_0_ONLY_FIELDS = [
    "supportedInterfaces",
]

# Fields that survived across both schema versions
COMMON_FIELDS = ["name", "description", "version", "skills", "provider"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture(version_dir: str, filename: str) -> dict[str, Any]:
    """Load a JSON fixture from the versioned historic test data directory."""
    path = FIXTURES_DIR / version_dir / filename
    return json.loads(path.read_text())


def _make_dsse_payload(predicate: dict) -> bytes:
    """Create an in-toto statement payload wrapping the given predicate."""
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": predicate.get("name", "test"), "digest": {"sha256": "deadbeef"}}],
        "predicateType": "https://a2a.openwallet.dev/agentcard/v1",
        "predicate": predicate,
    }
    return json.dumps(statement).encode()


def _mock_certificate():
    """Create a minimal mock X.509 certificate with no extensions."""
    from cryptography import x509

    cert = MagicMock()
    cert.extensions = MagicMock()
    cert.extensions.get_extension_for_oid = MagicMock(
        side_effect=x509.ExtensionNotFound("not found", x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    )
    cert.extensions.__iter__ = MagicMock(return_value=iter([]))
    return cert


def _mock_bundle(card_data: dict):
    """Create a mock Bundle whose payload matches the given card data."""
    bundle = MagicMock()
    bundle.signing_certificate = _mock_certificate()
    bundle._payload = _make_dsse_payload(card_data)
    return bundle


def _setup_verifier_with_card(card_data: dict) -> AgentCardVerifier:
    """Create a verifier with mocked sigstore backend returning the given card data."""
    agent_card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
    card_json = MessageToDict(agent_card)

    mock_signed_card = MagicMock()
    mock_signed_card.agent_card = agent_card
    mock_signed_card.attestations.signature_bundle = _mock_bundle(card_json)

    mock_sig_verifier = MagicMock()
    mock_sig_verifier.verify_dsse.return_value = (
        "application/vnd.in-toto+json",
        _make_dsse_payload(card_data),
    )

    verifier = AgentCardVerifier()
    verifier._parse_signed_card = MagicMock(return_value=mock_signed_card)
    verifier._get_verifier = MagicMock(return_value=mock_sig_verifier)
    return verifier


# ---------------------------------------------------------------------------
# Test: ParseDict compatibility across schema versions
# ---------------------------------------------------------------------------


class TestParseDictCompat:
    """Verify that ParseDict with ignore_unknown_fields=True can parse cards from all schema versions."""

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v0_2_x", "agentcard_minimal.json"),
            ("v1_0", "agentcard.json"),
            ("v1_0", "agentcard_minimal.json"),
        ],
    )
    def test_parse_succeeds(self, version_dir: str, filename: str):
        """ParseDict must not raise for any supported schema version."""
        card_data = _load_fixture(version_dir, filename)
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        assert card.name == card_data["name"]
        assert card.version == card_data["version"]

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v0_2_x", "agentcard_minimal.json"),
        ],
    )
    def test_v0_2_x_core_fields_survive(self, version_dir: str, filename: str):
        """Core identity fields from v0.2.x cards must survive protobuf parsing."""
        card_data = _load_fixture(version_dir, filename)
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)

        assert card.name == card_data["name"]
        assert card.description == card_data["description"]
        assert card.version == card_data["version"]
        assert len(card.skills) == len(card_data["skills"])
        for i, skill in enumerate(card.skills):
            assert skill.name == card_data["skills"][i]["name"]

    def test_v1_0_supported_interfaces_parsed(self):
        """v1.0 cards with supportedInterfaces must parse correctly."""
        card_data = _load_fixture("v1_0", "agentcard.json")
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)

        assert len(card.supported_interfaces) == 2
        assert card.supported_interfaces[0].url == "https://georoute-agent.example.com/a2a/v1"

    def test_v0_2_x_unknown_fields_dropped_silently(self):
        """Fields unique to v0.2.x must be silently dropped, not cause errors."""
        card_data = _load_fixture("v0_2_x", "agentcard.json")
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        card_dict = MessageToDict(card)

        for field in V0_2_X_ONLY_FIELDS:
            assert field not in card_dict, f"v0.2.x-only field '{field}' should have been dropped"


# ---------------------------------------------------------------------------
# Test: SignedAgentCard model compatibility
# ---------------------------------------------------------------------------


def _build_signed_card(card_data: dict) -> SignedAgentCard:
    """Build a SignedAgentCard with a mocked Attestations bundle."""
    agent_card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
    attestations = MagicMock()
    attestations.model_dump.return_value = {"signatureBundle": {}}
    signed = SignedAgentCard.__new__(SignedAgentCard)
    object.__setattr__(signed, "agent_card", agent_card)
    object.__setattr__(signed, "attestations", attestations)
    object.__setattr__(signed, "_raw_card_data", card_data)
    return signed


class TestSignedAgentCardCompat:
    """Verify that SignedAgentCard can wrap cards from all schema versions."""

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v0_2_x", "agentcard_minimal.json"),
            ("v1_0", "agentcard.json"),
            ("v1_0", "agentcard_minimal.json"),
        ],
    )
    def test_signed_card_preserves_identity_fields(self, version_dir: str, filename: str):
        """SignedAgentCard must preserve core identity fields from any schema version."""
        card_data = _load_fixture(version_dir, filename)
        signed = _build_signed_card(card_data)

        assert signed.name == card_data["name"]
        assert signed.version == card_data["version"]

    def test_v0_2_x_card_url_property_falls_back(self):
        """The url property must return empty string for old cards without supported_interfaces."""
        card_data = _load_fixture("v0_2_x", "agentcard.json")
        signed = _build_signed_card(card_data)
        assert signed.url == ""

    def test_v1_0_card_url_property_uses_supported_interfaces(self):
        """The url property must return the first supported interface URL for v1.0 cards."""
        card_data = _load_fixture("v1_0", "agentcard.json")
        signed = _build_signed_card(card_data)
        assert signed.url == "https://georoute-agent.example.com/a2a/v1"

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v1_0", "agentcard.json"),
        ],
    )
    def test_to_dict_roundtrip(self, version_dir: str, filename: str):
        """to_dict must produce a serializable dict for cards from any schema version."""
        card_data = _load_fixture(version_dir, filename)
        signed = _build_signed_card(card_data)

        result = signed.to_dict()
        assert "agentCard" in result
        assert "attestations" in result
        assert result["agentCard"]["name"] == card_data["name"]
        json.dumps(result)

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v1_0", "agentcard.json"),
        ],
    )
    def test_to_dict_without_raw_card_data(self, version_dir: str, filename: str):
        """to_dict falls back to MessageToDict when _raw_card_data is None."""
        card_data = _load_fixture(version_dir, filename)
        signed = _build_signed_card(card_data)
        object.__setattr__(signed, "_raw_card_data", None)

        result = signed.to_dict()
        assert "agentCard" in result
        assert "attestations" in result
        assert result["agentCard"]["name"] == card_data["name"]
        json.dumps(result)


# ---------------------------------------------------------------------------
# Test: Verification flow with historic card formats
# ---------------------------------------------------------------------------


class TestVerificationCompat:
    """Verify the full verification flow preserves backward compatibility."""

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v0_2_x", "agentcard_minimal.json"),
            ("v1_0", "agentcard.json"),
            ("v1_0", "agentcard_minimal.json"),
        ],
    )
    def test_verification_succeeds_for_all_versions(self, version_dir: str, filename: str):
        """Verification must succeed for cards from any supported schema version."""
        card_data = _load_fixture(version_dir, filename)
        verifier = _setup_verifier_with_card(card_data)

        result = verifier.verify_signed_card({"agentCard": card_data})
        assert result.valid is True
        assert result.agent_card is not None
        assert result.agent_card.name == card_data["name"]

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v0_2_x", "agentcard_minimal.json"),
        ],
    )
    def test_v0_2_x_raw_card_data_preserves_legacy_fields(self, version_dir: str, filename: str):
        """raw_card_data must retain v0.2.x fields that ParseDict drops."""
        card_data = _load_fixture(version_dir, filename)
        verifier = _setup_verifier_with_card(card_data)

        result = verifier.verify_signed_card({"agentCard": card_data})
        assert result.valid is True

        assert result.raw_card_data.get("url") == card_data.get("url")
        assert result.raw_card_data.get("protocolVersion") == card_data.get("protocolVersion")

    def test_v0_2_x_full_card_all_legacy_fields_in_raw_data(self):
        """Every v0.2.x-only field must be preserved in raw_card_data."""
        card_data = _load_fixture("v0_2_x", "agentcard.json")
        verifier = _setup_verifier_with_card(card_data)

        result = verifier.verify_signed_card({"agentCard": card_data})
        assert result.valid is True

        for field in V0_2_X_ONLY_FIELDS:
            if field in card_data:
                assert field in result.raw_card_data, f"Legacy field '{field}' missing from raw_card_data"
                assert result.raw_card_data[field] == card_data[field]

    def test_v1_0_raw_card_data_matches_input(self):
        """For v1.0 cards, raw_card_data should match the original input."""
        card_data = _load_fixture("v1_0", "agentcard.json")
        verifier = _setup_verifier_with_card(card_data)

        result = verifier.verify_signed_card({"agentCard": card_data})
        assert result.valid is True
        assert result.raw_card_data["name"] == card_data["name"]
        assert result.raw_card_data["supportedInterfaces"] == card_data["supportedInterfaces"]


# ---------------------------------------------------------------------------
# Test: MessageToDict serialization compatibility
# ---------------------------------------------------------------------------


class TestSerializationCompat:
    """Verify that MessageToDict produces correct output for all schema versions."""

    def test_v0_2_x_card_roundtrips_through_protobuf(self):
        """A v0.2.x card parsed then serialized must retain all common fields."""
        card_data = _load_fixture("v0_2_x", "agentcard.json")
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        output = MessageToDict(card)

        for field in COMMON_FIELDS:
            if field in card_data and field in output:
                if field == "skills":
                    assert len(output["skills"]) == len(card_data["skills"])
                elif field == "provider":
                    assert output["provider"]["organization"] == card_data["provider"]["organization"]
                else:
                    assert output[field] == card_data[field], f"Field '{field}' mismatch after roundtrip"

    def test_v1_0_card_roundtrips_losslessly(self):
        """A v1.0 card must roundtrip through ParseDict/MessageToDict without data loss."""
        card_data = _load_fixture("v1_0", "agentcard.json")
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        output = MessageToDict(card)

        assert output["name"] == card_data["name"]
        assert output["version"] == card_data["version"]
        assert len(output["supportedInterfaces"]) == len(card_data["supportedInterfaces"])
        assert output["supportedInterfaces"][0]["url"] == card_data["supportedInterfaces"][0]["url"]
        assert output["provider"]["organization"] == card_data["provider"]["organization"]

    def test_v0_2_x_dropped_fields_not_in_output(self):
        """Fields dropped by ParseDict must not appear in MessageToDict output."""
        card_data = _load_fixture("v0_2_x", "agentcard.json")
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        output = MessageToDict(card)

        for field in V0_2_X_ONLY_FIELDS:
            assert field not in output, f"Dropped field '{field}' unexpectedly present in MessageToDict output"


# ---------------------------------------------------------------------------
# Test: Cross-version provenance compatibility
# ---------------------------------------------------------------------------


class TestProvenanceCompat:
    """Verify provenance operations work with cards from all schema versions."""

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v1_0", "agentcard.json"),
        ],
    )
    def test_create_subject_from_fixture(self, version_dir: str, filename: str):
        """ProvenanceBuilder.create_subject must work with cards from all versions."""
        from sigstore_a2a.provenance import ProvenanceBuilder

        card_data = _load_fixture(version_dir, filename)
        builder = ProvenanceBuilder()
        subject = builder.create_subject(card_data)

        assert subject.name is not None
        assert subject.digest.sha256 is not None
        assert len(subject.digest.sha256) > 0

    @pytest.mark.parametrize(
        "version_dir,filename",
        [
            ("v0_2_x", "agentcard.json"),
            ("v1_0", "agentcard.json"),
        ],
    )
    def test_create_subject_from_parsed_card(self, version_dir: str, filename: str):
        """ProvenanceBuilder.create_subject must work with protobuf AgentCard objects."""
        from sigstore_a2a.provenance import ProvenanceBuilder

        card_data = _load_fixture(version_dir, filename)
        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        builder = ProvenanceBuilder()
        subject = builder.create_subject(card)

        assert subject.name is not None
        assert subject.digest.sha256 is not None
