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

"""Tests for EC key signing and verification of Agent Cards."""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore_a2a._signing.sign_ec_key import ECKeyAgentCardSigner
from sigstore_a2a._signing.verify_ec_key import ECKeyAgentCardVerifier
from tests.conftest import generate_ec_keypair

SAMPLE_AGENT_CARD = {
    "name": "test-agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "greeting", "name": "Greeting", "description": "Says hello"}],
}


class TestECKeySigning:
    def test_sign_and_verify_roundtrip(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)
        card_path = tmp_path / "agent-card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(card_path)

        assert signed.agent_card.name == "test-agent"
        assert isinstance(signed.attestations.signature_bundle, dict)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid
        assert result.agent_card.name == "test-agent"

    def test_sign_and_verify_via_file(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)
        card_path = tmp_path / "agent-card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        out_path = signer.sign_file(card_path)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_file(out_path)

        assert result.valid

    def test_wrong_key_fails(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        _, wrong_pub = generate_ec_keypair(tmp_path / "other")

        card_path = tmp_path / "agent-card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(card_path)

        verifier = ECKeyAgentCardVerifier(public_key_path=wrong_pub)
        result = verifier.verify_signed_card(signed)

        assert not result.valid

    def test_sign_with_dict_input(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid

    def test_secp384r1_curve(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path, ec.SECP384R1())

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid

    def test_json_roundtrip(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        card_json = json.dumps(signed.to_dict(), default=str)
        loaded = json.loads(card_json)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(loaded)

        assert result.valid

    def test_secp521r1_curve(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path, ec.SECP521R1())

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid


class TestECKeyEdgeCases:
    def test_rsa_key_rejected_for_signing(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        rsa_key = rsa.generate_private_key(65537, 2048)
        key_path = tmp_path / "rsa.pem"
        key_path.write_bytes(
            rsa_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        with pytest.raises(ValueError, match="elliptic curve"):
            ECKeyAgentCardSigner(private_key_path=key_path)

    def test_rsa_key_rejected_for_verification(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        rsa_key = rsa.generate_private_key(65537, 2048)
        pub_path = tmp_path / "rsa_pub.pem"
        pub_path.write_bytes(
            rsa_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        with pytest.raises(ValueError, match="elliptic curve"):
            ECKeyAgentCardVerifier(public_key_path=pub_path)

    def test_tampered_payload_fails_verification(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        tampered = signed.to_dict()
        tampered["agentCard"]["name"] = "evil-agent"

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(tampered)

        assert result.valid
        assert result.agent_card.name == "test-agent"

    def test_invalid_bundle_returns_error(self, tmp_path):
        _, pub_path = generate_ec_keypair(tmp_path)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card({"agentCard": {}, "attestations": {"signatureBundle": {"bad": True}}})

        assert not result.valid

    def test_invalid_input_type_returns_error(self, tmp_path):
        _, pub_path = generate_ec_keypair(tmp_path)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(12345)

        assert not result.valid

    def test_invalid_json_string_raises_valueerror(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        signer = ECKeyAgentCardSigner(private_key_path=key_path)

        with pytest.raises(ValueError, match="Invalid agent card JSON"):
            signer.sign_agent_card("not valid json {{{")

    def test_wrong_media_type_returns_error(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        bundle_dict = signed.attestations.signature_bundle.copy()
        bundle_dict["mediaType"] = "application/wrong"

        tampered = signed.to_dict()
        tampered["attestations"]["signatureBundle"] = bundle_dict

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(tampered)

        assert not result.valid

    def test_sign_with_agentcard_protobuf(self, tmp_path):
        from a2a.types import AgentCard
        from google.protobuf.json_format import ParseDict

        key_path, pub_path = generate_ec_keypair(tmp_path)

        card = ParseDict(SAMPLE_AGENT_CARD, AgentCard(), ignore_unknown_fields=True)
        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(card)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid
        assert result.agent_card.name == "test-agent"

    def test_sign_with_json_string(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        json_str = json.dumps(SAMPLE_AGENT_CARD)
        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(json_str)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid

    def test_sign_file_explicit_output(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)
        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        out_path = tmp_path / "custom-output.json"

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        result_path = signer.sign_file(card_path, output_path=out_path)

        assert result_path == out_path
        assert out_path.exists()

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_file(out_path)
        assert result.valid

    def test_verify_from_json_string(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        json_str = json.dumps(signed.to_dict(), default=str)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(json_str)

        assert result.valid

    def test_sign_with_provenance(self, tmp_path):
        from sigstore_a2a.provenance import ProvenanceBuilder

        key_path, pub_path = generate_ec_keypair(tmp_path)

        builder = ProvenanceBuilder()
        prov = builder.build_provenance(agent_card=SAMPLE_AGENT_CARD)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD, provenance_bundle=prov)

        assert signed.attestations.provenance_bundle is not None

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)
        assert result.valid

    def test_sign_with_provenance_json_roundtrip(self, tmp_path):
        from sigstore_a2a.provenance import ProvenanceBuilder

        key_path, pub_path = generate_ec_keypair(tmp_path)

        builder = ProvenanceBuilder()
        prov = builder.build_provenance(agent_card=SAMPLE_AGENT_CARD)

        signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD, provenance_bundle=prov)

        card_json = json.dumps(signed.to_dict(), default=str)
        loaded = json.loads(card_json)

        assert "provenanceBundle" in loaded["attestations"]

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(loaded)
        assert result.valid

    def test_password_protected_key(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        private_key = ec.generate_private_key(ec.SECP256R1())
        password = b"test-password"

        key_path = tmp_path / "encrypted.pem"
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password),
            )
        )
        pub_path = tmp_path / "public.pem"
        pub_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        signer = ECKeyAgentCardSigner(private_key_path=key_path, password=password)
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = ECKeyAgentCardVerifier(public_key_path=pub_path)
        result = verifier.verify_signed_card(signed)

        assert result.valid
