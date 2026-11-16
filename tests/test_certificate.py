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

"""Tests for certificate-based signing and verification of Agent Cards."""

import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid

from sigstore_a2a._signing.sign_certificate import CertificateAgentCardSigner
from sigstore_a2a._signing.verify_certificate import CertificateAgentCardVerifier
from tests.conftest import generate_ec_keypair

SAMPLE_AGENT_CARD = {
    "name": "cert-test-agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "s1", "name": "Skill", "description": "A skill"}],
}


def _generate_self_signed_cert(tmp: Path, private_key, san_uris=None):
    tmp.mkdir(parents=True, exist_ok=True)
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Test Signer")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    )
    if san_uris:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in san_uris]),
            critical=False,
        )
    cert = builder.sign(private_key, hashes.SHA256())
    cert_path = tmp / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, private_key


class TestCertificateSigning:
    def test_sign_and_verify_roundtrip(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        assert signed.agent_card.name == "cert-test-agent"
        bundle = signed.attestations.signature_bundle
        assert "x509CertificateChain" in bundle.get("verificationMaterial", {})

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(signed)

        assert result.valid
        assert result.agent_card.name == "cert-test-agent"
        assert result.certificate is not None

    def test_sign_and_verify_via_file(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        out_path = signer.sign_file(card_path)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_file(out_path)

        assert result.valid

    def test_json_roundtrip(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        card_json = json.dumps(signed.to_dict(), default=str)
        loaded = json.loads(card_json)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(loaded)

        assert result.valid

    def test_with_provenance(self, tmp_path):
        from sigstore_a2a.provenance import ProvenanceBuilder

        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        prov = ProvenanceBuilder().build_provenance(agent_card=SAMPLE_AGENT_CARD)
        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD, provenance_bundle=prov)

        assert signed.attestations.provenance_bundle is not None

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(signed)
        assert result.valid


class TestCertificateEdgeCases:
    def test_key_cert_mismatch_rejected(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        other_key = ec.generate_private_key(ec.SECP256R1())
        cert_path, _ = _generate_self_signed_cert(tmp_path, other_key)

        with pytest.raises(ValueError, match="does not match"):
            CertificateAgentCardSigner(
                private_key_path=key_path,
                signing_cert_path=cert_path,
            )

    def test_expired_cert_rejected(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Expired")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=365))
            .not_valid_after(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "expired.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(ValueError, match="expired"):
            CertificateAgentCardSigner(private_key_path=key_path, signing_cert_path=cert_path)

    def test_wrong_trust_chain_fails(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        other_key = ec.generate_private_key(ec.SECP256R1())
        wrong_ca_path, _ = _generate_self_signed_cert(tmp_path / "wrong", other_key)

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[wrong_ca_path])
        result = verifier.verify_signed_card(signed)

        assert not result.valid

    def test_san_uri_pinning_success(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key, san_uris=["spiffe://example.com/agent"])

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(
            cert_chain_paths=[cert_path],
            expected_san_uris=["spiffe://example.com/agent"],
        )
        result = verifier.verify_signed_card(signed)
        assert result.valid

    def test_san_uri_pinning_failure(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key, san_uris=["spiffe://example.com/agent"])

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(
            cert_chain_paths=[cert_path],
            expected_san_uris=["spiffe://wrong.com/other"],
        )
        result = verifier.verify_signed_card(signed)
        assert not result.valid

    def test_no_code_signing_eku_rejected(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "TLS Only")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "tls.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(signed)

        assert not result.valid
        assert "cannot be used for signing" in result.errors[0]

    def test_not_yet_valid_cert_rejected(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Future")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "future.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(ValueError, match="not yet valid"):
            CertificateAgentCardSigner(private_key_path=key_path, signing_cert_path=cert_path)

    def test_san_uri_required_but_cert_has_no_san(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_path, _ = _generate_self_signed_cert(tmp_path, private_key)

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(
            cert_chain_paths=[cert_path],
            expected_san_uris=["spiffe://example.com/required"],
        )
        result = verifier.verify_signed_card(signed)
        assert not result.valid
        assert "SubjectAlternativeName" in result.errors[0]

    def test_bundle_with_no_certificate_chain_returns_error(self, tmp_path):
        from sigstore_a2a._signing.sign_ec_key import ECKeyAgentCardSigner

        key_path, _ = generate_ec_keypair(tmp_path)
        ec_signer = ECKeyAgentCardSigner(private_key_path=key_path)
        signed = ec_signer.sign_agent_card(SAMPLE_AGENT_CARD)

        cert_path, _ = _generate_self_signed_cert(
            tmp_path / "ca",
            serialization.load_pem_private_key(key_path.read_bytes(), password=None),
        )
        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(signed)

        assert not result.valid
        assert "no certificate chain" in result.errors[0].lower() or "verification failed" in result.errors[0].lower()

    def test_cert_with_no_key_usage_or_eku(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Bare Cert")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "bare.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        signer = CertificateAgentCardSigner(
            private_key_path=key_path,
            signing_cert_path=cert_path,
            cert_chain_paths=[cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[cert_path])
        result = verifier.verify_signed_card(signed)

        assert not result.valid
        assert "cannot be used for signing" in result.errors[0]


def _build_ca_and_leaf(tmp: Path, leaf_san_uris=None):
    """Generate a root CA cert and a leaf cert signed by it."""
    tmp.mkdir(parents=True, exist_ok=True)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Leaf Signer")])
    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    )
    if leaf_san_uris:
        leaf_builder = leaf_builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in leaf_san_uris]),
            critical=False,
        )
    leaf_cert = leaf_builder.sign(ca_key, hashes.SHA256())
    leaf_cert_path = tmp / "leaf.pem"
    leaf_cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))

    leaf_key_path = tmp / "leaf_key.pem"
    leaf_key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    return ca_path, leaf_key_path, leaf_cert_path


class TestCALeafChain:
    def test_sign_with_leaf_verify_with_ca(self, tmp_path):
        ca_path, leaf_key_path, leaf_cert_path = _build_ca_and_leaf(tmp_path)

        signer = CertificateAgentCardSigner(
            private_key_path=leaf_key_path,
            signing_cert_path=leaf_cert_path,
            cert_chain_paths=[leaf_cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[ca_path])
        result = verifier.verify_signed_card(signed)

        assert result.valid
        assert result.agent_card.name == "cert-test-agent"
        assert result.certificate is not None
        assert "Leaf Signer" in result.certificate.subject.rfc4514_string()

    def test_leaf_with_san_verified_by_ca(self, tmp_path):
        ca_path, leaf_key_path, leaf_cert_path = _build_ca_and_leaf(
            tmp_path, leaf_san_uris=["spiffe://example.com/agent"]
        )

        signer = CertificateAgentCardSigner(
            private_key_path=leaf_key_path,
            signing_cert_path=leaf_cert_path,
            cert_chain_paths=[leaf_cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(
            cert_chain_paths=[ca_path],
            expected_san_uris=["spiffe://example.com/agent"],
        )
        result = verifier.verify_signed_card(signed)
        assert result.valid

    def test_leaf_wrong_ca_fails(self, tmp_path):
        _, leaf_key_path, leaf_cert_path = _build_ca_and_leaf(tmp_path)
        other_ca_path, _, _ = _build_ca_and_leaf(tmp_path / "other_ca")

        signer = CertificateAgentCardSigner(
            private_key_path=leaf_key_path,
            signing_cert_path=leaf_cert_path,
            cert_chain_paths=[leaf_cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[other_ca_path])
        result = verifier.verify_signed_card(signed)
        assert not result.valid

    def test_leaf_san_mismatch_fails(self, tmp_path):
        ca_path, leaf_key_path, leaf_cert_path = _build_ca_and_leaf(
            tmp_path, leaf_san_uris=["spiffe://example.com/agent"]
        )

        signer = CertificateAgentCardSigner(
            private_key_path=leaf_key_path,
            signing_cert_path=leaf_cert_path,
            cert_chain_paths=[leaf_cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        verifier = CertificateAgentCardVerifier(
            cert_chain_paths=[ca_path],
            expected_san_uris=["spiffe://wrong.com/other"],
        )
        result = verifier.verify_signed_card(signed)
        assert not result.valid

    def test_json_roundtrip_with_ca_leaf(self, tmp_path):
        ca_path, leaf_key_path, leaf_cert_path = _build_ca_and_leaf(tmp_path)

        signer = CertificateAgentCardSigner(
            private_key_path=leaf_key_path,
            signing_cert_path=leaf_cert_path,
            cert_chain_paths=[leaf_cert_path],
        )
        signed = signer.sign_agent_card(SAMPLE_AGENT_CARD)

        loaded = json.loads(json.dumps(signed.to_dict(), default=str))

        verifier = CertificateAgentCardVerifier(cert_chain_paths=[ca_path])
        result = verifier.verify_signed_card(loaded)
        assert result.valid
