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

"""Tests for the high-level Config builder APIs (signing.py / verifying.py)."""

import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import oid

from sigstore_a2a.signing import SigningConfig
from sigstore_a2a.verifying import VerifyingConfig
from tests.conftest import generate_ec_keypair

SAMPLE_CARD = {
    "name": "config-test-agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "s1", "name": "Skill", "description": "A skill"}],
}


def _make_cert(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    key_path, _ = generate_ec_keypair(tmp_path / "keys")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Config Test")])
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
        .add_extension(x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


class TestSigningConfig:
    def test_ec_key_sign_card(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)

        signed = SigningConfig().use_elliptic_key_signer(private_key=key_path).sign_card(SAMPLE_CARD)

        assert signed.agent_card.name == "config-test-agent"

    def test_ec_key_sign_to_file(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        out = tmp_path / "signed.json"

        result_path = SigningConfig().use_elliptic_key_signer(private_key=key_path).sign(SAMPLE_CARD, out)

        assert result_path == out
        assert out.exists()
        data = json.loads(out.read_text())
        assert "agentCard" in data
        assert "attestations" in data

    def test_certificate_sign_card(self, tmp_path):
        key_path, cert_path = _make_cert(tmp_path)

        signed = (
            SigningConfig()
            .use_certificate_signer(private_key=key_path, signing_cert=cert_path, cert_chain=[cert_path])
            .sign_card(SAMPLE_CARD)
        )

        assert signed.agent_card.name == "config-test-agent"
        bundle = signed.attestations.signature_bundle
        assert "x509CertificateChain" in bundle.get("verificationMaterial", {})

    def test_default_is_sigstore(self):
        config = SigningConfig()
        config._get_signer()
        from sigstore_a2a._signing.sign_sigstore import AgentCardSigner

        assert isinstance(config._signer, AgentCardSigner)

    def test_last_use_wins(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)

        config = SigningConfig().use_sigstore_signer().use_elliptic_key_signer(private_key=key_path)

        from sigstore_a2a._signing.sign_ec_key import ECKeyAgentCardSigner

        assert isinstance(config._signer, ECKeyAgentCardSigner)

    def test_sign_with_provenance(self, tmp_path):
        from sigstore_a2a.provenance import ProvenanceBuilder

        key_path, _ = generate_ec_keypair(tmp_path)
        prov = ProvenanceBuilder().build_provenance(agent_card=SAMPLE_CARD)

        signed = (
            SigningConfig().use_elliptic_key_signer(private_key=key_path).sign_card(SAMPLE_CARD, provenance_bundle=prov)
        )

        assert signed.attestations.provenance_bundle is not None

    def test_chaining_returns_self(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)

        config = SigningConfig()
        result = config.use_elliptic_key_signer(private_key=key_path)

        assert result is config


class TestVerifyingConfig:
    def test_ec_key_verify(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)

        signed = SigningConfig().use_elliptic_key_signer(private_key=key_path).sign_card(SAMPLE_CARD)

        result = VerifyingConfig().use_elliptic_key_verifier(public_key=pub_path).verify(signed)

        assert result.valid
        assert result.agent_card.name == "config-test-agent"

    def test_certificate_verify(self, tmp_path):
        key_path, cert_path = _make_cert(tmp_path)

        signed = (
            SigningConfig()
            .use_certificate_signer(private_key=key_path, signing_cert=cert_path, cert_chain=[cert_path])
            .sign_card(SAMPLE_CARD)
        )

        result = VerifyingConfig().use_certificate_verifier(cert_chain=[cert_path]).verify(signed)

        assert result.valid
        assert result.certificate is not None

    def test_no_method_raises(self):
        with pytest.raises(ValueError, match="No verification method selected"):
            VerifyingConfig().verify({"agentCard": {}, "attestations": {}})

    def test_verify_file(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)
        out = tmp_path / "signed.json"

        SigningConfig().use_elliptic_key_signer(private_key=key_path).sign(SAMPLE_CARD, out)

        result = VerifyingConfig().use_elliptic_key_verifier(public_key=pub_path).verify_file(out)

        assert result.valid

    def test_wrong_key_fails(self, tmp_path):
        key_path, _ = generate_ec_keypair(tmp_path)
        _, wrong_pub = generate_ec_keypair(tmp_path / "wrong")

        signed = SigningConfig().use_elliptic_key_signer(private_key=key_path).sign_card(SAMPLE_CARD)

        result = VerifyingConfig().use_elliptic_key_verifier(public_key=wrong_pub).verify(signed)

        assert not result.valid

    def test_chaining_returns_self(self, tmp_path):
        _, pub_path = generate_ec_keypair(tmp_path)

        config = VerifyingConfig()
        result = config.use_elliptic_key_verifier(public_key=pub_path)

        assert result is config

    def test_last_use_wins(self, tmp_path):
        _, pub_path = generate_ec_keypair(tmp_path)

        config = VerifyingConfig().use_sigstore_verifier().use_elliptic_key_verifier(public_key=pub_path)

        from sigstore_a2a._signing.verify_ec_key import ECKeyAgentCardVerifier

        assert isinstance(config._verifier, ECKeyAgentCardVerifier)


class TestEndToEnd:
    def test_sign_config_verify_config_ec_key(self, tmp_path):
        key_path, pub_path = generate_ec_keypair(tmp_path)
        out = tmp_path / "signed.json"

        SigningConfig().use_elliptic_key_signer(private_key=key_path).sign(SAMPLE_CARD, out)
        result = VerifyingConfig().use_elliptic_key_verifier(public_key=pub_path).verify_file(out)

        assert result.valid

    def test_sign_config_verify_config_certificate(self, tmp_path):
        key_path, cert_path = _make_cert(tmp_path)
        out = tmp_path / "signed.json"

        SigningConfig().use_certificate_signer(
            private_key=key_path, signing_cert=cert_path, cert_chain=[cert_path]
        ).sign(SAMPLE_CARD, out)

        result = VerifyingConfig().use_certificate_verifier(cert_chain=[cert_path]).verify_file(out)

        assert result.valid
