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

"""Tests for the serve command's FastAPI app endpoints."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from a2a.types import AgentCard
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from google.protobuf.json_format import ParseDict

from sigstore_a2a._signing.sign_certificate import CertificateAgentCardSigner
from sigstore_a2a._signing.sign_ec_key import ECKeyAgentCardSigner
from sigstore_a2a.cli.serve import create_app
from tests.conftest import generate_ec_keypair

FIXTURES_DIR = Path(__file__).parent.parent / "historic"


def _make_signed_card_file(tmp_path: Path, card_data: dict) -> Path:
    """Write a signed card JSON file with the given agent card data."""
    path = tmp_path / "signed-card.json"
    path.write_text(json.dumps({"agentCard": card_data, "attestations": {}}), encoding="utf-8")
    return path


def _mock_signed_card(card_data: dict):
    """Build a mock SignedAgentCard with a real protobuf AgentCard."""
    agent_card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
    mock = MagicMock()
    mock.agent_card = agent_card
    return mock


@pytest.fixture
def v1_card_data():
    return json.loads((FIXTURES_DIR / "v1_0" / "agentcard.json").read_text())


@pytest.fixture
def v0_2_card_data():
    return json.loads((FIXTURES_DIR / "v0_2_x" / "agentcard.json").read_text())


class TestServeEndpoints:
    """Test the FastAPI app endpoints created by create_app."""

    def test_agent_card_endpoint_serves_v1_card(self, tmp_path, v1_card_data):
        """/.well-known/agent.json must serve the agent card data."""
        path = _make_signed_card_file(tmp_path, v1_card_data)
        mock = _mock_signed_card(v1_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/.well-known/agent.json")
                assert resp.status_code == 200
                data = resp.json()
                assert data["name"] == v1_card_data["name"]
                assert "supportedInterfaces" in data

    def test_agent_card_endpoint_serves_v0_2_card(self, tmp_path, v0_2_card_data):
        """/.well-known/agent.json must serve old-format cards (v0.2.x fields dropped by protobuf)."""
        path = _make_signed_card_file(tmp_path, v0_2_card_data)
        mock = _mock_signed_card(v0_2_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/.well-known/agent.json")
                assert resp.status_code == 200
                data = resp.json()
                assert data["name"] == v0_2_card_data["name"]

    def test_signed_card_endpoint_returns_full_envelope(self, tmp_path, v1_card_data):
        """/.well-known/agent.signed.json must return the complete signed card."""
        path = _make_signed_card_file(tmp_path, v1_card_data)
        mock = _mock_signed_card(v1_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/.well-known/agent.signed.json")
                assert resp.status_code == 200
                data = resp.json()
                assert "agentCard" in data
                assert "attestations" in data

    def test_health_endpoint(self, tmp_path, v1_card_data):
        """/health must report healthy status."""
        path = _make_signed_card_file(tmp_path, v1_card_data)
        mock = _mock_signed_card(v1_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200
                assert resp.json()["status"] == "healthy"
                assert resp.json()["agent_loaded"] is True

    def test_root_endpoint_v1_card_shows_url(self, tmp_path, v1_card_data):
        """Root endpoint must extract URL from supportedInterfaces for v1.0 cards."""
        path = _make_signed_card_file(tmp_path, v1_card_data)
        mock = _mock_signed_card(v1_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/")
                assert resp.status_code == 200
                data = resp.json()
                assert data["agent"]["name"] == v1_card_data["name"]
                assert data["agent"]["url"] == v1_card_data["supportedInterfaces"][0]["url"]

    def test_root_endpoint_v0_2_card_url_is_none(self, tmp_path, v0_2_card_data):
        """Root endpoint URL falls back to None for old cards since protobuf drops the url field."""
        path = _make_signed_card_file(tmp_path, v0_2_card_data)
        mock = _mock_signed_card(v0_2_card_data)

        with patch("sigstore_a2a.cli.serve.SignedAgentCard.model_validate", return_value=mock):
            app = create_app(path, verify_on_serve=False)
            with TestClient(app) as client:
                resp = client.get("/")
                assert resp.status_code == 200
                data = resp.json()
                assert data["agent"]["name"] == v0_2_card_data["name"]


SAMPLE_CARD = {
    "name": "serve-test-agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "s1", "name": "Skill", "description": "A skill"}],
}


def _sign_card_with_ec_key(tmp_path: Path):
    key_path, pub_path = generate_ec_keypair(tmp_path / "keys")
    signer = ECKeyAgentCardSigner(private_key_path=key_path)
    signed = signer.sign_agent_card(SAMPLE_CARD)
    signed_path = tmp_path / "signed.json"
    signed_path.write_text(json.dumps(signed.to_dict(), default=str))
    return signed_path, pub_path


class TestServeWithECKey:
    def test_serve_ec_key_signed_card_with_public_key(self, tmp_path):
        signed_path, pub_path = _sign_card_with_ec_key(tmp_path)

        app = create_app(signed_path, verify_on_serve=True, public_key_path=pub_path)
        with TestClient(app) as client:
            resp = client.get("/.well-known/agent.json")
            assert resp.status_code == 200
            assert resp.json()["name"] == "serve-test-agent"

    def test_serve_ec_key_signed_card_wrong_key_fails(self, tmp_path):
        signed_path, _ = _sign_card_with_ec_key(tmp_path)
        _, wrong_pub = generate_ec_keypair(tmp_path / "wrong")

        app = create_app(signed_path, verify_on_serve=True, public_key_path=wrong_pub)
        with pytest.raises(Exception, match="verification failed"):
            with TestClient(app):
                pass

    def test_serve_ec_key_signed_card_no_verify(self, tmp_path):
        signed_path, _ = _sign_card_with_ec_key(tmp_path)

        app = create_app(signed_path, verify_on_serve=False)
        with TestClient(app) as client:
            resp = client.get("/.well-known/agent.json")
            assert resp.status_code == 200

    def test_serve_ec_key_signed_card_endpoints(self, tmp_path):
        signed_path, pub_path = _sign_card_with_ec_key(tmp_path)

        app = create_app(signed_path, verify_on_serve=True, public_key_path=pub_path)
        with TestClient(app) as client:
            signed_resp = client.get("/.well-known/agent.signed.json")
            assert signed_resp.status_code == 200
            assert "attestations" in signed_resp.json()

            health_resp = client.get("/health")
            assert health_resp.json()["status"] == "healthy"


def _sign_card_with_certificate(tmp_path: Path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import oid

    key_path, _ = generate_ec_keypair(tmp_path / "keys")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Serve Test")])
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

    signer = CertificateAgentCardSigner(
        private_key_path=key_path,
        signing_cert_path=cert_path,
        cert_chain_paths=[cert_path],
    )
    signed = signer.sign_agent_card(SAMPLE_CARD)
    signed_path = tmp_path / "signed-cert.json"
    signed_path.write_text(json.dumps(signed.to_dict(), default=str))
    return signed_path, cert_path


class TestServeWithCertificate:
    def test_serve_cert_signed_card_with_chain(self, tmp_path):
        signed_path, cert_path = _sign_card_with_certificate(tmp_path)

        app = create_app(signed_path, verify_on_serve=True, cert_chain_paths=[cert_path])
        with TestClient(app) as client:
            resp = client.get("/.well-known/agent.json")
            assert resp.status_code == 200
            assert resp.json()["name"] == "serve-test-agent"

    def test_serve_cert_signed_card_wrong_chain_fails(self, tmp_path):
        signed_path, _ = _sign_card_with_certificate(tmp_path)
        _, wrong_cert_path = _sign_card_with_certificate(tmp_path / "other")

        app = create_app(signed_path, verify_on_serve=True, cert_chain_paths=[wrong_cert_path])
        with pytest.raises(ValueError, match="verification failed"):
            with TestClient(app):
                pass

    def test_serve_cert_signed_card_no_verify(self, tmp_path):
        signed_path, _ = _sign_card_with_certificate(tmp_path)

        app = create_app(signed_path, verify_on_serve=False)
        with TestClient(app) as client:
            resp = client.get("/.well-known/agent.json")
            assert resp.status_code == 200
