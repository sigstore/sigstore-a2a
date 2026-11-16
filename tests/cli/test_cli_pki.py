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

"""CLI tests for sign key / verify key subcommands."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from sigstore_a2a.cli.main import cli
from tests.conftest import generate_ec_keypair

SAMPLE_AGENT_CARD = {
    "name": "cli-test-agent",
    "version": "2.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "s1", "name": "Skill", "description": "A skill"}],
}


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    return generate_ec_keypair(tmp_path)


@pytest.fixture
def card_path(tmp_path: Path) -> Path:
    p = tmp_path / "agent-card.json"
    p.write_text(json.dumps(SAMPLE_AGENT_CARD))
    return p


class TestSignKey:
    def test_sign_key_produces_output(self, runner, keypair, card_path, tmp_path):
        key_path, _ = keypair
        out = tmp_path / "signed.json"

        result = runner.invoke(cli, ["sign", "key", str(card_path), "--private-key", str(key_path), "-o", str(out)])

        assert result.exit_code == 0, result.output
        assert out.exists()
        data = json.loads(out.read_text())
        assert "agentCard" in data
        assert "attestations" in data

    def test_sign_key_default_output(self, runner, keypair, card_path):
        key_path, _ = keypair

        result = runner.invoke(cli, ["sign", "key", str(card_path), "--private-key", str(key_path)])

        assert result.exit_code == 0, result.output
        default_out = card_path.with_suffix(".signed.json")
        assert default_out.exists()

    def test_sign_key_missing_private_key_errors(self, runner, card_path):
        result = runner.invoke(cli, ["sign", "key", str(card_path)])

        assert result.exit_code != 0
        assert "private-key" in result.output.lower() or "required" in result.output.lower()

    def test_sign_key_with_provenance(self, runner, keypair, card_path, tmp_path):
        key_path, pub_path = keypair
        out = tmp_path / "signed-prov.json"

        result = runner.invoke(
            cli,
            [
                "sign",
                "key",
                str(card_path),
                "--private-key",
                str(key_path),
                "-o",
                str(out),
                "--provenance",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "provenanceBundle" in data["attestations"]

        verify_result = runner.invoke(cli, ["verify", "key", str(out), "--public-key", str(pub_path)])
        assert verify_result.exit_code == 0, verify_result.output

    def test_sign_key_with_provenance_metadata(self, runner, keypair, card_path, tmp_path):
        key_path, _ = keypair
        out = tmp_path / "signed-prov-meta.json"

        result = runner.invoke(
            cli,
            [
                "sign",
                "key",
                str(card_path),
                "--private-key",
                str(key_path),
                "-o",
                str(out),
                "--provenance",
                "--repository",
                "owner/repo",
                "--commit_sha",
                "abc123",
                "--workflow_ref",
                ".github/workflows/ci.yml@refs/heads/main",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "provenanceBundle" in data["attestations"]

    def test_sign_key_without_provenance_has_no_provenance(self, runner, keypair, card_path, tmp_path):
        key_path, _ = keypair
        out = tmp_path / "signed-no-prov.json"

        result = runner.invoke(
            cli,
            ["sign", "key", str(card_path), "--private-key", str(key_path), "-o", str(out)],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "provenanceBundle" not in data["attestations"]

    def test_sign_key_nonexistent_key_errors(self, runner, card_path, tmp_path):
        fake_key = tmp_path / "no-such-key.pem"

        result = runner.invoke(cli, ["sign", "key", str(card_path), "--private-key", str(fake_key)])

        assert result.exit_code != 0


class TestVerifyKey:
    def test_verify_key_success(self, runner, keypair, card_path, tmp_path):
        key_path, pub_path = keypair
        out = tmp_path / "signed.json"

        runner.invoke(cli, ["sign", "key", str(card_path), "--private-key", str(key_path), "-o", str(out)])

        result = runner.invoke(cli, ["verify", "key", str(out), "--public-key", str(pub_path)])

        assert result.exit_code == 0, result.output
        assert "valid" in result.output.lower()
        assert "cli-test-agent" in result.output

    def test_verify_key_wrong_key_fails(self, runner, keypair, card_path, tmp_path):
        key_path, _ = keypair
        out = tmp_path / "signed.json"

        runner.invoke(cli, ["sign", "key", str(card_path), "--private-key", str(key_path), "-o", str(out)])

        _, wrong_pub = generate_ec_keypair(tmp_path / "wrong")

        result = runner.invoke(cli, ["verify", "key", str(out), "--public-key", str(wrong_pub)])

        assert result.exit_code != 0

    def test_verify_key_missing_public_key_errors(self, runner, tmp_path):
        dummy = tmp_path / "dummy.json"
        dummy.write_text("{}")

        result = runner.invoke(cli, ["verify", "key", str(dummy)])

        assert result.exit_code != 0
        assert "public-key" in result.output.lower() or "required" in result.output.lower()


def _make_cert_fixtures(tmp_path: Path):
    """Generate a key + self-signed code-signing cert for CLI certificate tests."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import oid

    key_path, _ = generate_ec_keypair(tmp_path / "certkeys")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "CLI Test")])
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


class TestSignCertificate:
    def test_sign_certificate_produces_output(self, runner, tmp_path):
        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        key_path, cert_path = _make_cert_fixtures(tmp_path)
        out = tmp_path / "signed.json"

        result = runner.invoke(
            cli,
            [
                "sign",
                "certificate",
                str(card_path),
                "--private-key",
                str(key_path),
                "--signing-cert",
                str(cert_path),
                "--cert-chain",
                str(cert_path),
                "-o",
                str(out),
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "x509CertificateChain" in data["attestations"]["signatureBundle"]["verificationMaterial"]

    def test_sign_certificate_with_provenance(self, runner, tmp_path):
        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        key_path, cert_path = _make_cert_fixtures(tmp_path)
        out = tmp_path / "signed-prov.json"

        result = runner.invoke(
            cli,
            [
                "sign",
                "certificate",
                str(card_path),
                "--private-key",
                str(key_path),
                "--signing-cert",
                str(cert_path),
                "--cert-chain",
                str(cert_path),
                "-o",
                str(out),
                "--provenance",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "provenanceBundle" in data["attestations"]

    def test_sign_certificate_missing_cert_errors(self, runner, keypair, tmp_path):
        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        key_path, _ = keypair

        result = runner.invoke(
            cli,
            ["sign", "certificate", str(card_path), "--private-key", str(key_path)],
        )

        assert result.exit_code != 0


class TestVerifyCertificate:
    def test_verify_certificate_success(self, runner, tmp_path):
        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        key_path, cert_path = _make_cert_fixtures(tmp_path)
        out = tmp_path / "signed.json"

        runner.invoke(
            cli,
            [
                "sign",
                "certificate",
                str(card_path),
                "--private-key",
                str(key_path),
                "--signing-cert",
                str(cert_path),
                "--cert-chain",
                str(cert_path),
                "-o",
                str(out),
            ],
        )

        result = runner.invoke(cli, ["verify", "certificate", str(out), "--cert-chain", str(cert_path)])

        assert result.exit_code == 0, result.output
        assert "valid" in result.output.lower()

    def test_verify_certificate_with_san_uri(self, runner, tmp_path):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import oid

        card_path = tmp_path / "card.json"
        card_path.write_text(json.dumps(SAMPLE_AGENT_CARD))
        key_path, _ = generate_ec_keypair(tmp_path / "sankeys")
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "SAN Test")])
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
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier("spiffe://example.com/agent")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "san_cert.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        out = tmp_path / "signed-san.json"
        runner.invoke(
            cli,
            [
                "sign",
                "certificate",
                str(card_path),
                "--private-key",
                str(key_path),
                "--signing-cert",
                str(cert_path),
                "--cert-chain",
                str(cert_path),
                "-o",
                str(out),
            ],
        )

        result = runner.invoke(
            cli,
            [
                "verify",
                "certificate",
                str(out),
                "--cert-chain",
                str(cert_path),
                "--san-uri",
                "spiffe://example.com/agent",
            ],
        )
        assert result.exit_code == 0, result.output


class TestDefaultSubcommand:
    def test_sign_without_subcommand_defaults_to_sigstore(self, runner, card_path):
        result = runner.invoke(cli, ["sign", str(card_path), "--identity_token", "fake"])

        assert result.exit_code != 0
        assert "malformed" in result.output.lower() or "failed" in result.output.lower()

    def test_verify_without_subcommand_defaults_to_sigstore(self, runner, tmp_path):
        dummy = tmp_path / "dummy.json"
        dummy.write_text("{}")

        result = runner.invoke(
            cli,
            ["verify", str(dummy), "--identity", "x", "--identity_provider", "y"],
            obj={"verbose": False},
        )

        assert result.exit_code != 0
