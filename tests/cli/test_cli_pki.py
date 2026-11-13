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
