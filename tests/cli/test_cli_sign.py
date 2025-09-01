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

import pytest
from click.testing import CliRunner

from sigstore_a2a.cli.sign import sign_cmd


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sample_card_path() -> Path:
    return Path(__file__).parents[1] / "assets" / "example_agentcard.json"


class _DummySigned:
    def __init__(self, card: dict):
        self._card = card

    def model_dump(self, by_alias: bool = True, exclude_none: bool = True) -> dict:
        # Minimal structure your CLI writes back out
        return {
            "agentCard": self._card,
            "attestations": {
                "signatureBundle": {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {},
                    "dsseEnvelope": {},
                }
            },
        }


class _RecordingSigner:
    """
    Stub for AgentCardSigner that records init kwargs and returns a minimal 'signed' object.
    """

    last_init_kwargs: dict | None = None
    last_sign_kwargs: dict | None = None

    def __init__(self, **kwargs):
        type(self).last_init_kwargs = dict(kwargs)

    def sign_agent_card(self, agent_card: Path, provenance_bundle=None):
        type(self).last_sign_kwargs = {"agent_card": Path(agent_card), "provenance_bundle": provenance_bundle}
        card = json.loads(Path(agent_card).read_text(encoding="utf-8"))
        return _DummySigned(card)


class _RecordingProvenanceBuilder:
    """
    Stub for ProvenanceBuilder that records args and returns a simple dict.
    """

    last_build_kwargs: dict | None = None

    def build_provenance(self, **kwargs):
        type(self).last_build_kwargs = dict(kwargs)
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"buildType": "dummy", "builder": {"id": "test"}},
        }


def _patch_cmd_module(monkeypatch):
    monkeypatch.setattr("sigstore_a2a.cli.sign.AgentCardSigner", _RecordingSigner, raising=True)
    monkeypatch.setattr("sigstore_a2a.cli.sign.ProvenanceBuilder", _RecordingProvenanceBuilder, raising=True)


def test_sign_default_output_path(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    # Run without --output, should write <input>.signed.json
    result = runner.invoke(
        sign_cmd,
        [str(sample_card_path)],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code == 0, result.output

    expected_out = sample_card_path.with_suffix(".signed.json")
    assert expected_out.exists(), "Default <input>.signed.json was not created"

    data = json.loads(expected_out.read_text(encoding="utf-8"))
    assert "agentCard" in data and "attestations" in data


def test_sign_explicit_output_path(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    out_path = tmp_path / "signed-explicit.json"
    result = runner.invoke(
        sign_cmd,
        [str(sample_card_path), "--output", str(out_path)],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "agentCard" in data and "attestations" in data


def test_sign_forwards_flags_to_signer(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    out_path = tmp_path / "flags.json"
    result = runner.invoke(
        sign_cmd,
        [
            str(sample_card_path),
            "--output",
            str(out_path),
            "--staging",
            "--use_ambient_credentials",
            "--identity_token",
            "ABC123",
            "--client_id",
            "cid",
            "--client_secret",
            "csecret",
        ],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code == 0, result.output
    init = _RecordingSigner.last_init_kwargs or {}

    assert init.get("staging") is True
    assert init.get("use_ambient_credentials") is True
    assert init.get("identity_token") == "ABC123"
    assert init.get("client_id") == "cid"
    assert init.get("client_secret") == "csecret"


def test_sign_with_provenance_calls_builder(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    out_path = tmp_path / "with-prov.json"
    result = runner.invoke(
        sign_cmd,
        [
            str(sample_card_path),
            "--output",
            str(out_path),
            "--provenance",
            "--repository",
            "owner/repo",
            "--commit_sha",
            "deadbeef",
            "--workflow_ref",
            ".github/workflows/ci.yml@refs/heads/main",
        ],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code == 0, result.output
    prov_kwargs = _RecordingProvenanceBuilder.last_build_kwargs or {}
    assert prov_kwargs.get("source_repo") == "owner/repo"
    assert prov_kwargs.get("commit_sha") == "deadbeef"
    assert prov_kwargs.get("workflow_ref") == ".github/workflows/ci.yml@refs/heads/main"

    # The signer should have been called with a provenance bundle
    called = _RecordingSigner.last_sign_kwargs or {}
    assert called.get("provenance_bundle") is not None


def test_sign_missing_trust_config_errors(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    missing = tmp_path / "nope.json"  # does not exist
    result = runner.invoke(
        sign_cmd,
        [str(sample_card_path), "--trust_config", str(missing)],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code != 0
    assert "Trust config not found" in result.output


def test_sign_existing_trust_config_ok(runner: CliRunner, sample_card_path: Path, monkeypatch, tmp_path: Path):
    _patch_cmd_module(monkeypatch)

    trust = tmp_path / "trust.json"
    trust.write_text("{}", encoding="utf-8")
    out_path = tmp_path / "signed-with-trust.json"

    result = runner.invoke(
        sign_cmd,
        [str(sample_card_path), "--trust_config", str(trust), "--output", str(out_path)],
        env={"SIGSTORE_NO_BROWSER": "1"},
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()
