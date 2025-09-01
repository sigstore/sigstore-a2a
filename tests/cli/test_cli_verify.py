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

from sigstore_a2a.cli.verify import verify_cmd


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sample_signed_path(tmp_path: Path) -> Path:
    """
    We only need an existing file; the verifier is stubbed and
    doesn't read contents in these tests.
    """
    p = tmp_path / "signed-card.json"
    p.write_text(json.dumps({"dummy": True}), encoding="utf-8")
    return p


class _VR:
    """Simple stand-in for VerificationResult."""

    def __init__(self, valid=True, errors=None, agent_card=None, identity=None, certificate=None):
        self.valid = valid
        self.errors = errors or []
        self.agent_card = agent_card
        self.identity = identity
        self.certificate = certificate


class _RecordingVerifier:
    """
    Records init kwargs and the last verification call.
    Defaults to a successful verification.
    """

    last_init_kwargs = None
    last_call = None
    return_result = _VR(valid=True)

    def __init__(self, **kwargs):
        type(self).last_init_kwargs = dict(kwargs)

    def verify_signed_card(self, signed_card, constraints):
        type(self).last_call = {"signed_card": signed_card, "constraints": constraints}
        return type(self).return_result


def _patch_verifier(monkeypatch, impl=_RecordingVerifier):
    monkeypatch.setattr("sigstore_a2a.cli.verify.AgentCardVerifier", impl, raising=True)


def test_verify_success_minimal(runner: CliRunner, sample_signed_path: Path, monkeypatch):
    _patch_verifier(monkeypatch)

    result = runner.invoke(
        verify_cmd,
        [
            str(sample_signed_path),
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
        ],
        obj={"verbose": False},
    )

    assert result.exit_code == 0, result.output
    assert "Agent Card signature is valid" in result.output


def test_verify_failure_shows_errors(runner: CliRunner, sample_signed_path: Path, monkeypatch):
    class _FailingVerifier(_RecordingVerifier):
        return_result = _VR(valid=False, errors=["Identity mismatch", "Repo constraint failed"])

    _patch_verifier(monkeypatch, _FailingVerifier)

    result = runner.invoke(
        verify_cmd,
        [
            str(sample_signed_path),
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
        ],
        obj={"verbose": False},
    )

    assert result.exit_code != 0
    assert "Agent Card signature verification failed" in result.output
    assert "Identity mismatch" in result.output
    assert "Repo constraint failed" in result.output


def test_verify_passes_staging_flag(runner: CliRunner, sample_signed_path: Path, monkeypatch):
    _patch_verifier(monkeypatch)

    result = runner.invoke(
        verify_cmd,
        [
            str(sample_signed_path),
            "--staging",
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
        ],
        obj={"verbose": False},
    )

    assert result.exit_code == 0, result.output
    init = _RecordingVerifier.last_init_kwargs
    assert init is not None
    assert init.get("staging") is True
    assert init.get("trust_config") is None


def test_verify_passes_trust_config(runner: CliRunner, sample_signed_path: Path, tmp_path: Path, monkeypatch):
    _patch_verifier(monkeypatch)

    trust_cfg = tmp_path / "client-trust.json"
    trust_cfg.write_text("{}", encoding="utf-8")

    result = runner.invoke(
        verify_cmd,
        [
            str(sample_signed_path),
            "--trust_config",
            str(trust_cfg),
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
        ],
        obj={"verbose": False},
    )

    assert result.exit_code == 0, result.output
    init = _RecordingVerifier.last_init_kwargs
    assert init is not None
    assert init.get("staging") is False
    assert Path(init.get("trust_config")) == trust_cfg


def test_verify_constraints_are_forwarded(runner: CliRunner, sample_signed_path: Path, monkeypatch):
    _patch_verifier(monkeypatch)

    result = runner.invoke(
        verify_cmd,
        [
            str(sample_signed_path),
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
            "--repository",
            "owner/repo",
            "--workflow",
            "ci",
        ],
        obj={"verbose": True},
    )

    assert result.exit_code == 0, result.output

    call = _RecordingVerifier.last_call
    assert call is not None
    constraints = call["constraints"]
    assert getattr(constraints, "repository", None) == "owner/repo"
    assert getattr(constraints, "workflow", None) == "ci"
    assert getattr(constraints, "identity", None) == "dev@example.com"
    assert getattr(constraints, "identity_provider", None) == "https://accounts.google.com"


def test_verify_requires_existing_file(runner: CliRunner, monkeypatch, tmp_path: Path):
    _patch_verifier(monkeypatch)
    missing = tmp_path / "nope.json"

    result = runner.invoke(
        verify_cmd,
        [
            str(missing),
            "--identity",
            "dev@example.com",
            "--identity_provider",
            "https://accounts.google.com",
        ],
        obj={"verbose": False},
    )

    assert result.exit_code != 0
    assert "Invalid value for 'SIGNED_CARD'" in result.output or "does not exist" in result.output
