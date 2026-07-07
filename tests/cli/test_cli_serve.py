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
from fastapi.testclient import TestClient
from google.protobuf.json_format import ParseDict

from sigstore_a2a.cli.serve import create_app

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
