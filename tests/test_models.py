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

import pytest
from a2a.types import AgentCard
from google.protobuf.json_format import ParseDict, ParseError

from sigstore_a2a.models.provenance import DigestSet, ProvenanceSubject


class TestAgentCard:
    """Test Agent Card protobuf parsing."""

    def test_agent_card_parsing(self):
        """Verify core identity fields survive ParseDict with ignore_unknown_fields."""
        card_data = {
            "name": "Test Agent",
            "description": "A test agent",
            "version": "1.0.0",
            "skills": [{"id": "test-skill", "name": "Test Skill", "description": "A test skill", "tags": ["test"]}],
        }

        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        assert card.name == "Test Agent"
        assert card.version == "1.0.0"
        assert len(card.skills) == 1

    def test_agent_card_with_provider(self):
        """Verify provider nested message is parsed correctly."""
        card_data = {
            "name": "Test Agent",
            "description": "A test agent",
            "version": "1.0.0",
            "provider": {"organization": "Test Org", "url": "https://example.com"},
            "skills": [],
        }

        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        assert card.HasField("provider")
        assert card.provider.organization == "Test Org"

    def test_old_format_card_parsed_with_ignore_unknown_fields(self):
        """Verify v0.2.x card data is parsed gracefully with unknown fields dropped."""
        card_data = {
            "protocolVersion": "0.2.9",
            "name": "Legacy Agent",
            "description": "An old-format agent",
            "url": "https://example.com/agent",
            "version": "1.0.0",
            "capabilities": {"streaming": True, "pushNotifications": False},
            "defaultInputModes": ["application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [],
        }

        card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        assert card.name == "Legacy Agent"
        assert card.version == "1.0.0"

    def test_unknown_fields_without_ignore_raises(self):
        """Verify ParseDict without ignore_unknown_fields raises on unknown fields."""
        card_data = {
            "name": "Test Agent",
            "unknownField": "should fail",
        }

        with pytest.raises(ParseError):
            ParseDict(card_data, AgentCard(), ignore_unknown_fields=False)


class TestProvenance:
    """Test SLSA provenance models."""

    def test_provenance_subject(self):
        """Test provenance subject creation."""
        subject = ProvenanceSubject(name="test-agent", digest=DigestSet(sha256="abc123", sha512="def456"))

        assert subject.name == "test-agent"
        assert subject.digest.sha256 == "abc123"

    def test_digest_set(self):
        """Test digest set validation."""
        digest = DigestSet(sha256="test-hash")
        assert digest.sha256 == "test-hash"
