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
from typing import Any

from a2a.types import AgentCard
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator
from sigstore.models import Bundle

from .provenance import SLSAProvenance


class Attestations(BaseModel):
    """Verification material for Agent Card signatures."""

    signature_bundle: Bundle = Field(..., alias="signatureBundle", description="Sigstore signature bundle")
    provenance_bundle: SLSAProvenance | None = Field(
        None, alias="provenanceBundle", description="SLSA provenance attestation"
    )

    model_config = ConfigDict(
        arbitrary_types_allowed=True,  # allow non-Pydantic Bundle objects
        populate_by_name=True,
        extra="ignore",
    )

    @field_validator("signature_bundle", mode="before")
    @classmethod
    def _bundle_in(cls, v):
        if v is None or isinstance(v, Bundle):
            return v
        if isinstance(v, dict):
            return Bundle.from_json(json.dumps(v))
        if isinstance(v, str):
            return Bundle.from_json(v)
        raise TypeError("Expected sigstore.models.Bundle, dict, or JSON string")

    @field_serializer("signature_bundle")
    def _bundle_out(self, v: Bundle, _info):
        if v is None:
            return None
        return json.loads(v.to_json())


class SignedAgentCard(BaseModel):
    """Agent Card with cryptographic signature and provenance."""

    agent_card: AgentCard = Field(..., alias="agentCard", description="The A2A Agent Card")
    attestations: Attestations = Field(..., description="Cryptographic attestation of the Agent Card")

    model_config = {"populate_by_name": True}

    @property
    def name(self) -> str:
        """Get the agent name."""
        return self.agent_card.name

    @property
    def version(self) -> str:
        """Get the agent version."""
        return self.agent_card.version

    @property
    def url(self) -> str:
        """Get the agent URL."""
        return str(self.agent_card.url)


def _to_jsonable(v: Any) -> Any:
    if v is None:
        return None
    # BetterProto / dataclass style:
    if hasattr(v, "to_json") and callable(v.to_json):
        return json.loads(v.to_json())
    if hasattr(v, "to_dict") and callable(v.to_dict):
        return v.to_dict()
    # Fallback: already a dict or Pydantic model
    return v
