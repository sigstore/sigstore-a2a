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

# """Import and re-export A2A Agent Card types from upstream a2a-python library."""

# try:
#     from a2a.types import (
#         AgentCapabilities,
#         AgentCard,
#         AgentInterface,
#         AgentProvider,
#         AgentSkill,
#         SecurityScheme,
#     )
# except ImportError:
#     from typing import Any

#     from pydantic import BaseModel, Field, HttpUrl

#     class AgentProvider(BaseModel):
#         """Information about the organization or entity providing the agent."""

#         organization: str = Field(..., description="Name of the organization/entity")
#         url: HttpUrl = Field(..., description="URL for the provider's website/contact")

#     class AgentExtension(BaseModel):
#         """Extension to the A2A protocol supported by the agent."""

#         uri: str = Field(..., description="The URI for the supported extension")
#         required: bool = Field(False, description="Whether the extension is required")
#         description: str | None = Field(None, description="Description of the extension")
#         params: dict[str, Any] | None = Field(None, description="Extension parameters")

#     class AgentCapabilities(BaseModel):
#         """Optional A2A protocol features supported by the agent."""

#         streaming: bool = Field(False, description="Support for SSE streaming methods")
#         push_notifications: bool = Field(
#             False, alias="pushNotifications", description="Support for push notification methods"
#         )
#         state_transition_history: bool = Field(
#             False, alias="stateTransitionHistory", description="Support for detailed task status change history"
#         )
#         extensions: list[AgentExtension] = Field(
#             default_factory=list, description="list of extensions supported by this agent"
#         )

#     class SecurityScheme(BaseModel):
#         """Security scheme for agent authentication."""

#         type: str = Field(..., description="Type of security scheme")
#         scheme: str | None = Field(None, description="HTTP authentication scheme")
#         bearer_format: str | None = Field(None, alias="bearerFormat", description="Bearer token format")
#         openid_connect_url: HttpUrl | None = Field(
#             None, alias="openIdConnectUrl", description="OpenID Connect discovery URL"
#         )

#     class AgentInterface(BaseModel):
#         """Interface definition for agent endpoints."""

#         url: HttpUrl = Field(..., description="URL for this interface")
#         transport: str = Field(..., description="Transport protocol (JSONRPC, GRPC, HTTP+JSON)")

#     class AgentSkill(BaseModel):
#         """A specific capability or area of expertise the agent can perform."""

#         id: str = Field(..., description="Unique skill identifier within this agent")
#         name: str = Field(..., description="Human-readable skill name")
#         description: str = Field(..., description="Detailed skill description")
#         tags: list[str] = Field(..., description="Keywords/categories for discoverability")
#         examples: list[str] | None = Field(None, description="Example prompts or use cases")
#         input_modes: list[str] | None = Field(
#             None, alias="inputModes", description="Accepted Media Types for this skill"
#         )
#         output_modes: list[str] | None = Field(
#             None, alias="outputModes", description="Produced Media Types for this skill"
#         )

#     class AgentCard(BaseModel):
#         """A2A Agent Card containing agent metadata and capabilities."""

#         protocol_version: str = Field(
#             ..., alias="protocolVersion", description="Version of the A2A protocol this agent supports"
#         )
#         name: str = Field(..., description="Human-readable name of the agent")
#         description: str = Field(..., description="Human-readable description")
#         url: HttpUrl = Field(..., description="Base URL for the agent's A2A service")
#         preferred_transport: str | None = Field(
#             None, alias="preferredTransport", description="Preferred transport protocol"
#         )
#         additional_interfaces: list[AgentInterface] | None = Field(
#             None, alias="additionalInterfaces", description="Additional transport interfaces"
#         )
#         provider: AgentProvider | None = Field(None, description="Information about the agent's provider")
#         icon_url: HttpUrl | None = Field(None, alias="iconUrl", description="URL to an icon for the agent")
#         version: str = Field(..., description="Agent or A2A implementation version")
#         documentation_url: HttpUrl | None = Field(
#             None, alias="documentationUrl", description="URL to human-readable documentation"
#         )
#         capabilities: AgentCapabilities = Field(..., description="Optional A2A protocol features supported")
#         security_schemes: dict[str, SecurityScheme] | None = Field(
#             None, alias="securitySchemes", description="Security scheme details for authentication"
#         )
#         security: list[dict[str, list[str]]] | None = Field(
#             None, description="Security requirements for contacting the agent"
#         )
#         default_input_modes: list[str] = Field(
#             ..., alias="defaultInputModes", description="Input Media Types accepted by the agent"
#         )
#         default_output_modes: list[str] = Field(
#             ..., alias="defaultOutputModes", description="Output Media Types produced by the agent"
#         )
#         skills: list[AgentSkill] = Field(..., description="Array of skills")
#         supports_authenticated_extended_card: bool | None = Field(
#             None,
#             alias="supportsAuthenticatedExtendedCard",
#             description="Support for retrieving detailed Agent Card via authenticated endpoint",
#         )

#         model_config = {"populate_by_name": True, "extra": "allow", "str_strip_whitespace": True}
