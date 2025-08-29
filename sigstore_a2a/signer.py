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
from typing import Any

from a2a.types import AgentCard
from sigstore._internal.trust import ClientTrustConfig
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.oidc import IdentityToken, Issuer, detect_credential
from sigstore.sign import SigningContext

from .models.provenance import SLSAProvenance
from .models.signature import Attestations, SignedAgentCard
from .utils.crypto import canonicalize_json


class AgentCardSigner:
    """Signs A2A Agent Cards using Sigstore keyless signing."""

    def __init__(
        self,
        identity_token: str | None = None,
        trust_config: Path | None = None,
        staging: bool = False,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_ambient_credentials: bool = False,
        verbose: bool = False,
    ):
        """Initialize the Agent Card signer.

        Args:
            identity_token: Pre-obtained identity token
            staging: Use Sigstore staging environment
        """
        self.identity_token = identity_token
        self.staging = staging
        self.trust_config = trust_config
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_ambient_credentials = use_ambient_credentials
        self.verbose = verbose

    def _get_signer(self) -> SigningContext:
        """
        Retrieves or creates a Sigstore signer instance based on the configuration.

        The method prioritizes the staging environment if enabled, falls back to a
        custom trust configuration, and defaults to the production environment
        for signing operations. This ensures the correct root of trust is used.
        """

        if self.staging:
            self._signer = SigningContext.staging()
            self._issuer = Issuer.staging()
        elif self.trust_config:
            trust_config = ClientTrustConfig.from_json(self.trust_config.read_text())
            self._signer = SigningContext._from_trust_config(trust_config)
            self._issuer = Issuer(trust_config._inner.signing_config.oidc_url)
        else:
            self._signer = SigningContext.production()
            self._issuer = Issuer.production()

        return self._signer, self._issuer

    def sign_agent_card(
        self, agent_card: AgentCard | dict[str, Any] | str | Path, provenance_bundle: SLSAProvenance | None = None
    ) -> SignedAgentCard:
        """Sign an A2A Agent Card.

        Args:
            agent_card: Agent card to sign (model, dict, JSON string, or file path)
            provenance_bundle: Optional SLSA provenance bundle

        Returns:
            Signed Agent Card with verification material

        Raises:
            ValueError: If agent card is invalid
            RuntimeError: If signing fails
        """
        if isinstance(agent_card, str | Path):
            if Path(agent_card).exists():
                with open(agent_card) as f:
                    card_data = json.load(f)
            else:
                card_data = json.loads(str(agent_card))
        elif isinstance(agent_card, dict):
            card_data = agent_card
        elif isinstance(agent_card, AgentCard):
            card_data = agent_card.model_dump(by_alias=True)
        else:
            raise ValueError(f"Invalid agent card type: {type(agent_card)}")
        try:
            parsed_card = AgentCard.model_validate(card_data)
        except Exception as e:
            raise ValueError(f"Invalid agent card: {e}") from e

        canonical_data = canonicalize_json(card_data)

        # Create in-toto statement for agent card
        import hashlib

        # Calculate digest of the canonical data
        digest_hex = hashlib.sha256(canonical_data).hexdigest()
        digest_set = DigestSet(root={"sha256": digest_hex})

        # Create subject for the agent card
        subject = Subject(name=parsed_card.name, digest=digest_set)

        # Build the in-toto statement
        builder = StatementBuilder()
        builder = builder.subjects([subject])
        builder = builder.predicate_type("https://a2a.openwallet.dev/agentcard/v1")
        builder = builder.predicate(card_data)

        # Build the statement
        statement = builder.build()

        signing_context, issuer = self._get_signer()

        # 1) Explicitly supplied identity token
        # 2) Ambient credential detected in the environment
        # 3) Interactive OAuth flow
        try:
            if self.identity_token:
                if isinstance(self.identity_token, str):
                    identity = IdentityToken(self.identity_token)
                else:
                    identity = self.identity_token

            elif self.use_ambient_credentials:
                ambient_credential = detect_credential()
                identity = IdentityToken(ambient_credential)

            else:
                identity = issuer.identity_token()

            with signing_context.signer(identity, cache=True) as signer:
                bundle = signer.sign_dsse(statement)

        except Exception as e:
            raise RuntimeError(f"Failed to sign agent card: {e}") from e

        attestations = Attestations(signature_bundle=bundle.to_json(), provenance_bundle=provenance_bundle)

        signed_card = SignedAgentCard(agent_card=parsed_card, attestations=attestations)

        return signed_card

    def sign_file(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
        provenance_bundle: SLSAProvenance | None = None,
    ) -> Path:
        """Sign an Agent Card file.

        Args:
            input_path: Path to Agent Card JSON file
            output_path: Output path for signed card (default: input_path with .signed.json)
            provenance_bundle: Optional SLSA provenance bundle

        Returns:
            Path to signed Agent Card file
        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path.with_suffix(".signed.json")
        else:
            output_path = Path(output_path)

        signed_card = self.sign_agent_card(input_path, provenance_bundle)

        with open(output_path, "w") as f:
            json.dump(signed_card.model_dump(by_alias=True), f, indent=2, default=str)

        return output_path
