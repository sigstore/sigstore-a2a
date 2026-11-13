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

"""Sigstore keyless signing for A2A Agent Cards."""

import hashlib
import json
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from google.protobuf.json_format import MessageToDict, ParseDict
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.models import ClientTrustConfig
from sigstore.oidc import IdentityToken, Issuer, detect_credential
from sigstore.sign import SigningContext

from ..models.provenance import SLSAProvenance
from ..models.signature import Attestations, SignedAgentCard
from ..utils.crypto import canonicalize_json
from .common import PREDICATE_TYPE


class AgentCardSigner:
    """Signs A2A Agent Cards using Sigstore keyless signing."""

    def __init__(
        self,
        identity_token: str | None = None,
        trust_config: Path | None = None,
        staging: bool = False,
        instance: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_ambient_credentials: bool = False,
        verbose: bool = False,
    ):
        self.identity_token = identity_token
        self.staging = staging
        self.trust_config = trust_config
        self.instance = instance
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_ambient_credentials = use_ambient_credentials
        self.verbose = verbose

        self._signer: SigningContext | None = None
        self._issuer: Issuer | None = None

    def _get_signer(self) -> tuple[SigningContext, Issuer]:
        if self._signer is not None and self._issuer is not None:
            return self._signer, self._issuer

        trust_opts = sum(bool(x) for x in [self.staging, self.instance, self.trust_config])
        if trust_opts > 1:
            raise ValueError("Only one of --staging, --instance, or --trust_config may be specified")

        if self.trust_config:
            trust_config = ClientTrustConfig.from_json(self.trust_config.read_text())
        elif self.instance:
            trust_config = ClientTrustConfig.from_tuf(self.instance)
        elif self.staging:
            trust_config = ClientTrustConfig.staging()
        else:
            trust_config = ClientTrustConfig.production()

        self._signer = SigningContext.from_trust_config(trust_config)
        oidc_issuer = trust_config.signing_config.get_oidc_url()
        self._issuer = Issuer(oidc_issuer)

        return self._signer, self._issuer

    def sign_agent_card(
        self, agent_card: AgentCard | dict[str, Any] | str | Path, provenance_bundle: SLSAProvenance | None = None
    ) -> SignedAgentCard:
        if isinstance(agent_card, str | Path):
            if Path(agent_card).exists():
                with open(agent_card) as f:
                    card_data = json.load(f)
            else:
                card_data = json.loads(str(agent_card))
        elif isinstance(agent_card, dict):
            card_data = agent_card
        elif isinstance(agent_card, AgentCard):
            card_data = MessageToDict(agent_card)
        else:
            raise ValueError(f"Invalid agent card type: {type(agent_card)}")
        try:
            parsed_card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        except Exception as e:
            raise ValueError(f"Invalid agent card: {e}") from e

        canonical_data = canonicalize_json(card_data)
        digest_hex = hashlib.sha256(canonical_data).hexdigest()
        digest_set = DigestSet(root={"sha256": digest_hex})
        subject = Subject(name=parsed_card.name, digest=digest_set)

        builder = StatementBuilder()
        builder = builder.subjects([subject])
        builder = builder.predicate_type(PREDICATE_TYPE)
        builder = builder.predicate(card_data)
        statement = builder.build()

        signing_context, issuer = self._get_signer()

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
                identity = issuer.identity_token(
                    client_id=self.client_id or "sigstore",
                    client_secret=self.client_secret or "",
                )

            with signing_context.signer(identity, cache=True) as signer:
                bundle = signer.sign_dsse(statement)

        except Exception as e:
            raise RuntimeError(f"Failed to sign agent card: {e}") from e

        attestations = Attestations(signature_bundle=bundle.to_json(), provenance_bundle=provenance_bundle)
        signed_card = SignedAgentCard(agent_card=parsed_card, attestations=attestations)
        signed_card._raw_card_data = card_data
        return signed_card

    def sign_file(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
        provenance_bundle: SLSAProvenance | None = None,
    ) -> Path:
        input_path = Path(input_path)
        if output_path is None:
            output_path = input_path.with_suffix(".signed.json")
        else:
            output_path = Path(output_path)

        signed_card = self.sign_agent_card(input_path, provenance_bundle)
        with open(output_path, "w") as f:
            json.dump(signed_card.to_dict(), f, indent=2, default=str)
        return output_path
