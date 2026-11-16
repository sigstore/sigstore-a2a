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

"""EC key signing for A2A Agent Cards."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
from google.protobuf.json_format import MessageToDict, ParseDict
from in_toto_attestation.v1 import statement as in_toto_statement
from sigstore_models import intoto as intoto_pb
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb

from ..models.provenance import SLSAProvenance
from ..models.signature import Attestations, SignedAgentCard
from ..utils.crypto import canonicalize_json
from .common import (
    BUNDLE_MEDIA_TYPE,
    IN_TOTO_JSON_PAYLOAD_TYPE,
    PREDICATE_TYPE,
    check_ec_key,
    ec_hash_for_key,
    pae,
)


class ECKeyAgentCardSigner:
    """Signs A2A Agent Cards using an elliptic curve private key."""

    def __init__(self, private_key_path: Path, password: bytes | None = None):
        loaded_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=password)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Only elliptic curve private keys are supported")
        self._private_key: ec.EllipticCurvePrivateKey = loaded_key
        check_ec_key(self._private_key.public_key())

    def _build_statement(self, card_data: dict, card_name: str) -> bytes:
        canonical_data = canonicalize_json(card_data)
        digest_hex = hashlib.sha256(canonical_data).hexdigest()

        subject = in_toto_statement.ResourceDescriptor(name=card_name, digest={"sha256": digest_hex}).pb

        stmt = in_toto_statement.Statement(
            subjects=[subject],
            predicate_type=PREDICATE_TYPE,
            predicate=card_data,
        )

        return json_format.MessageToJson(stmt.pb).encode("utf-8")

    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        raw_pub = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        hint = hashlib.sha256(raw_pub).digest().hex()
        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKeyIdentifier(hint=hint),
            tlog_entries=[],
        )

    def sign_agent_card(
        self,
        agent_card: AgentCard | dict[str, Any] | str | Path,
        provenance_bundle: SLSAProvenance | None = None,
    ) -> SignedAgentCard:
        if isinstance(agent_card, str | Path):
            if Path(agent_card).exists():
                with open(agent_card) as f:
                    card_data = json.load(f)
            else:
                try:
                    card_data = json.loads(str(agent_card))
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid agent card JSON: {e}") from e
        elif isinstance(agent_card, dict):
            import copy

            card_data = copy.deepcopy(agent_card)
        elif isinstance(agent_card, AgentCard):
            card_data = MessageToDict(agent_card)
        else:
            raise ValueError(f"Invalid agent card type: {type(agent_card)}")

        parsed_card = ParseDict(card_data, AgentCard(), ignore_unknown_fields=True)
        raw_payload = self._build_statement(card_data, parsed_card.name)

        public_key = self._private_key.public_key()
        signature_bytes = self._private_key.sign(
            pae(raw_payload),
            ec.ECDSA(ec_hash_for_key(public_key)),
        )

        envelope = intoto_pb.Envelope(
            payload=base64.b64encode(raw_payload),
            payload_type=IN_TOTO_JSON_PAYLOAD_TYPE,
            signatures=[intoto_pb.Signature(sig=base64.b64encode(signature_bytes), keyid="")],
        )

        bundle = bundle_pb.Bundle(
            media_type=BUNDLE_MEDIA_TYPE,
            verification_material=self._get_verification_material(),
            dsse_envelope=envelope,
        )

        attestations = Attestations(
            signature_bundle=bundle.to_dict(),
            provenance_bundle=provenance_bundle,
        )

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
