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

"""EC key verification for A2A Agent Cards."""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import ParseDict
from sigstore.models import Bundle
from sigstore_models.bundle import v1 as bundle_pb

from ..models.signature import SignedAgentCard
from .common import (
    BUNDLE_MEDIA_TYPE,
    IN_TOTO_JSON_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    VerificationResult,
    check_ec_key,
    ec_hash_for_key,
    pae,
)

logger = logging.getLogger(__name__)


class ECKeyAgentCardVerifier:
    """Verifies signed A2A Agent Cards using an elliptic curve public key."""

    def __init__(self, public_key_path: Path):
        loaded = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(loaded, ec.EllipticCurvePublicKey):
            raise ValueError("Only elliptic curve public keys are supported")
        self._public_key: ec.EllipticCurvePublicKey = loaded
        check_ec_key(self._public_key)

    def _parse_signed_card(self, signed_card: SignedAgentCard | dict | str | Path) -> SignedAgentCard:
        if isinstance(signed_card, SignedAgentCard):
            return signed_card
        if isinstance(signed_card, Path):
            card_data = json.loads(signed_card.read_text())
        elif isinstance(signed_card, str):
            path = Path(signed_card)
            try:
                is_file = path.exists()
            except OSError:
                is_file = False
            card_data = json.loads(path.read_text()) if is_file else json.loads(signed_card)
        elif isinstance(signed_card, dict):
            card_data = signed_card
        else:
            raise TypeError(f"Invalid signed card type: {type(signed_card)}")
        return SignedAgentCard.model_validate(card_data)

    def _get_bundle_dict(self, sig_bundle: Bundle | dict) -> dict:
        if isinstance(sig_bundle, Bundle):
            return json.loads(sig_bundle.to_json())
        return sig_bundle

    def _verify_signature(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        raw_pub = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_hint = hashlib.sha256(raw_pub).digest().hex()

        vm = bundle.verification_material
        if vm is None or not hasattr(vm, "public_key") or vm.public_key is None:
            raise ValueError(
                "Bundle does not contain a public key identifier — this may be a certificate-signed bundle"
            )

        hint = vm.public_key.hint
        if hint and hint != expected_hint:
            raise ValueError("Public key hash mismatch: bundle was signed with a different key")
        if not hint:
            logger.warning("Bundle has no public key hint — key binding not enforced")

        envelope = bundle.dsse_envelope
        self._public_key.verify(
            envelope.signatures[0].sig,
            pae(envelope.payload),
            ec.ECDSA(ec_hash_for_key(self._public_key)),
        )
        return envelope.payload_type, envelope.payload

    def _extract_verified_card(self, payload_type: str, payload: bytes) -> tuple[AgentCard, dict]:
        if payload_type != IN_TOTO_JSON_PAYLOAD_TYPE:
            raise ValueError(f"Expected DSSE payload type {IN_TOTO_JSON_PAYLOAD_TYPE}, got {payload_type}")
        statement = json.loads(payload)
        if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
            raise ValueError(f"Expected in-toto statement type {IN_TOTO_STATEMENT_TYPE}, got {statement.get('_type')}")
        predicate = statement.get("predicate")
        if predicate is None or not isinstance(predicate, dict):
            raise ValueError("DSSE statement does not contain a valid predicate")
        return ParseDict(predicate, AgentCard(), ignore_unknown_fields=True), predicate

    def verify_signed_card(
        self,
        signed_card: SignedAgentCard | dict[str, Any] | str | Path,
    ) -> VerificationResult:
        try:
            parsed = self._parse_signed_card(signed_card)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Invalid signed card: {e}"])

        bundle_dict = self._get_bundle_dict(parsed.attestations.signature_bundle)

        try:
            bundle = bundle_pb.Bundle.from_dict(bundle_dict)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Invalid bundle: {e}"])

        if bundle.media_type != BUNDLE_MEDIA_TYPE:
            return VerificationResult(
                valid=False,
                errors=[f"Unexpected bundle media type: {bundle.media_type}"],
            )

        try:
            payload_type, payload = self._verify_signature(bundle)
        except (crypto_exceptions.InvalidSignature, ValueError, AttributeError) as e:
            return VerificationResult(valid=False, errors=[f"Signature verification failed: {e}"])

        try:
            verified_card, raw_card_data = self._extract_verified_card(payload_type, payload)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Failed to parse agent card from DSSE payload: {e}"])

        return VerificationResult(
            valid=True,
            agent_card=verified_card,
            raw_card_data=raw_card_data,
        )

    def verify_file(self, file_path: str | Path) -> VerificationResult:
        return self.verify_signed_card(file_path)
