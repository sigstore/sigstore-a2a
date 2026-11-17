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

"""Shared constants and helpers for signing and verification."""

import json
from pathlib import Path
from typing import Any

from a2a.types import AgentCard
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import ParseDict
from sigstore.models import Bundle

from ..exceptions import InvalidAgentCardError, InvalidBundleError, InvalidKeyError
from ..models.signature import SignedAgentCard

# In-toto / DSSE constants
IN_TOTO_JSON_PAYLOAD_TYPE: str = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE: str = "https://in-toto.io/Statement/v1"

# Agent card predicate type
PREDICATE_TYPE: str = "https://a2a.openwallet.dev/agentcard/v1"

# Sigstore bundle media type (used by both Sigstore and traditional signing)
BUNDLE_MEDIA_TYPE: str = "application/vnd.dev.sigstore.bundle.v0.3+json"

# EC curves supported for traditional PKI signing
SUPPORTED_EC_CURVES: frozenset[str] = frozenset({"secp256r1", "secp384r1", "secp521r1"})


def pae(raw_payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAE).

    See https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md
    """
    payload_type = IN_TOTO_JSON_PAYLOAD_TYPE
    pae_str = f"DSSEv1 {len(payload_type)} {payload_type} {len(raw_payload)}"
    return b" ".join([pae_str.encode("utf-8"), raw_payload])


def ec_hash_for_key(public_key: ec.EllipticCurvePublicKey) -> hashes.HashAlgorithm:
    """Return the hash algorithm matching an EC key's curve size."""
    match public_key.curve.key_size:
        case 256:
            return hashes.SHA256()
        case 384:
            return hashes.SHA384()
        case 521:
            return hashes.SHA512()
        case _:
            raise InvalidKeyError(f"Unsupported EC key size {public_key.curve.key_size}")


def check_ec_key(public_key) -> None:
    """Validate that a key is a supported elliptic curve key."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise InvalidKeyError("Only elliptic curve keys are supported")
    if public_key.curve.name not in SUPPORTED_EC_CURVES:
        raise InvalidKeyError(f"Unsupported curve '{public_key.curve.name}'")


class VerificationResult:
    """Result of Agent Card verification (shared by all verification methods)."""

    def __init__(
        self,
        valid: bool,
        agent_card: AgentCard | None = None,
        certificate: x509.Certificate | None = None,
        identity: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        raw_card_data: dict[str, Any] | None = None,
    ):
        self.valid = valid
        self.agent_card = agent_card
        self.certificate = certificate
        self.identity = identity or {}
        self.errors = errors or []
        self.raw_card_data = raw_card_data or {}

    def __bool__(self) -> bool:
        return self.valid


def parse_signed_card(signed_card: SignedAgentCard | dict | str | Path) -> SignedAgentCard:
    """Parse input into a validated SignedAgentCard."""
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
        raise InvalidAgentCardError(f"Invalid signed card type: {type(signed_card)}")
    return SignedAgentCard.model_validate(card_data)


def get_bundle_dict(sig_bundle: Bundle | dict) -> dict:
    """Convert a signature bundle (Bundle or dict) to a plain dict."""
    if isinstance(sig_bundle, Bundle):
        return json.loads(sig_bundle.to_json())
    return sig_bundle


def extract_verified_card(payload_type: str, payload: bytes) -> tuple[AgentCard, dict]:
    """Extract the agent card from a verified DSSE payload."""
    if payload_type != IN_TOTO_JSON_PAYLOAD_TYPE:
        raise InvalidBundleError(f"Expected DSSE payload type {IN_TOTO_JSON_PAYLOAD_TYPE}, got {payload_type}")
    statement = json.loads(payload)
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise InvalidBundleError(
            f"Expected in-toto statement type {IN_TOTO_STATEMENT_TYPE}, got {statement.get('_type')}"
        )
    predicate = statement.get("predicate")
    if predicate is None or not isinstance(predicate, dict):
        raise InvalidBundleError("DSSE statement does not contain a valid predicate")
    return ParseDict(predicate, AgentCard(), ignore_unknown_fields=True), predicate
