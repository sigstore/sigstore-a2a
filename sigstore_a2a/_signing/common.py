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

from typing import Any

from a2a.types import AgentCard
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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
            raise ValueError(f"Unsupported EC key size {public_key.curve.key_size}")


def check_ec_key(public_key) -> None:
    """Validate that a key is a supported elliptic curve key."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Only elliptic curve keys are supported")
    if public_key.curve.name not in SUPPORTED_EC_CURVES:
        raise ValueError(f"Unsupported curve '{public_key.curve.name}'")


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
