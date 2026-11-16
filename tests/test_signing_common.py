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

"""Tests for _signing/common.py shared helpers."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore_a2a._signing.common import (
    BUNDLE_MEDIA_TYPE,
    IN_TOTO_JSON_PAYLOAD_TYPE,
    PREDICATE_TYPE,
    VerificationResult,
    check_ec_key,
    ec_hash_for_key,
    pae,
)


class TestPAE:
    def test_pae_format(self):
        payload = b'{"test": true}'
        result = pae(payload)
        prefix = f"DSSEv1 {len(IN_TOTO_JSON_PAYLOAD_TYPE)} {IN_TOTO_JSON_PAYLOAD_TYPE} {len(payload)}"
        assert result == prefix.encode("utf-8") + b" " + payload

    def test_pae_empty_payload(self):
        result = pae(b"")
        assert b"DSSEv1" in result
        assert b" 0 " in result


class TestECHashForKey:
    def test_sha256_for_p256(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        assert isinstance(ec_hash_for_key(key), hashes.SHA256)

    def test_sha384_for_p384(self):
        key = ec.generate_private_key(ec.SECP384R1()).public_key()
        assert isinstance(ec_hash_for_key(key), hashes.SHA384)

    def test_sha512_for_p521(self):
        key = ec.generate_private_key(ec.SECP521R1()).public_key()
        assert isinstance(ec_hash_for_key(key), hashes.SHA512)


class TestCheckECKey:
    def test_supported_curves_accepted(self):
        for curve in [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]:
            key = ec.generate_private_key(curve).public_key()
            check_ec_key(key)

    def test_rsa_key_rejected(self):
        key = rsa.generate_private_key(65537, 2048).public_key()
        with pytest.raises(ValueError, match="Only elliptic curve"):
            check_ec_key(key)

    def test_unsupported_curve_rejected(self):
        key = ec.generate_private_key(ec.SECP192R1()).public_key()
        with pytest.raises(ValueError, match="Unsupported curve"):
            check_ec_key(key)


class TestVerificationResult:
    def test_bool_true_when_valid(self):
        assert VerificationResult(valid=True)

    def test_bool_false_when_invalid(self):
        assert not VerificationResult(valid=False)

    def test_defaults(self):
        r = VerificationResult(valid=False)
        assert r.errors == []
        assert r.identity == {}
        assert r.raw_card_data == {}
        assert r.agent_card is None
        assert r.certificate is None


class TestConstants:
    def test_predicate_type(self):
        assert "a2a" in PREDICATE_TYPE

    def test_bundle_media_type(self):
        assert "sigstore" in BUNDLE_MEDIA_TYPE

    def test_in_toto_payload_type(self):
        assert "in-toto" in IN_TOTO_JSON_PAYLOAD_TYPE
