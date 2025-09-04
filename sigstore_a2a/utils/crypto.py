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

import hashlib
import json
from typing import Any


def compute_digest(data: bytes, algorithm: str = "sha256") -> str:
    """Compute cryptographic digest of data.

    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha1, sha512)

    Returns:
        Hex-encoded digest

    Raises:
        ValueError: If algorithm is not supported
    """
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def verify_digest(data: bytes, expected_digest: str, algorithm: str = "sha256") -> bool:
    """Verify data matches expected digest.

    Args:
        data: Data to verify
        expected_digest: Expected hex-encoded digest
        algorithm: Hash algorithm used

    Returns:
        True if digest matches, False otherwise
    """
    try:
        actual_digest = compute_digest(data, algorithm)
        return actual_digest.lower() == expected_digest.lower()
    except ValueError:
        return False


def canonicalize_json(obj: dict[str, Any]) -> bytes:
    """Canonicalize JSON for consistent signing.

    Args:
        obj: JSON object to canonicalize

    Returns:
        Canonical JSON bytes
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,  # Convert non-serializable objects to strings
    ).encode("utf-8")
