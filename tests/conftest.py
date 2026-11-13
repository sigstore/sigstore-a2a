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

"""Shared test fixtures."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_ec_keypair(directory: Path, curve=None) -> tuple[Path, Path]:
    """Generate an EC key pair and write PEM files to *directory*."""
    directory.mkdir(parents=True, exist_ok=True)
    curve = curve or ec.SECP256R1()
    private_key = ec.generate_private_key(curve)

    key_path = directory / "private.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    pub_path = directory / "public.pem"
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key_path, pub_path


@pytest.fixture
def ec_keypair(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a fresh secp256r1 key pair in tmp_path."""
    return generate_ec_keypair(tmp_path)
