#!/usr/bin/env python
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

"""Example: sign and verify an Agent Card using an EC private key.

Usage:
    # Generate a key pair first:
    openssl ecparam -genkey -name prime256v1 -noout -out private.pem
    openssl ec -in private.pem -pubout -out public.pem

    # Run:
    python examples/sign_verify_ec_key.py private.pem public.pem examples/agent-cards/georoute-agent.json
"""

import sys
from pathlib import Path

from sigstore_a2a.signing import SigningConfig
from sigstore_a2a.verifying import VerifyingConfig


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <private_key.pem> <public_key.pem> <agent-card.json>")
        sys.exit(1)

    private_key = Path(sys.argv[1])
    public_key = Path(sys.argv[2])
    agent_card = Path(sys.argv[3])
    output = agent_card.with_suffix(".signed.json")

    # Sign
    signed = SigningConfig().use_elliptic_key_signer(private_key=private_key).sign_card(agent_card)
    print(f"Signed: {signed.agent_card.name}")

    # Write to file
    SigningConfig().use_elliptic_key_signer(private_key=private_key).sign(agent_card, output)
    print(f"Written to: {output}")

    # Verify
    result = VerifyingConfig().use_elliptic_key_verifier(public_key=public_key).verify_file(output)

    if result.valid:
        print(f"Verified: {result.agent_card.name} v{result.agent_card.version}")
    else:
        print(f"Verification failed: {result.errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
