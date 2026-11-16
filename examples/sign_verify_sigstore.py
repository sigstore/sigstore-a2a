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

"""Example: sign and verify an Agent Card using Sigstore keyless signing.

Requires OIDC credentials (CI/CD ambient credentials or interactive OAuth).

Usage:
    # In CI/CD with ambient credentials:
    python examples/sign_verify_sigstore.py examples/agent-cards/georoute-agent.json

    # With an explicit identity token:
    export SIGSTORE_ID_TOKEN=$(curl -sS https://...)
    python examples/sign_verify_sigstore.py examples/agent-cards/georoute-agent.json "$SIGSTORE_ID_TOKEN"
"""

import sys
from pathlib import Path

from sigstore_a2a.signing import SigningConfig
from sigstore_a2a.verifying import VerifyingConfig


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <agent-card.json> [identity_token]")
        sys.exit(1)

    agent_card = Path(sys.argv[1])
    identity_token = sys.argv[2] if len(sys.argv) > 2 else None
    output = agent_card.with_suffix(".signed.json")

    # Sign (defaults to Sigstore if no use_* called, or explicit)
    signer = SigningConfig()
    if identity_token:
        signer.use_sigstore_signer(identity_token=identity_token)
    else:
        signer.use_sigstore_signer(use_ambient_credentials=True)

    signer.sign(agent_card, output)
    print(f"Signed: {output}")

    # Verify (requires identity and issuer)
    result = (
        VerifyingConfig()
        .use_sigstore_verifier(
            identity="untrusted-sa@sigstore-conformance.iam.gserviceaccount.com",
            oidc_issuer="https://accounts.google.com",
        )
        .verify_file(output)
    )

    if result.valid:
        print(f"Verified: {result.agent_card.name} v{result.agent_card.version}")
        if result.identity:
            print(f"Signer: {result.identity.get('subject')}")
    else:
        print(f"Verification failed: {result.errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
