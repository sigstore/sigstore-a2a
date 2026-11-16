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

"""Example: sign and verify an Agent Card using an X.509 certificate.

Usage:
    # Generate a key and self-signed code-signing certificate:
    openssl ecparam -genkey -name prime256v1 -noout -out private.pem
    openssl req -x509 -new -key private.pem -out cert.pem -days 365 \
      -subj "/CN=My Agent Signer" \
      -addext "keyUsage=digitalSignature" \
      -addext "extendedKeyUsage=codeSigning"

    # Run:
    python examples/sign_verify_certificate.py private.pem cert.pem examples/agent-cards/georoute-agent.json
"""

import sys
from pathlib import Path

from sigstore_a2a.signing import SigningConfig
from sigstore_a2a.verifying import VerifyingConfig


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <private_key.pem> <cert.pem> <agent-card.json>")
        sys.exit(1)

    private_key = Path(sys.argv[1])
    cert = Path(sys.argv[2])
    agent_card = Path(sys.argv[3])
    output = agent_card.with_suffix(".signed.json")

    # Sign with certificate (cert used as both signing cert and trust chain for self-signed)
    signed = (
        SigningConfig()
        .use_certificate_signer(private_key=private_key, signing_cert=cert, cert_chain=[cert])
        .sign_card(agent_card)
    )
    print(f"Signed: {signed.agent_card.name}")

    # Write to file
    SigningConfig().use_certificate_signer(private_key=private_key, signing_cert=cert, cert_chain=[cert]).sign(
        agent_card, output
    )
    print(f"Written to: {output}")

    # Verify with certificate chain
    result = VerifyingConfig().use_certificate_verifier(cert_chain=[cert]).verify_file(output)

    if result.valid:
        print(f"Verified: {result.agent_card.name} v{result.agent_card.version}")
        if result.certificate:
            print(f"Certificate: {result.certificate.subject.rfc4514_string()}")
    else:
        print(f"Verification failed: {result.errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
