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

"""
sigstore-a2a: Keyless signing library for A2A Agent Cards.

This library provides tools for signing and verifying A2A Agent Cards using
Sigstore's keyless signing infrastructure with SLSA provenance attestations.
"""

__version__ = "0.4.0"


def __getattr__(name: str):
    """Lazy imports to avoid dependency issues."""
    if name == "AgentCardSigner":
        from .signer import AgentCardSigner

        return AgentCardSigner
    elif name == "AgentCardVerifier":
        from .verifier import AgentCardVerifier

        return AgentCardVerifier
    elif name == "ProvenanceBuilder":
        from .provenance import ProvenanceBuilder

        return ProvenanceBuilder
    else:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
