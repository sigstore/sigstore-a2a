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

"""Exception hierarchy for sigstore-a2a."""


class SigstoreA2AError(Exception):
    """Base exception for all sigstore-a2a errors."""


class SigningError(SigstoreA2AError):
    """Signing operation failed."""


class VerificationError(SigstoreA2AError):
    """Verification operation failed."""


class InvalidAgentCardError(SigstoreA2AError):
    """Agent card input is invalid (bad JSON, wrong type, missing fields)."""


class InvalidKeyError(SigstoreA2AError):
    """Key is unsupported (wrong type, unsupported curve)."""


class InvalidCertificateError(SigstoreA2AError):
    """Certificate is invalid (expired, not yet valid, wrong EKU, key mismatch)."""


class InvalidBundleError(SigstoreA2AError):
    """Signature bundle is malformed (wrong media type, missing chain, bad payload)."""


class ConfigurationError(SigstoreA2AError):
    """Configuration is invalid (mutually exclusive options, missing verifier)."""
