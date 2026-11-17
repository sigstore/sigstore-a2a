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

"""High-level verification API for A2A Agent Cards."""

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Self

from ._signing.common import VerificationResult
from .exceptions import ConfigurationError
from .models.signature import SignedAgentCard


class VerifyingConfig:
    """Builder-pattern configuration for verifying signed Agent Cards.

    Select a verification method with one of the ``use_*`` methods, then
    call :meth:`verify` or :meth:`verify_file`.  A method must be selected
    explicitly; there is no default.

    Example::

        from sigstore_a2a.verifying import VerifyingConfig

        result = (
            VerifyingConfig()
            .use_elliptic_key_verifier(public_key=Path("pub.pem"))
            .verify("signed-card.json")
        )
    """

    def __init__(self):
        self._verifier = None

    def use_sigstore_verifier(
        self,
        identity: str | None = None,
        oidc_issuer: str | None = None,
        staging: bool = False,
        trust_config: Path | None = None,
        instance: str | None = None,
    ) -> Self:
        from ._signing.verify_sigstore import AgentCardVerifier

        self._verifier = AgentCardVerifier(
            identity=identity,
            oidc_issuer=oidc_issuer,
            staging=staging,
            trust_config=trust_config,
            instance=instance,
        )
        return self

    def use_elliptic_key_verifier(
        self,
        public_key: Path,
    ) -> Self:
        from ._signing.verify_ec_key import ECKeyAgentCardVerifier

        self._verifier = ECKeyAgentCardVerifier(public_key_path=public_key)
        return self

    def use_certificate_verifier(
        self,
        cert_chain: Iterable[Path] = (),
        expected_san_uris: Iterable[str] = (),
    ) -> Self:
        from ._signing.verify_certificate import CertificateAgentCardVerifier

        self._verifier = CertificateAgentCardVerifier(
            cert_chain_paths=cert_chain,
            expected_san_uris=expected_san_uris,
        )
        return self

    def _get_verifier(self):
        if self._verifier is None:
            raise ConfigurationError(
                "No verification method selected. "
                "Call use_sigstore_verifier(), use_elliptic_key_verifier(), "
                "or use_certificate_verifier() first."
            )
        return self._verifier

    def verify(
        self,
        signed_card: SignedAgentCard | dict[str, Any] | str | Path,
    ) -> VerificationResult:
        """Verify a signed agent card."""
        return self._get_verifier().verify_signed_card(signed_card)

    def verify_file(self, file_path: str | Path) -> VerificationResult:
        """Verify a signed agent card from a file path."""
        return self._get_verifier().verify_signed_card(file_path)
