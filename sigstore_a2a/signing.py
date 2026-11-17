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

"""High-level signing API for A2A Agent Cards."""

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Self

from a2a.types import AgentCard

from .models.provenance import SLSAProvenance
from .models.signature import SignedAgentCard

logger = logging.getLogger(__name__)


class SigningConfig:
    """Builder-pattern configuration for signing Agent Cards.

    Select a signing method with one of the ``use_*`` methods, then call
    :meth:`sign` or :meth:`sign_card`.  If no method is selected, Sigstore
    keyless signing is used by default.

    Example::

        from sigstore_a2a.signing import SigningConfig

        signed = (
            SigningConfig()
            .use_elliptic_key_signer(private_key=Path("key.pem"))
            .sign_card("agent-card.json")
        )
    """

    def __init__(self):
        self._signer = None

    def use_sigstore_signer(
        self,
        identity_token: str | None = None,
        staging: bool = False,
        trust_config: Path | None = None,
        instance: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_ambient_credentials: bool = False,
    ) -> Self:
        from ._signing.sign_sigstore import AgentCardSigner

        self._signer = AgentCardSigner(
            identity_token=identity_token,
            staging=staging,
            trust_config=trust_config,
            instance=instance,
            client_id=client_id,
            client_secret=client_secret,
            use_ambient_credentials=use_ambient_credentials,
        )
        logger.debug("Signing method selected: sigstore")
        return self

    def use_elliptic_key_signer(
        self,
        private_key: Path,
        password: bytes | None = None,
    ) -> Self:
        from ._signing.sign_ec_key import ECKeyAgentCardSigner

        self._signer = ECKeyAgentCardSigner(
            private_key_path=private_key,
            password=password,
        )
        logger.debug("Signing method selected: ec_key")
        return self

    def use_certificate_signer(
        self,
        private_key: Path,
        signing_cert: Path,
        cert_chain: Iterable[Path] = (),
        password: bytes | None = None,
    ) -> Self:
        from ._signing.sign_certificate import CertificateAgentCardSigner

        self._signer = CertificateAgentCardSigner(
            private_key_path=private_key,
            signing_cert_path=signing_cert,
            cert_chain_paths=cert_chain,
            password=password,
        )
        logger.debug("Signing method selected: certificate")
        return self

    def _get_signer(self):
        if self._signer is None:
            logger.debug("No signing method selected, defaulting to sigstore")
            self.use_sigstore_signer()
        return self._signer

    def sign_card(
        self,
        agent_card: AgentCard | dict[str, Any] | str | Path,
        provenance_bundle: SLSAProvenance | None = None,
    ) -> SignedAgentCard:
        """Sign an agent card and return the result in memory."""
        return self._get_signer().sign_agent_card(agent_card, provenance_bundle=provenance_bundle)

    def sign(
        self,
        agent_card: AgentCard | dict[str, Any] | str | Path,
        output_path: Path,
        provenance_bundle: SLSAProvenance | None = None,
    ) -> Path:
        """Sign an agent card and write the result to a file."""
        signed = self.sign_card(agent_card, provenance_bundle=provenance_bundle)
        logger.info("Writing signed agent card to %s", output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(signed.to_dict(), f, indent=2, default=str)
        return output_path
