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

"""Certificate-based signing for A2A Agent Cards."""

import base64
import datetime
import logging
from collections.abc import Iterable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb

from ..exceptions import InvalidCertificateError
from .sign_ec_key import ECKeyAgentCardSigner

logger = logging.getLogger(__name__)


class CertificateAgentCardSigner(ECKeyAgentCardSigner):
    """Signs A2A Agent Cards using an EC private key with an X.509 certificate chain."""

    def __init__(
        self,
        private_key_path: Path,
        signing_cert_path: Path,
        cert_chain_paths: Iterable[Path] = (),
        password: bytes | None = None,
    ):
        super().__init__(private_key_path, password=password)

        self._signing_cert = x509.load_pem_x509_certificate(signing_cert_path.read_bytes())

        now = datetime.datetime.now(datetime.UTC)
        if now > self._signing_cert.not_valid_after_utc:
            raise InvalidCertificateError(f"Signing certificate expired ({self._signing_cert.not_valid_after_utc})")
        if now < self._signing_cert.not_valid_before_utc:
            raise InvalidCertificateError(
                f"Signing certificate not yet valid ({self._signing_cert.not_valid_before_utc})"
            )

        if self._private_key.public_key() != self._signing_cert.public_key():
            raise InvalidCertificateError("Certificate public key does not match private key")

        chain_bytes = b"".join(p.read_bytes() for p in cert_chain_paths)
        self._trust_chain = x509.load_pem_x509_certificates(chain_bytes) if chain_bytes else []
        logger.debug(
            "Certificate signer initialized, subject=%s, chain_length=%d",
            self._signing_cert.subject.rfc4514_string(),
            len(self._trust_chain) + 1,
        )

    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        def _to_pb_cert(cert: x509.Certificate) -> common_pb.X509Certificate:
            return common_pb.X509Certificate(
                raw_bytes=base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER))
            )

        chain = [_to_pb_cert(self._signing_cert)]
        chain.extend(_to_pb_cert(c) for c in self._trust_chain)
        return bundle_pb.VerificationMaterial(
            x509_certificate_chain=common_pb.X509CertificateChain(certificates=chain),
            tlog_entries=[],
        )
