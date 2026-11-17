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

"""Certificate-based verification for A2A Agent Cards."""

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import certifi
from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
from OpenSSL import crypto
from sigstore_models.bundle import v1 as bundle_pb

from ..exceptions import InvalidBundleError, InvalidCertificateError, SigstoreA2AError
from ..models.signature import SignedAgentCard
from .common import (
    BUNDLE_MEDIA_TYPE,
    VerificationResult,
    check_ec_key,
    ec_hash_for_key,
    extract_verified_card,
    get_bundle_dict,
    pae,
    parse_signed_card,
)

logger = logging.getLogger(__name__)


class CertificateAgentCardVerifier:
    """Verifies signed A2A Agent Cards using X.509 certificate chain validation."""

    def __init__(
        self,
        cert_chain_paths: Iterable[Path] = (),
        expected_san_uris: Iterable[str] = (),
    ):
        cert_paths = list(cert_chain_paths) or [Path(certifi.where())]
        cert_bytes = b"".join(p.read_bytes() for p in cert_paths)
        self._trusted_certificates = x509.load_pem_x509_certificates(cert_bytes)
        self._expected_san_uris = frozenset(expected_san_uris)
        logger.debug("Certificate verifier initialized, trusted_certs=%d", len(self._trusted_certificates))

    def _verify_certificate_chain(self, bundle: bundle_pb.Bundle) -> ec.EllipticCurvePublicKey:
        """Validate the certificate chain and return the leaf cert's public key."""
        signing_chain = bundle.verification_material.x509_certificate_chain
        if not signing_chain or not signing_chain.certificates:
            raise InvalidBundleError("Bundle has no certificate chain")

        signing_cert = x509.load_der_x509_certificate(signing_chain.certificates[0].raw_bytes)

        store = crypto.X509Store()
        for cert in self._trusted_certificates:
            store.add_cert(crypto.X509.from_cryptography(cert))

        chain_ssl = [
            crypto.X509.from_cryptography(x509.load_der_x509_certificate(c.raw_bytes))
            for c in signing_chain.certificates[1:]
        ]
        signing_cert_ssl = crypto.X509.from_cryptography(signing_cert)

        store_ctx = crypto.X509StoreContext(store, signing_cert_ssl, chain_ssl)
        store_ctx.verify_certificate()
        logger.debug("Certificate chain validated, subject=%s", signing_cert.subject.rfc4514_string())

        self._check_key_usage(signing_cert)
        self._verify_san_identity(signing_cert)

        public_key = signing_cert.public_key()
        check_ec_key(public_key)
        return public_key

    def _check_key_usage(self, cert: x509.Certificate) -> None:
        extensions = cert.extensions
        can_sign = False

        try:
            usage = extensions.get_extension_for_class(x509.KeyUsage)
            if usage.value.digital_signature:
                can_sign = True
        except x509.ExtensionNotFound:
            logger.warning("Certificate does not specify KeyUsage")

        try:
            eku = extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if (
                oid.ExtendedKeyUsageOID.CODE_SIGNING not in eku
                and oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku
            ):
                can_sign = False
        except x509.ExtensionNotFound:
            pass

        if not can_sign:
            raise InvalidCertificateError("Signing certificate cannot be used for signing")

    def _verify_san_identity(self, cert: x509.Certificate) -> None:
        if not self._expected_san_uris:
            return
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound as err:
            raise InvalidCertificateError("Signing certificate has no SubjectAlternativeName") from err

        actual_uris = frozenset(san.get_values_for_type(x509.UniformResourceIdentifier))
        missing = self._expected_san_uris - actual_uris
        if missing:
            raise InvalidCertificateError(f"Certificate missing expected SAN URI(s): {sorted(missing)}")

    def _verify_signature(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        public_key = self._verify_certificate_chain(bundle)

        envelope = bundle.dsse_envelope
        public_key.verify(
            envelope.signatures[0].sig,
            pae(envelope.payload),
            ec.ECDSA(ec_hash_for_key(public_key)),
        )
        return envelope.payload_type, envelope.payload

    def verify_signed_card(
        self,
        signed_card: SignedAgentCard | dict[str, Any] | str | Path,
    ) -> VerificationResult:
        logger.info("Verifying agent card with certificate chain")
        try:
            parsed = parse_signed_card(signed_card)
        except Exception as e:
            logger.error("Invalid signed card: %s", e)
            return VerificationResult(valid=False, errors=[f"Invalid signed card: {e}"])

        bundle_dict = get_bundle_dict(parsed.attestations.signature_bundle)

        try:
            bundle = bundle_pb.Bundle.from_dict(bundle_dict)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Invalid bundle: {e}"])

        if bundle.media_type != BUNDLE_MEDIA_TYPE:
            return VerificationResult(valid=False, errors=[f"Unexpected bundle media type: {bundle.media_type}"])

        try:
            payload_type, payload = self._verify_signature(bundle)
        except (
            crypto_exceptions.InvalidSignature,
            crypto.Error,
            crypto.X509StoreContextError,
            SigstoreA2AError,
            ValueError,
        ) as e:
            logger.error("Certificate verification failed: %s", e)
            return VerificationResult(valid=False, errors=[f"Signature verification failed: {e}"])

        try:
            verified_card, raw_card_data = extract_verified_card(payload_type, payload)
        except Exception as e:
            return VerificationResult(valid=False, errors=[f"Failed to parse agent card from DSSE payload: {e}"])

        signing_chain = bundle.verification_material.x509_certificate_chain
        cert = x509.load_der_x509_certificate(signing_chain.certificates[0].raw_bytes)

        logger.info("Agent card verified successfully (certificate, subject=%s)", cert.subject.rfc4514_string())
        return VerificationResult(
            valid=True,
            agent_card=verified_card,
            certificate=cert,
            raw_card_data=raw_card_data,
        )

    def verify_file(self, file_path: str | Path) -> VerificationResult:
        return self.verify_signed_card(file_path)
