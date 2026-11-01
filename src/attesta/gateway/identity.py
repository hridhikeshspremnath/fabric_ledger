"""Peer identity from the mTLS client certificate.

The SPIFFE ID comes from the certificate's URI SAN only (never CN or DNS SAN).
The TLS layer has already validated the chain against the trust bundle.
"""
import hashlib
from dataclasses import dataclass

from cryptography import x509
from fastapi import HTTPException, Request

PEER_CERT_SCOPE_KEY = "attesta.peer_cert_der"


@dataclass(frozen=True)
class PeerIdentity:
    spiffe_id: str
    cert_sha256: str


def identity_from_der(der: bytes) -> PeerIdentity:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("certificate has no SAN extension") from exc
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or not uris[0].startswith("spiffe://"):
        raise ValueError("certificate must carry exactly one spiffe:// URI SAN")
    return PeerIdentity(spiffe_id=uris[0], cert_sha256=hashlib.sha256(der).hexdigest())


def get_peer_identity(request: Request) -> PeerIdentity:
    """FastAPI dependency; tests override it."""
    der = request.scope.get(PEER_CERT_SCOPE_KEY)
    if not der:
        raise HTTPException(status_code=401, detail="client certificate required")
    try:
        return identity_from_der(der)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
