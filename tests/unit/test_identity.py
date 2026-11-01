import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from attesta.gateway.identity import identity_from_der


def _cert(sans: list, cn: str = "ignored") -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(hours=1)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def test_spiffe_id_comes_from_uri_san():
    der = _cert([x509.UniformResourceIdentifier("spiffe://attesta.example.org/scoring-service")])
    peer = identity_from_der(der)
    assert peer.spiffe_id == "spiffe://attesta.example.org/scoring-service"
    assert len(peer.cert_sha256) == 64


def test_cn_or_dns_san_is_not_an_identity():
    with pytest.raises(ValueError):
        identity_from_der(_cert([x509.DNSName("scoring-service")],
                                cn="spiffe://attesta.example.org/scoring-service"))
    with pytest.raises(ValueError):
        identity_from_der(_cert([]))
    with pytest.raises(ValueError):
        identity_from_der(_cert([x509.UniformResourceIdentifier("https://example.org")]))
