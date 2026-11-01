"""Real TLS handshake against uvicorn + MtlsH11Protocol with a throwaway CA."""
import datetime
import hashlib
import http.client
import json
import socket
import ssl
import threading
import time

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from attesta.gateway.app import create_app
from attesta.gateway.protocol import MtlsH11Protocol
from attesta.gateway.settings import GatewaySettings
from attesta.gateway.svid import SvidMaterial
from attesta.gateway.tls import build_client_context, build_server_context
from attesta.records.signing import sign_record_fields
from tests.conftest import SCORER_ID, make_fields

GATEWAY_ID = "spiffe://attesta.example.org/gateway"
PEM = serialization.Encoding.PEM


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(ca_key, ca_cert, spiffe_id: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name("leaf")).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(spiffe_id)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert, key


def _material(cert, key, ca_cert) -> SvidMaterial:
    der = cert.public_bytes(serialization.Encoding.DER)
    return SvidMaterial(
        cert.public_bytes(PEM).decode(),
        key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode(),
        ca_cert.public_bytes(PEM).decode(), hashlib.sha256(der).hexdigest())


@pytest.fixture
def running_gateway(backend, registry, policy):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (x509.CertificateBuilder().subject_name(_name("ca")).issuer_name(_name("ca"))
               .public_key(ca_key.public_key()).serial_number(1)
               .not_valid_before(now - datetime.timedelta(minutes=1))
               .not_valid_after(now + datetime.timedelta(hours=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    server = _material(*_issue(ca_key, ca_cert, GATEWAY_ID), ca_cert)
    scorer = _material(*_issue(ca_key, ca_cert, SCORER_ID), ca_cert)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ctx = build_server_context(server)
    app = create_app(GatewaySettings(), backend, registry, policy)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, http=MtlsH11Protocol,
                            ssl_context_factory=lambda _c, _d: ctx, log_level="warning")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if uv.started:
            break
        time.sleep(0.05)
    yield port, scorer
    uv.should_exit = True
    thread.join(timeout=5)


def _request(port, ctx, method, path, body=None):
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    try:
        conn.request(method, path, body=json.dumps(body) if body else None,
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read() or b"null")
    finally:
        conn.close()


def test_scorer_submits_over_mtls(running_gateway, scorer_key):
    port, scorer = running_gateway
    ctx = build_client_context(scorer)
    record = sign_record_fields(make_fields(caller_cert_sha256=scorer.leaf_sha256), scorer_key)
    status, body = _request(port, ctx, "POST", "/records", record.to_dict())
    assert status == 201 and body["sequence"] == 1
    status, _ = _request(port, ctx, "GET", "/checkpoint")
    assert status == 200


def test_client_without_certificate_is_refused(running_gateway):
    port, scorer = running_gateway
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(cadata=scorer.bundle_pem)
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        _request(port, ctx, "GET", "/records")
