"""Reloadable mTLS contexts built from SVID material (trust bundle = client CA)."""
import ssl
import tempfile
from pathlib import Path

from attesta.gateway.svid import SvidMaterial


def _load(ctx: ssl.SSLContext, material: SvidMaterial) -> None:
    # load_cert_chain needs files; use a short-lived dir (tmpfs in the container).
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp, "chain.pem"), Path(tmp, "key.pem")
        cert.write_text(material.cert_chain_pem)
        key.write_text(material.key_pem)
        key.chmod(0o600)
        ctx.load_cert_chain(str(cert), str(key))
    ctx.load_verify_locations(cadata=material.bundle_pem)


def build_server_context(material: SvidMaterial) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    _load(ctx, material)
    return ctx


def build_client_context(material: SvidMaterial) -> ssl.SSLContext:
    """Client side: presents our SVID; hostname checks are replaced by SPIFFE ID checks."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    _load(ctx, material)
    return ctx


def reload_context(ctx: ssl.SSLContext, material: SvidMaterial) -> None:
    """Hot-swap the certificate for new handshakes (SVID rotation)."""
    _load(ctx, material)
