"""SVID material from the SPIRE Workload API.

Primary: py-spiffe's X509Source (live rotation). Fallback (config switch
`svid_fallback`): the `spire-agent api fetch x509` binary, re-run on a slow
refresh loop. The fallback is used only if X509Source fails to connect.
"""
import hashlib
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from attesta.gateway.settings import GatewaySettings

log = logging.getLogger("attesta.svid")


@dataclass(frozen=True)
class SvidMaterial:
    cert_chain_pem: str
    key_pem: str
    bundle_pem: str
    leaf_sha256: str


class SvidSource(Protocol):
    refresh_seconds: int

    def snapshot(self) -> SvidMaterial: ...

    def close(self) -> None: ...


class SvidProvider:
    """py-spiffe X509Source wrapper."""

    def __init__(self, socket: str, trust_domain: str, refresh_seconds: int = 300) -> None:
        from spiffe import TrustDomain, X509Source  # imported lazily: optional at test time
        self._source = X509Source(socket_path=socket)
        self._trust_domain = TrustDomain(trust_domain)
        self.refresh_seconds = refresh_seconds

    def snapshot(self) -> SvidMaterial:
        svid = self._source.svid
        if svid is None:
            raise RuntimeError("no X.509 SVID available from the Workload API")
        pem = serialization.Encoding.PEM
        chain = "".join(c.public_bytes(pem).decode("ascii") for c in svid.cert_chain)
        key = svid.private_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
        bundle = self._source.get_bundle_for_trust_domain(self._trust_domain)
        if bundle is None:
            raise RuntimeError("no trust bundle for the trust domain")
        bundle_pem = "".join(
            c.public_bytes(pem).decode("ascii") for c in bundle.x509_authorities)
        leaf_der = svid.leaf.public_bytes(serialization.Encoding.DER)
        return SvidMaterial(chain, key, bundle_pem, hashlib.sha256(leaf_der).hexdigest())

    def close(self) -> None:
        self._source.close()


class FetchLoopProvider:
    """Fallback: shell out to `spire-agent api fetch x509 -write <tmpdir>`."""

    def __init__(self, agent_bin: Path, socket: str, refresh_seconds: int = 1200) -> None:
        self._agent_bin = str(agent_bin)
        # The CLI wants a bare path, not a unix:// URI.
        self._socket = socket.removeprefix("unix://")
        self.refresh_seconds = refresh_seconds

    def snapshot(self) -> SvidMaterial:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [self._agent_bin, "api", "fetch", "x509", "-socketPath", self._socket,
                 "-write", tmp],
                check=True, capture_output=True, timeout=30)
            chain = Path(tmp, "svid.0.pem").read_text()
            key = Path(tmp, "svid.0.key").read_text()
            bundle = Path(tmp, "bundle.0.pem").read_text()
        leaf = x509.load_pem_x509_certificate(chain.encode("ascii"))
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
        return SvidMaterial(chain, key, bundle, hashlib.sha256(leaf_der).hexdigest())

    def close(self) -> None:
        return None


def create_svid_source(settings: GatewaySettings) -> tuple[SvidSource, SvidMaterial]:
    """Primary source; on connect failure use the fetch loop iff `svid_fallback` is on."""
    try:
        primary = SvidProvider(settings.spiffe_socket, settings.trust_domain,
                               settings.svid_refresh_seconds)
        return primary, primary.snapshot()
    except Exception:
        if not settings.svid_fallback:
            raise
        log.warning("X509Source failed to connect; using fetch-loop fallback", exc_info=True)
        fallback = FetchLoopProvider(settings.spire_agent_bin, settings.spiffe_socket,
                                     settings.svid_fallback_refresh_seconds)
        return fallback, fallback.snapshot()
