"""mTLS client for the Fabric bridge, authenticated with the gateway's SVID.

The server is authenticated by SPIFFE ID (URI SAN), not hostname.
"""
from __future__ import annotations

import http.client
import json
import ssl
import time
from typing import Any, Optional

from attesta.gateway.identity import identity_from_der
from attesta.gateway.svid import SvidSource
from attesta.gateway.tls import build_client_context, reload_context


class BridgeIdentityError(RuntimeError):
    """The bridge presented a SPIFFE ID other than the expected one."""


class SpiffeBridgeClient:
    def __init__(self, host: str, port: int, expected_server_id: str, source: SvidSource,
                 refresh_seconds: int = 300, timeout: float = 90.0) -> None:
        self._host, self._port, self._expected = host, port, expected_server_id
        self._source, self._refresh, self._timeout = source, refresh_seconds, timeout
        material = source.snapshot()
        self._leaf = material.leaf_sha256
        self._ctx: ssl.SSLContext = build_client_context(material)
        self._checked = time.monotonic()

    def _context(self) -> ssl.SSLContext:
        if time.monotonic() - self._checked >= self._refresh:
            material = self._source.snapshot()
            if material.leaf_sha256 != self._leaf:
                reload_context(self._ctx, material)
                self._leaf = material.leaf_sha256
            self._checked = time.monotonic()
        return self._ctx

    def leaf_sha256(self) -> str:
        """Fingerprint of the client certificate the next request will present."""
        self._context()
        return self._leaf

    def request(self, method: str, path: str,
                body: Optional[dict[str, Any]] = None) -> tuple[int, Any]:
        conn = http.client.HTTPSConnection(self._host, self._port, context=self._context(),
                                           timeout=self._timeout)
        try:
            conn.connect()
            peer = identity_from_der(conn.sock.getpeercert(binary_form=True))  # type: ignore[union-attr]
            if peer.spiffe_id != self._expected:
                raise BridgeIdentityError(f"unexpected bridge identity: {peer.spiffe_id}")
            payload = json.dumps(body) if body is not None else None
            conn.request(method, path, body=payload, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
        except (OSError, http.client.HTTPException) as exc:
            return 503, {"error": f"bridge unreachable: {exc}"}
        finally:
            conn.close()
