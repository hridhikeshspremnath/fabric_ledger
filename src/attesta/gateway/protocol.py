"""uvicorn HTTP protocol that exposes the verified client certificate to the app.

uvicorn does not put the peer certificate in the ASGI scope, so each
connection's app is wrapped to add the DER bytes under PEER_CERT_SCOPE_KEY.
"""
from typing import Any, Optional

from uvicorn.protocols.http.h11_impl import H11Protocol

from attesta.gateway.identity import PEER_CERT_SCOPE_KEY


class _PeerCertApp:
    def __init__(self, app: Any, der: Optional[bytes]) -> None:
        self._app, self._der = app, der

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and self._der:
            scope = {**scope, PEER_CERT_SCOPE_KEY: self._der}
        await self._app(scope, receive, send)


class MtlsH11Protocol(H11Protocol):
    def connection_made(self, transport: Any) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        self.app = _PeerCertApp(self.app, der)
