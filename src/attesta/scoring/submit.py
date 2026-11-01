"""Submit a signed TrustRecord to the gateway over SPIFFE mTLS."""
from typing import Any, Callable, Optional, Protocol

from attesta.records.trust_record import TrustRecord
from attesta.scoring.errors import SubmitError


class JsonClient(Protocol):
    def request(self, method: str, path: str,
                body: Optional[dict[str, Any]] = None) -> tuple[int, Any]: ...


class Submitter(Protocol):
    def cert_sha256(self) -> str: ...

    def submit(self, record: TrustRecord) -> dict[str, Any]: ...


class GatewaySubmitter:
    """Wraps an mTLS JSON client (SpiffeBridgeClient pointed at the gateway)."""

    def __init__(self, client: JsonClient, cert_fingerprint: Callable[[], str]) -> None:
        self._client = client
        self._fingerprint = cert_fingerprint

    def cert_sha256(self) -> str:
        return self._fingerprint()

    def submit(self, record: TrustRecord) -> dict[str, Any]:
        status, body = self._client.request("POST", "/records", record.to_dict())
        if status == 201:
            return body
        detail = body.get("detail") if isinstance(body, dict) else body
        raise SubmitError(f"gateway returned {status}: {detail}")
