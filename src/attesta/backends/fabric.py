"""Hyperledger Fabric backend: talks to the Go bridge over (SPIFFE mTLS) HTTP.

The bridge holds the Fabric identity; this class never sees Fabric keys. The
chaincode re-validates everything (signature, policy, replay) independently,
so a compromised gateway still cannot forge a record without the scorer key.
"""
from __future__ import annotations

import hashlib
from typing import Any, Optional, Protocol
from urllib.parse import quote

from attesta.backends.base import (
    DuplicateRecordError, LedgerRejectedError, LedgerUnavailableError, RecordNotFoundError)
from attesta.backends.models import (
    ArtifactVerdict, FabricCheckpoint, FabricProof, LedgerEntry, ListPage)
from attesta.records.trust_record import TrustRecord


class BridgeTransport(Protocol):
    def request(self, method: str, path: str,
                body: Optional[dict[str, Any]] = None) -> tuple[int, Any]: ...


def record_hash(record: TrustRecord) -> str:
    """SHA-256 of the canonical record bytes (what the chaincode stores)."""
    return hashlib.sha256(record.canonical_bytes()).hexdigest()


def _message(body: Any) -> str:
    return str(body.get("error", body)) if isinstance(body, dict) else str(body)


class FabricBackend:
    def __init__(self, transport: BridgeTransport) -> None:
        self._bridge = transport

    # -- helpers -----------------------------------------------------------

    def _call(self, method: str, path: str, body: Optional[dict[str, Any]] = None,
              allow_404: bool = False) -> Optional[Any]:
        status, payload = self._bridge.request(method, path, body)
        if status < 400:
            return payload
        if status == 404 and allow_404:
            return None
        if status == 404:
            raise RecordNotFoundError(_message(payload))
        if status == 409:
            raise DuplicateRecordError(_message(payload))
        if status in (400, 422):
            raise LedgerRejectedError(_message(payload))
        raise LedgerUnavailableError(f"bridge error {status}: {_message(payload)}")

    @staticmethod
    def _entry(view: dict[str, Any]) -> LedgerEntry:
        record = TrustRecord.model_validate(view["record"])
        meta = view["meta"]
        return LedgerEntry(
            record=record, timestamp=meta["tx_time"], record_hash=record_hash(record),
            tx_id=meta["tx_id"], effective_decision=meta.get("effective_decision"),
            overrides=view.get("overrides") or [])

    # -- LedgerBackend -----------------------------------------------------

    def append(self, record: TrustRecord) -> LedgerEntry:
        body = self._call("POST", "/v1/records", record.to_dict())
        assert body is not None
        return LedgerEntry(
            record=record, timestamp=body["result"]["tx_time"], record_hash=record_hash(record),
            tx_id=body["tx_id"], block_number=body["block_number"],
            effective_decision=record.decision.value)

    def get(self, record_id: str) -> Optional[LedgerEntry]:
        view = self._call("GET", f"/v1/records/{quote(record_id, safe='')}", allow_404=True)
        return None if view is None else self._entry(view)

    def list_page(self, limit: int = 100, cursor: str = "") -> ListPage:
        path = f"/v1/records?limit={int(limit)}"
        if cursor:
            path += f"&cursor={quote(cursor, safe='')}"
        page = self._call("GET", path)
        assert page is not None
        return ListPage(entries=[self._entry(v) for v in page["items"]],
                        next_cursor=page.get("next_cursor", ""))

    def proof(self, record_id: str) -> FabricProof:
        body = self._call("GET", f"/v1/proof/{quote(record_id, safe='')}")
        assert body is not None
        return FabricProof(record_id=body["record_id"], **body["proof"])

    def checkpoint(self) -> FabricCheckpoint:
        body = self._call("GET", "/v1/checkpoint")
        assert body is not None
        return FabricCheckpoint(**body)

    def active_policy(self) -> dict[str, Any]:
        """The active on-chain policy: version, bands, allowed scorer and the pinned bundle hash."""
        body = self._call("GET", "/v1/policy")
        assert body is not None
        return dict(body)

    def verify_artifact(self, digest: str) -> ArtifactVerdict:
        body = self._call("GET", f"/v1/artifacts/{quote(digest, safe='')}")
        assert body is not None
        return ArtifactVerdict(**body)
