"""The ledger contract the gateway depends on."""
from __future__ import annotations

from typing import Optional, Protocol

from attesta.backends.models import AnyCheckpoint, LedgerEntry, ListPage, Proof
from attesta.records.trust_record import TrustRecord


class DuplicateRecordError(Exception):
    """run_id or record_id already exists."""


class LedgerEmptyError(Exception):
    """No records yet, so no tree/checkpoint can be built."""


class RecordNotFoundError(Exception):
    """record_id is not in the ledger."""


class LedgerRejectedError(Exception):
    """The ledger (e.g. chaincode) refused the record."""


class LedgerUnavailableError(Exception):
    """The ledger could not be reached or timed out."""


class LedgerBackend(Protocol):
    def append(self, record: TrustRecord) -> LedgerEntry: ...

    def get(self, record_id: str) -> Optional[LedgerEntry]: ...

    def list_page(self, limit: int = 100, cursor: str = "") -> ListPage: ...

    def proof(self, record_id: str) -> Proof: ...

    def checkpoint(self) -> AnyCheckpoint: ...
