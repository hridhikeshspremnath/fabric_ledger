"""The ledger contract the gateway depends on."""
from __future__ import annotations

from typing import Optional, Protocol

from attesta.backends.models import ChainResult, Checkpoint, InclusionProof, LedgerEntry
from attesta.records.trust_record import TrustRecord


class DuplicateRecordError(Exception):
    """run_id or record_id already exists."""


class LedgerEmptyError(Exception):
    """No records yet, so no tree/checkpoint can be built."""


class RecordNotFoundError(Exception):
    """record_id is not in the ledger."""


class LedgerBackend(Protocol):
    def append(self, record: TrustRecord) -> LedgerEntry: ...

    def get(self, record_id: str) -> Optional[LedgerEntry]: ...

    def list(self, limit: int = 100, after_sequence: int = 0) -> list[LedgerEntry]: ...

    def proof(self, record_id: str) -> InclusionProof: ...

    def checkpoint(self) -> Checkpoint: ...

    def verify_chain(self) -> ChainResult: ...
