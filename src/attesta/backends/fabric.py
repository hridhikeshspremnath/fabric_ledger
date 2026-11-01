"""Hyperledger Fabric backend (target ledger). Not implemented yet.

The chaincode must reproduce `canonical_bytes` and the record-hash formula in
`attesta.backends.sqlite.hash_entry`; both use integers only so Go can match them.
"""
from __future__ import annotations

from typing import Optional

from attesta.backends.models import ChainResult, Checkpoint, InclusionProof, LedgerEntry
from attesta.records.trust_record import TrustRecord

_MSG = "FabricBackend is not implemented yet"


class FabricBackend:
    def append(self, record: TrustRecord) -> LedgerEntry:
        raise NotImplementedError(_MSG)

    def get(self, record_id: str) -> Optional[LedgerEntry]:
        raise NotImplementedError(_MSG)

    def list(self, limit: int = 100, after_sequence: int = 0) -> list[LedgerEntry]:
        raise NotImplementedError(_MSG)

    def proof(self, record_id: str) -> InclusionProof:
        raise NotImplementedError(_MSG)

    def checkpoint(self) -> Checkpoint:
        raise NotImplementedError(_MSG)

    def verify_chain(self) -> ChainResult:
        raise NotImplementedError(_MSG)
