"""Backend-neutral result types (JSON-serializable, integers only)."""
from typing import Optional

from pydantic import BaseModel

from attesta.records.trust_record import TrustRecord


class LedgerEntry(BaseModel):
    sequence: int
    record: TrustRecord
    timestamp: int  # unix seconds
    previous_record_hash: str
    record_hash: str


class InclusionProof(BaseModel):
    record_id: str
    record_hash: str
    leaf_hash: str
    leaf_index: int
    tree_size: int
    merkle_root: str
    proof: list[dict[str, str]]


class Checkpoint(BaseModel):
    version: int
    record_count: int
    merkle_root: str
    timestamp: int
    signature: str


class ChainResult(BaseModel):
    valid: bool
    records_checked: int
    failed_record: Optional[str] = None
    reason: Optional[str] = None
