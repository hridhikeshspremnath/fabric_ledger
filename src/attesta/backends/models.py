"""Backend-neutral result types (JSON-serializable, integers only).

Proofs and checkpoints are tagged with `kind` because SQLite (Merkle tree +
signed checkpoint) and Fabric (block hash chain) prove inclusion differently.
"""
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field

from attesta.records.trust_record import TrustRecord


class LedgerEntry(BaseModel):
    # SQLite-only chain fields are optional so Fabric entries fit the same shape.
    sequence: Optional[int] = None
    record: TrustRecord
    timestamp: int  # unix seconds (ledger time / Fabric tx timestamp)
    previous_record_hash: Optional[str] = None
    record_hash: str
    # Fabric-only fields.
    tx_id: Optional[str] = None
    block_number: Optional[int] = None
    effective_decision: Optional[str] = None  # reflects auditor overrides
    overrides: list[dict[str, Any]] = Field(default_factory=list)


class ListPage(BaseModel):
    entries: list[LedgerEntry]
    next_cursor: str = ""  # opaque; empty means no more pages


class InclusionProof(BaseModel):
    kind: Literal["merkle"] = "merkle"
    record_id: str
    record_hash: str
    leaf_hash: str
    leaf_index: int
    tree_size: int
    merkle_root: str
    proof: list[dict[str, str]]


class FabricProof(BaseModel):
    kind: Literal["fabric"] = "fabric"
    record_id: str
    tx_id: str
    block_number: int
    block_hash: str
    previous_block_hash: str
    data_hash: str
    validation_code: str
    chain_height: int
    chain_tip_hash: str


class Checkpoint(BaseModel):
    kind: Literal["merkle"] = "merkle"
    version: int
    record_count: int
    merkle_root: str
    timestamp: int
    signature: str


class FabricCheckpoint(BaseModel):
    kind: Literal["fabric"] = "fabric"
    channel: str
    height: int
    current_block_hash: str
    previous_block_hash: str


class ArtifactVerdict(BaseModel):
    """Every decision recorded for one artifact digest (what a deploy gate asks for).

    Same shape as the chaincode's VerifyArtifact: `records` items carry record_id,
    effective_decision, tx_time and tx_id.
    """
    artifact_digest: str
    found: bool
    latest_record_id: Optional[str] = None
    latest_effective_decision: Optional[str] = None
    records: list[dict[str, Any]] = Field(default_factory=list)


class ChainResult(BaseModel):
    valid: bool
    records_checked: int
    failed_record: Optional[str] = None
    reason: Optional[str] = None


Proof = Union[InclusionProof, FabricProof]
AnyCheckpoint = Union[Checkpoint, FabricCheckpoint]
