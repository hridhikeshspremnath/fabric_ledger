"""SQLite LedgerBackend: hash-chained `trust_records` with Merkle tree and checkpoints.

Chain/Merkle/checkpoint logic mirrors the legacy attestations ledger but runs
over the `trust_records` table. Writes must come from a single writer (the
gateway's writer queue); reads use short-lived connections (WAL mode).
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

from attesta.backends.base import DuplicateRecordError, LedgerEmptyError, RecordNotFoundError
from attesta.backends.models import ChainResult, Checkpoint, InclusionProof, LedgerEntry
from attesta.ledger.checkpoints import CheckpointSigner, sign_checkpoint
from attesta.ledger.merkle import build_merkle_tree, generate_proof, get_merkle_root, hash_leaf
from attesta.records.canonical import canonical_bytes, sha256_hex
from attesta.records.trust_record import TrustRecord

GENESIS_HASH = "GENESIS"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_records (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT UNIQUE NOT NULL,
    run_id TEXT UNIQUE NOT NULL,
    payload TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
)
"""


def hash_entry(previous_hash: str, payload: str, timestamp: int) -> str:
    """record_hash = sha256(canonical({previous_record_hash, record, timestamp}))."""
    body = {"previous_record_hash": previous_hash, "record": json.loads(payload),
            "timestamp": timestamp}
    return sha256_hex(canonical_bytes(body))


class SqliteBackend:
    def __init__(self, db_path: Path, signer: CheckpointSigner) -> None:
        self._db_path = Path(db_path)
        self._signer = signer
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _to_entry(row: sqlite3.Row) -> LedgerEntry:
        return LedgerEntry(
            sequence=row["sequence"], record=TrustRecord.model_validate_json(row["payload"]),
            timestamp=row["timestamp"], previous_record_hash=row["previous_record_hash"],
            record_hash=row["record_hash"])

    def append(self, record: TrustRecord) -> LedgerEntry:
        payload = record.canonical_bytes().decode("ascii")
        timestamp = int(time.time())
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute(
                    "SELECT record_hash FROM trust_records ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous = last["record_hash"] if last else GENESIS_HASH
                record_hash = hash_entry(previous, payload, timestamp)
                cursor = conn.execute(
                    "INSERT INTO trust_records (record_id, run_id, payload, timestamp,"
                    " previous_record_hash, record_hash) VALUES (?,?,?,?,?,?)",
                    (record.record_id, record.run_id, payload, timestamp, previous, record_hash))
                conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise DuplicateRecordError(str(exc)) from exc
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return LedgerEntry(sequence=cursor.lastrowid or 0, record=record, timestamp=timestamp,
                           previous_record_hash=previous, record_hash=record_hash)

    def get(self, record_id: str) -> Optional[LedgerEntry]:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM trust_records WHERE record_id = ?",
                               (record_id,)).fetchone()
        return self._to_entry(row) if row else None

    def list(self, limit: int = 100, after_sequence: int = 0) -> list[LedgerEntry]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM trust_records WHERE sequence > ? ORDER BY sequence ASC LIMIT ?",
                (after_sequence, limit)).fetchall()
        return [self._to_entry(row) for row in rows]

    def _all_rows(self) -> list[sqlite3.Row]:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT * FROM trust_records ORDER BY sequence ASC").fetchall()

    def _tree(self, rows: list[sqlite3.Row]) -> list[list[str]]:
        if not rows:
            raise LedgerEmptyError("ledger has no records")
        return build_merkle_tree([hash_leaf(row["record_hash"]) for row in rows])

    def verify_chain(self) -> ChainResult:
        expected_previous = GENESIS_HASH
        rows = self._all_rows()
        for row in rows:
            if row["previous_record_hash"] != expected_previous:
                return ChainResult(valid=False, records_checked=len(rows),
                                   failed_record=row["record_id"],
                                   reason="Previous record hash mismatch")
            calculated = hash_entry(row["previous_record_hash"], row["payload"], row["timestamp"])
            if calculated != row["record_hash"]:
                return ChainResult(valid=False, records_checked=len(rows),
                                   failed_record=row["record_id"], reason="Record hash mismatch")
            expected_previous = row["record_hash"]
        return ChainResult(valid=True, records_checked=len(rows))

    def proof(self, record_id: str) -> InclusionProof:
        rows = self._all_rows()
        levels = self._tree(rows)
        for index, row in enumerate(rows):
            if row["record_id"] == record_id:
                return InclusionProof(
                    record_id=record_id, record_hash=row["record_hash"],
                    leaf_hash=levels[0][index], leaf_index=index, tree_size=len(rows),
                    merkle_root=get_merkle_root(levels), proof=generate_proof(levels, index))
        raise RecordNotFoundError(record_id)

    def checkpoint(self) -> Checkpoint:
        chain = self.verify_chain()
        if not chain.valid:
            raise ValueError(f"cannot checkpoint an invalid ledger: {chain.reason}")
        rows = self._all_rows()
        root = get_merkle_root(self._tree(rows))
        return sign_checkpoint(len(rows), root, int(time.time()), self._signer)
