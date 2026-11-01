import sqlite3

import pytest

from attesta.backends.base import DuplicateRecordError, LedgerEmptyError, RecordNotFoundError
from attesta.ledger.checkpoints import verify_checkpoint, verify_inclusion


def test_append_get_list_and_chain(backend, signed):
    first = backend.append(signed())
    second = backend.append(signed())
    assert first.previous_record_hash == "GENESIS"
    assert second.previous_record_hash == first.record_hash
    assert backend.get(first.record.record_id).record_hash == first.record_hash
    assert [e.sequence for e in backend.list(limit=10)] == [1, 2]
    assert [e.sequence for e in backend.list(after_sequence=1)] == [2]
    assert backend.verify_chain().valid


def test_duplicate_run_id_and_record_id(backend, signed):
    original = backend.append(signed(run_id="same"))
    with pytest.raises(DuplicateRecordError):
        backend.append(signed(run_id="same"))
    with pytest.raises(DuplicateRecordError):
        backend.append(signed(record_id=original.record.record_id))


def test_tampering_breaks_chain_and_checkpoint(backend, signed, tmp_path):
    for _ in range(3):
        backend.append(signed())
    conn = sqlite3.connect(tmp_path / "ledger.db")
    payload = conn.execute("SELECT payload FROM trust_records WHERE sequence=2").fetchone()[0]
    conn.execute("UPDATE trust_records SET payload=? WHERE sequence=2",
                 (payload.replace('"pkg"', '"evil"'),))
    conn.commit()
    conn.close()
    result = backend.verify_chain()
    assert not result.valid and result.reason == "Record hash mismatch"
    with pytest.raises(ValueError):
        backend.checkpoint()


def test_new_record_proven_against_signed_checkpoint(backend, signed):
    for _ in range(5):
        backend.append(signed())
    new = backend.append(signed())          # the newly added record
    checkpoint = backend.checkpoint()        # signed after it was added
    proof = backend.proof(new.record.record_id)
    public_key = backend._signer.public_key
    assert checkpoint.record_count == 6 and proof.tree_size == 6
    assert verify_checkpoint(checkpoint, public_key)
    assert verify_inclusion(proof, checkpoint, public_key)
    # A forged root or altered leaf must fail.
    forged = checkpoint.model_copy(update={"merkle_root": "0" * 64})
    assert not verify_inclusion(proof, forged, public_key)
    bad_leaf = proof.model_copy(update={"leaf_hash": "1" * 64})
    assert not verify_inclusion(bad_leaf, checkpoint, public_key)


def test_empty_ledger_and_unknown_record(backend, signed):
    with pytest.raises(LedgerEmptyError):
        backend.checkpoint()
    backend.append(signed())
    with pytest.raises(RecordNotFoundError):
        backend.proof("00000000-0000-0000-0000-000000000000")


def test_list_page_uses_sequence_cursor(backend, signed):
    for _ in range(3):
        backend.append(signed())
    first = backend.list_page(limit=2)
    assert [e.sequence for e in first.entries] == [1, 2] and first.next_cursor == "2"
    second = backend.list_page(limit=2, cursor=first.next_cursor)
    assert [e.sequence for e in second.entries] == [3] and second.next_cursor == ""
    with pytest.raises(ValueError):
        backend.list_page(cursor="not-a-number")
