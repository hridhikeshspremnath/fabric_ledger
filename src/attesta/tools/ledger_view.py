"""Read-only ledger viewer for the SQLite backend: table, chain check and Merkle root.

    python -m attesta.tools.ledger_view --db /path/to/ledger.db
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from attesta.backends.sqlite import GENESIS_HASH, hash_entry
from attesta.ledger.merkle import build_merkle_tree, get_merkle_root, hash_leaf


def read_rows(db_path: Path) -> list[sqlite3.Row]:
    """Open the database read-only so viewing can never change the ledger."""
    conn = sqlite3.connect(f"file:{Path(db_path).resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM trust_records ORDER BY sequence ASC").fetchall()
    finally:
        conn.close()


def verify_rows(rows: Sequence[sqlite3.Row]) -> tuple[bool, str]:
    expected_previous = GENESIS_HASH
    for row in rows:
        if row["previous_record_hash"] != expected_previous:
            return False, f"entry #{row['sequence']}: previous-hash link broken"
        if hash_entry(row["previous_record_hash"], row["payload"], row["timestamp"]) != row["record_hash"]:
            return False, f"entry #{row['sequence']}: content does not match its hash (tampered)"
        expected_previous = row["record_hash"]
    return True, f"all {len(rows)} entries chain correctly"


def merkle_root(rows: Sequence[sqlite3.Row]) -> Optional[str]:
    if not rows:
        return None
    return get_merkle_root(build_merkle_tree([hash_leaf(r["record_hash"]) for r in rows]))


def render(rows: Sequence[sqlite3.Row]) -> str:
    header = f"{'#':>3}  {'time (UTC)':<19}  {'package@version':<26}  {'decision':<8}  {'score':>5}  {'record hash':<12}  {'prev hash':<12}"
    lines = [header, "-" * len(header)]
    for row in rows:
        record = json.loads(row["payload"])
        when = datetime.fromtimestamp(row["timestamp"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        label = f"{record['package']}@{record['version']}"
        lines.append(f"{row['sequence']:>3}  {when:<19}  {label[:26]:<26}  {record['decision']:<8}  "
                     f"{record['risk_score']:>5}  {row['record_hash'][:10] + '..':<12}  "
                     f"{row['previous_record_hash'][:10] + '..':<12}")
    ok, message = verify_rows(rows)
    root = merkle_root(rows)
    lines += ["", f"chain check : {'VALID' if ok else 'BROKEN'} - {message}",
              f"merkle root : {root if root else '(empty ledger)'}"]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = read_rows(args.db)
    print(render(rows))
    return 0 if verify_rows(rows)[0] else 2


if __name__ == "__main__":
    sys.exit(main())
