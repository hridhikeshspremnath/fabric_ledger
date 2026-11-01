"""Canonical JSON for hashing and signing.

Rules (chosen so a Go chaincode can reproduce the bytes): keys sorted, no
whitespace, ASCII-only output, and NO floats anywhere. TrustRecord string
fields are restricted to a character set that excludes `<`, `>` and `&`, so
Go's default HTML escaping cannot cause a mismatch.
"""
import hashlib
import json
from typing import Any


def assert_no_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"floats are not allowed in canonical JSON (at {path})")
    if isinstance(obj, dict):
        for key, value in obj.items():
            assert_no_floats(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            assert_no_floats(value, f"{path}[{index}]")


def canonical_bytes(obj: Any) -> bytes:
    assert_no_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
