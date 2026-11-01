"""Scorer key registry and Ed25519 signature verification for TrustRecords.

Only public keys live in the registry file. Private keys never enter the repo.
"""
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, field_validator

from attesta.records.trust_record import TrustRecord


class SignatureRejected(Exception):
    """The record's signature or signing key is not acceptable."""


class ScorerKey(BaseModel):
    key_id: str
    public_key: str  # base64 of the raw 32-byte Ed25519 public key
    not_before: datetime
    not_after: datetime
    revoked: bool = False

    @field_validator("not_before", "not_after")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def public_key_obj(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key, validate=True))


class KeyRegistry:
    def __init__(self, keys: list[ScorerKey]) -> None:
        self._keys = {key.key_id: key for key in keys}

    @classmethod
    def load(cls, path: Path) -> "KeyRegistry":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls([ScorerKey(**item) for item in data.get("keys", [])])

    def active_key(self, key_id: str, now: Optional[datetime] = None) -> ScorerKey:
        now = now or datetime.now(timezone.utc)
        key = self._keys.get(key_id)
        if key is None:
            raise SignatureRejected(f"unknown scorer key: {key_id}")
        if key.revoked:
            raise SignatureRejected(f"scorer key revoked: {key_id}")
        if not key.not_before <= now <= key.not_after:
            raise SignatureRejected(f"scorer key outside validity window: {key_id}")
        return key


def verify_record_signature(
    record: TrustRecord, registry: KeyRegistry, now: Optional[datetime] = None
) -> None:
    key = registry.active_key(record.scorer_key_id, now)
    try:
        signature = base64.b64decode(record.scorer_signature, validate=True)
        key.public_key_obj().verify(signature, record.signing_payload())
    except (InvalidSignature, ValueError) as exc:
        raise SignatureRejected("invalid scorer signature") from exc


def sign_record_fields(fields: dict[str, Any], private_key: Ed25519PrivateKey) -> TrustRecord:
    """Sign unsigned record fields (used by the scorer, demo and tests)."""
    placeholder = base64.b64encode(bytes(64)).decode("ascii")
    unsigned = TrustRecord(**fields, scorer_signature=placeholder)
    signature = private_key.sign(unsigned.signing_payload())
    return unsigned.model_copy(
        update={"scorer_signature": base64.b64encode(signature).decode("ascii")}
    )
