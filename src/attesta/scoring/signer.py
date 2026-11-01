"""Ed25519 record signing. The private key must live outside the git work tree."""
import logging
import os
import stat
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attesta.records.signing import sign_record_fields
from attesta.records.trust_record import TrustRecord
from attesta.scoring.errors import ConfigError

log = logging.getLogger("attesta.scoring")


def inside_git_worktree(path: Path, boundary: Optional[Path] = None) -> bool:
    """True if any parent directory (up to `boundary`, for tests) contains `.git`."""
    for parent in path.resolve().parents:
        if (parent / ".git").exists():
            return True
        if boundary is not None and parent == boundary.resolve():
            return False
    return False


class ScorerSigner:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._key = private_key

    @classmethod
    def load(cls, path: Path, key_id: str, allow_in_repo: bool = False) -> "ScorerSigner":
        path = Path(path)
        if not path.is_file():
            raise ConfigError(f"scorer key not found: {path}")
        if inside_git_worktree(path) and not allow_in_repo:
            raise ConfigError(
                f"scorer key {path} is inside a git work tree; keep keys outside the repo "
                "(or set allow_key_in_repo for a gitignored dev key)")
        if os.name == "posix" and path.stat().st_mode & stat.S_IRWXO:
            log.warning("scorer key %s is world-accessible", path)
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigError("scorer key must be an Ed25519 private key")
        return cls(key_id, key)

    def sign(self, fields: dict[str, Any]) -> TrustRecord:
        return sign_record_fields({**fields, "scorer_key_id": self.key_id}, self._key)
