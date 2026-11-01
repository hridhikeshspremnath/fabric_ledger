"""Signed checkpoints over the TrustRecord Merkle tree (Ed25519, integer fields)."""
import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from attesta.backends.models import Checkpoint, InclusionProof
from attesta.ledger.merkle import verify_proof
from attesta.records.canonical import canonical_bytes

PRIVATE_NAME = "checkpoint_private.pem"
PUBLIC_NAME = "checkpoint_public.pem"


class CheckpointSigner:
    """Holds the ledger's checkpoint signing key (separate from scorer keys)."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def load_or_create(cls, key_dir: Path) -> "CheckpointSigner":
        key_dir = Path(key_dir)
        private_path, public_path = key_dir / PRIVATE_NAME, key_dir / PUBLIC_NAME
        if private_path.exists():
            key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
            return cls(key)  # type: ignore[arg-type]
        key_dir.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        private_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        private_path.chmod(0o600)
        public_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return cls(key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._private_key.sign(payload)).decode("ascii")


def _unsigned(checkpoint: Checkpoint) -> dict[str, int | str]:
    return {
        "version": checkpoint.version,
        "record_count": checkpoint.record_count,
        "merkle_root": checkpoint.merkle_root,
        "timestamp": checkpoint.timestamp,
    }


def sign_checkpoint(record_count: int, merkle_root: str, timestamp: int,
                    signer: CheckpointSigner) -> Checkpoint:
    unsigned = Checkpoint(version=1, record_count=record_count, merkle_root=merkle_root,
                          timestamp=timestamp, signature="")
    signature = signer.sign(canonical_bytes(_unsigned(unsigned)))
    return unsigned.model_copy(update={"signature": signature})


def verify_checkpoint(checkpoint: Checkpoint, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(base64.b64decode(checkpoint.signature, validate=True),
                          canonical_bytes(_unsigned(checkpoint)))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_inclusion(proof: InclusionProof, checkpoint: Checkpoint,
                     public_key: Ed25519PublicKey) -> bool:
    """True iff the checkpoint is validly signed and the proof leads to its root."""
    return (
        verify_checkpoint(checkpoint, public_key)
        and proof.merkle_root == checkpoint.merkle_root
        and proof.tree_size == checkpoint.record_count
        and verify_proof(proof.leaf_hash, proof.proof, checkpoint.merkle_root)
    )
