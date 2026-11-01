"""Test isolation: every DB and key lives in a temp dir, never the real ones."""
import base64
import os
import tempfile
import uuid
from pathlib import Path

# Legacy modules read these at import time; point them at a session temp dir.
_SESSION_TMP = tempfile.mkdtemp(prefix="attesta-tests-")
os.environ["ATTESTA_DB_PATH"] = str(Path(_SESSION_TMP) / "legacy.db")
os.environ["ATTESTA_LEGACY_KEY_DIR"] = str(Path(_SESSION_TMP) / "legacy_keys")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from attesta.backends.sqlite import SqliteBackend  # noqa: E402
from attesta.ledger.checkpoints import CheckpointSigner  # noqa: E402
from attesta.policy.engine import PolicyConfig  # noqa: E402
from attesta.records.signing import KeyRegistry, ScorerKey, sign_record_fields  # noqa: E402

SCORER_ID = "spiffe://attesta.example.org/scoring-service"
SCORER_CERT = "ab" * 32


def sha(label: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture
def scorer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def registry(scorer_key: Ed25519PrivateKey) -> KeyRegistry:
    raw = scorer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return KeyRegistry([ScorerKey(
        key_id="k1", public_key=base64.b64encode(raw).decode(),
        not_before="2020-01-01T00:00:00+00:00", not_after="2099-01-01T00:00:00+00:00")])


@pytest.fixture
def policy() -> PolicyConfig:
    return PolicyConfig(policy_version="p1", bands=[
        {"name": "LOW", "min_score": 0, "max_score": 399, "decision": "ALLOW"},
        {"name": "MEDIUM", "min_score": 400, "max_score": 699, "decision": "WARN"},
        {"name": "HIGH", "min_score": 700, "max_score": 899, "decision": "REVIEW"},
        {"name": "CRITICAL", "min_score": 900, "max_score": 1000, "decision": "BLOCK"},
    ])


@pytest.fixture
def backend(tmp_path: Path) -> SqliteBackend:
    return SqliteBackend(tmp_path / "ledger.db", CheckpointSigner.load_or_create(tmp_path / "keys"))


def make_fields(**overrides):
    fields = {
        "record_id": str(uuid.uuid4()), "run_id": f"run-{uuid.uuid4().hex[:8]}",
        "submitted_by_spiffe_id": SCORER_ID, "caller_cert_sha256": SCORER_CERT,
        "ecosystem": "pypi", "package": "pkg", "version": "1.0.0",
        "artifact_digest": sha("a"), "risk_score": 100, "risk_band": "LOW",
        "flag_install_exec": False, "flag_network": False, "flag_obfuscation": False,
        "flag_cred_access": False, "flag_process_spawn": False,
        "llm_verdict": "NOT_RUN", "llm_evidence_hash": None,
        "model_version_hash": sha("m"), "policy_version": "p1", "runner_class": "demo",
        "node_attestor": "join_token", "attestation_verified": True,
        "attestation_digest": sha("att"), "decision": "ALLOW", "evidence_hash": sha("e"),
        "scorer_key_id": "k1",
    }
    fields.update(overrides)
    return fields


@pytest.fixture
def signed(scorer_key: Ed25519PrivateKey):
    """Factory: signed TrustRecord with optional field overrides."""
    return lambda **overrides: sign_record_fields(make_fields(**overrides), scorer_key)
