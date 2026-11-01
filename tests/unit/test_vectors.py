"""Python side of the shared Python/Go vectors (testvectors/*.json)."""
import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from attesta.policy.engine import PolicyConfig, evaluate
from attesta.records.canonical import canonical_bytes
from attesta.records.trust_record import TrustRecord

VECTORS = Path(__file__).resolve().parents[2] / "testvectors"
CANON = json.loads((VECTORS / "canonical.json").read_text(encoding="utf-8"))
RECORDS = json.loads((VECTORS / "records.json").read_text(encoding="utf-8"))
BASE = CANON["signing"]["record"]


@pytest.mark.parametrize("case", CANON["canonical_cases"], ids=lambda c: c["name"])
def test_canonical_cases(case):
    out = canonical_bytes(json.loads(case["input"]))
    assert out.decode("ascii") == case["canonical"]
    assert hashlib.sha256(out).hexdigest() == case["sha256"]


@pytest.mark.parametrize("case", CANON["canonical_rejects"], ids=lambda c: c["name"])
def test_canonical_rejects(case):
    with pytest.raises(ValueError):
        canonical_bytes(json.loads(case["input"]))


def test_signing_vector_matches_python():
    sig = CANON["signing"]
    record = TrustRecord(**sig["record"])
    assert record.signing_payload().decode() == sig["signing_payload"]
    assert record.canonical_bytes().decode() == sig["canonical_record"]
    assert hashlib.sha256(record.canonical_bytes()).hexdigest() == sig["canonical_record_sha256"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sig["seed_hex"]))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64encode(raw).decode() == sig["public_key_b64"]
    assert base64.b64encode(key.sign(record.signing_payload())).decode() == record.scorer_signature


@pytest.mark.parametrize("case", CANON["signing"]["tamper_cases"], ids=lambda c: c["name"])
def test_tampered_records_fail_signature(case):
    sig = CANON["signing"]
    record = TrustRecord(**{**sig["record"], **case["set"]})
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sig["seed_hex"]))
    public_key = key.public_key()
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        public_key.verify(base64.b64decode(record.scorer_signature), record.signing_payload())


@pytest.mark.parametrize("case", RECORDS["mutations"], ids=lambda c: c["name"])
def test_schema_mutations(case):
    payload = copy.deepcopy(BASE)
    payload.update(case.get("set", {}))
    for field in case.get("delete", []):
        payload.pop(field, None)
    if case["valid"]:
        TrustRecord(**payload)
    else:
        with pytest.raises((ValidationError, TypeError)):
            TrustRecord(**payload)


@pytest.mark.parametrize("case", RECORDS["policy"]["cases"],
                         ids=lambda c: f"{c['score']}-{c['verified']}")
def test_policy_cases(case):
    policy = PolicyConfig(policy_version=RECORDS["policy"]["policy_version"],
                          bands=RECORDS["policy"]["bands"])
    result = evaluate(policy, case["score"], case["verified"])
    assert (result.band.value, result.decision.value) == (case["band"], case["decision"])
