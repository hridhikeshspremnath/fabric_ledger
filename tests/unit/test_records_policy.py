from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from attesta.policy.engine import PolicyConfig, evaluate
from attesta.records.canonical import canonical_bytes
from attesta.records.signing import SignatureRejected, verify_record_signature
from attesta.records.trust_record import TrustRecord
from tests.conftest import make_fields


def test_canonical_json_rejects_floats_and_is_stable():
    assert canonical_bytes({"b": 1, "a": [True, None]}) == b'{"a":[true,null],"b":1}'
    with pytest.raises(ValueError):
        canonical_bytes({"x": {"y": 1.5}})


def test_trust_record_rejects_float_score_and_extra_fields(signed):
    good = signed().to_dict()
    with pytest.raises(ValidationError):
        TrustRecord(**{**good, "risk_score": 100.5})
    with pytest.raises(ValidationError):
        TrustRecord(**{**good, "surprise": 1})
    with pytest.raises(ValidationError):
        TrustRecord(**{**good, "risk_score": 1001})


def test_signature_roundtrip_and_tamper(signed, registry):
    record = signed()
    verify_record_signature(record, registry)
    tampered = record.model_copy(update={"package": "evil"})
    with pytest.raises(SignatureRejected):
        verify_record_signature(tampered, registry)


def test_revoked_and_expired_keys_rejected(signed, registry):
    record = signed()
    key = registry._keys["k1"]
    registry._keys["k1"] = key.model_copy(update={"revoked": True})
    with pytest.raises(SignatureRejected, match="revoked"):
        verify_record_signature(record, registry)
    registry._keys["k1"] = key.model_copy(update={"not_after": datetime(2021, 1, 1, tzinfo=timezone.utc)})
    with pytest.raises(SignatureRejected):
        verify_record_signature(record, registry)


@pytest.mark.parametrize("score,band,decision", [
    (0, "LOW", "ALLOW"), (399, "LOW", "ALLOW"), (400, "MEDIUM", "WARN"),
    (699, "MEDIUM", "WARN"), (700, "HIGH", "REVIEW"), (899, "HIGH", "REVIEW"),
    (900, "CRITICAL", "BLOCK"), (1000, "CRITICAL", "BLOCK"),
])
def test_bands(policy, score, band, decision):
    result = evaluate(policy, score, True)
    assert (result.band.value, result.decision.value) == (band, decision)


def test_unverified_attestation_downgrades_to_review_but_keeps_block(policy):
    assert evaluate(policy, 100, False).decision.value == "REVIEW"
    assert evaluate(policy, 500, False).decision.value == "REVIEW"
    assert evaluate(policy, 950, False).decision.value == "BLOCK"


def test_policy_must_cover_range():
    with pytest.raises(ValidationError):
        PolicyConfig(policy_version="x", bands=[
            {"name": "LOW", "min_score": 0, "max_score": 500, "decision": "ALLOW"}])


def test_make_fields_valid():
    TrustRecord(**make_fields(scorer_signature="A" * 86 + "=="))
