"""Signed policy decisions: payload, policy service, gateway enforcement, scorer integration."""
import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.policy.decision import (
    DECISION_FIELDS, PolicyUnavailable, bundle_hash, decision_payload, remote_decide, sign_decision, verify_decision)
from attesta.policy.opa import OpaUnavailable
from attesta.policy.service import create_decision_app
from attesta.records.signing import KeyRegistry, ScorerKey, SignatureRejected, sign_record_fields
from attesta.records.trust_record import Decision
from tests.conftest import SCORER_CERT, SCORER_ID, make_fields, sha

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "testvectors" / "canonical.json").read_text())["decision"]
BUNDLE = sha("bundle")


def decision_registry(key: Ed25519PrivateKey, key_id="d1") -> KeyRegistry:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return KeyRegistry([ScorerKey(key_id=key_id, public_key=base64.b64encode(raw).decode(),
                                  not_before="2020-01-01T00:00:00+00:00", not_after="2099-01-01T00:00:00+00:00")])


@pytest.fixture
def dkey():
    return Ed25519PrivateKey.generate()


def test_payload_and_signature_match_the_shared_vector():
    assert decision_payload(VECTORS["fields"]).decode() == VECTORS["payload"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["seed_hex"]))
    assert sign_decision(VECTORS["fields"], key) == VECTORS["signature_b64"]
    verify_decision(VECTORS["fields"], "d1", VECTORS["signature_b64"], decision_registry(key))


@pytest.mark.parametrize("case", VECTORS["tamper_cases"], ids=lambda c: c["name"])
def test_any_changed_field_breaks_the_signature(case):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["seed_hex"]))
    with pytest.raises(SignatureRejected):
        verify_decision({**VECTORS["fields"], **case["set"]}, "d1", VECTORS["signature_b64"], decision_registry(key))


def test_unknown_or_revoked_key_is_rejected(dkey):
    fields = VECTORS["fields"]
    sig = sign_decision(fields, dkey)
    with pytest.raises(SignatureRejected):
        verify_decision(fields, "other", sig, decision_registry(dkey))
    with pytest.raises(SignatureRejected):
        verify_decision(fields, "d1", sig, decision_registry(Ed25519PrivateKey.generate()))


def test_bundle_hash_changes_with_either_file(tmp_path):
    yaml_file, rego = tmp_path / "p.yaml", tmp_path / "p.rego"
    yaml_file.write_text("bands: a")
    rego.write_text("rules: a")
    base = bundle_hash(yaml_file, rego)
    assert base.startswith("sha256:") and base == bundle_hash(yaml_file, rego)
    rego.write_text("rules: b")
    assert bundle_hash(yaml_file, rego) != base
    rego.write_text("rules: a")
    yaml_file.write_text("bands: b")
    assert bundle_hash(yaml_file, rego) != base


# ---- the policy service ----------------------------------------------------------------------

EVIDENCE = {"record_id": "11111111-1111-4111-8111-111111111111", "artifact_digest": sha("a"), "risk_score": 100,
            "attestation_verified": True, "flag_install_exec": False, "flag_network": False,
            "flag_obfuscation": False, "flag_cred_access": False, "flag_process_spawn": False, "llm_verdict": "NOT_RUN"}


def service_client(policy, dkey, floor=lambda f: Decision.ALLOW):
    return TestClient(create_decision_app(policy, floor, dkey, "d1", BUNDLE))


def test_service_signs_a_decision_the_chaincode_style_check_accepts(policy, dkey):
    out = service_client(policy, dkey).post("/v1/decide", json=EVIDENCE).json()
    assert out["decision"] == "ALLOW" and out["risk_band"] == "LOW" and out["policy_bundle_hash"] == BUNDLE
    verify_decision({k: out[k] for k in DECISION_FIELDS}, out["decision_key_id"], out["decision_signature"],
                    decision_registry(dkey))


def test_service_applies_floors_and_the_attestation_downgrade(policy, dkey):
    floored = service_client(policy, dkey, floor=lambda f: Decision.BLOCK).post("/v1/decide", json=EVIDENCE).json()
    assert floored["decision"] == "BLOCK"
    unattested = service_client(policy, dkey).post("/v1/decide", json={**EVIDENCE, "attestation_verified": False}).json()
    assert unattested["decision"] == "REVIEW"


def test_service_fails_strict_and_validates_input(policy, dkey):
    def down(_fields):
        raise OpaUnavailable("refused")

    assert service_client(policy, dkey, down).post("/v1/decide", json=EVIDENCE).status_code == 503
    client = service_client(policy, dkey)
    assert client.post("/v1/decide", json={**EVIDENCE, "risk_score": 1001}).status_code == 422
    assert client.post("/v1/decide", json={**EVIDENCE, "risk_score": 1.5}).status_code == 422
    assert client.post("/v1/decide", json={**EVIDENCE, "extra": 1}).status_code == 422
    assert client.post("/v1/decide", json={k: v for k, v in EVIDENCE.items() if k != "record_id"}).status_code == 422


def test_unreachable_policy_service_is_an_error_not_a_default():
    with pytest.raises(PolicyUnavailable):
        remote_decide("http://127.0.0.1:1", timeout=1)(EVIDENCE)


# ---- the gateway -----------------------------------------------------------------------------

def signed_record(policy, dkey, scorer_key, key_id="d1", bundle=BUNDLE, tweak=None, **over):
    """A scorer-signed record whose decision the policy service signed."""
    base = make_fields(policy_bundle_hash=bundle, decision_key_id=key_id, **over)
    evidence = {k: base[k] for k in EVIDENCE if k in base}
    out = service_client(policy, dkey).post("/v1/decide", json={**EVIDENCE, **evidence}).json()
    fields = {**base, **{k: out[k] for k in ("decision", "risk_band")}, "decision_signature": out["decision_signature"],
              "policy_bundle_hash": bundle}
    if tweak:
        fields.update(tweak)
    return sign_record_fields(fields, scorer_key)


@pytest.fixture
def gateway(backend, registry, policy, dkey):
    app = create_app(GatewaySettings(), backend, registry, policy,
                     decision_keys=decision_registry(dkey), bundle=BUNDLE)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as client:
        yield client


def post(client, record):
    return client.post("/records", json=record.to_dict()).status_code


def test_gateway_accepts_a_properly_signed_decision(gateway, policy, dkey, scorer_key):
    assert post(gateway, signed_record(policy, dkey, scorer_key, record_id="11111111-1111-4111-8111-111111111111",
                                       artifact_digest=sha("a"), risk_score=100, risk_band="LOW")) == 201


def test_gateway_refuses_unsigned_wrong_bundle_forged_and_foreign_signatures(gateway, policy, dkey, scorer_key):
    ok = dict(artifact_digest=sha("a"), risk_score=100, risk_band="LOW")
    unsigned = sign_record_fields(make_fields(**ok), scorer_key)
    assert post(gateway, unsigned) == 422                                      # no bundle hash: not this bundle
    no_sig = sign_record_fields(make_fields(policy_bundle_hash=BUNDLE, **ok), scorer_key)
    assert post(gateway, no_sig) == 403                                        # bundle ok, no signature
    assert post(gateway, signed_record(policy, dkey, scorer_key, bundle=sha("other"), **ok)) == 422
    assert post(gateway, signed_record(policy, Ed25519PrivateKey.generate(), scorer_key, **ok)) == 403   # other key
    # The scorer re-signs a record after changing the decision: its own signature is fine, the policy's is not.
    forged = signed_record(policy, dkey, scorer_key, tweak={"decision": "BLOCK"}, **ok)
    assert post(gateway, forged) == 403


def test_without_decision_keys_the_gateway_does_not_require_signatures(backend, registry, policy, scorer_key):
    app = create_app(GatewaySettings(), backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as client:
        assert post(client, sign_record_fields(make_fields(), scorer_key)) == 201
