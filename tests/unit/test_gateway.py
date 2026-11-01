import pytest
from fastapi.testclient import TestClient

from attesta.backends.models import Checkpoint, InclusionProof
from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.ledger.checkpoints import verify_inclusion
from tests.conftest import SCORER_CERT, SCORER_ID

SCORER = PeerIdentity(SCORER_ID, SCORER_CERT)


@pytest.fixture
def make_client(backend, registry, policy):
    def build(peer: PeerIdentity = SCORER) -> TestClient:
        app = create_app(GatewaySettings(), backend, registry, policy)
        app.dependency_overrides[get_peer_identity] = lambda: peer
        return TestClient(app)
    return build


def post(client, record):
    return client.post("/records", json=record.to_dict())


def test_valid_record_is_appended_and_readable(make_client, signed):
    record = signed()
    with make_client() as client:
        response = post(client, record)
        assert response.status_code == 201
        assert response.json()["sequence"] == 1
        assert client.get(f"/records/{record.record_id}").json()["record_hash"]
        assert len(client.get("/records").json()) == 1
        assert client.get("/records/nope").status_code == 404


def test_bad_signature_rejected(make_client, signed):
    tampered = signed().model_copy(update={"package": "evil"})
    with make_client() as client:
        response = post(client, tampered)
    assert response.status_code == 403 and "signature" in response.json()["detail"]


def test_duplicate_run_id_rejected(make_client, signed):
    with make_client() as client:
        assert post(client, signed(run_id="r1")).status_code == 201
        assert post(client, signed(run_id="r1")).status_code == 409


def test_wrong_caller_id_rejected(make_client, signed):
    other = PeerIdentity("spiffe://attesta.example.org/ci/build-runner", SCORER_CERT)
    with make_client(other) as client:
        assert post(client, signed()).status_code == 403
    outsider = PeerIdentity("spiffe://evil.example.org/scoring-service", SCORER_CERT)
    with make_client(outsider) as client:
        assert post(client, signed()).status_code == 403


def test_caller_binding_mismatches_rejected(make_client, signed):
    with make_client() as client:
        assert post(client, signed(caller_cert_sha256="cd" * 32)).status_code == 403
        assert post(client, signed(
            submitted_by_spiffe_id="spiffe://attesta.example.org/other")).status_code == 403


def test_policy_mismatches_rejected(make_client, signed):
    with make_client() as client:
        assert post(client, signed(decision="BLOCK")).status_code == 422
        assert post(client, signed(risk_band="HIGH")).status_code == 422
        assert post(client, signed(policy_version="other")).status_code == 422
        # Unverified attestation: ALLOW is not acceptable, REVIEW is.
        unverified = dict(attestation_verified=False, attestation_digest=None)
        assert post(client, signed(**unverified)).status_code == 422
        assert post(client, signed(decision="REVIEW", **unverified)).status_code == 201


def test_invalid_payload_and_float_score_rejected(make_client, signed):
    body = signed().to_dict()
    with make_client() as client:
        assert client.post("/records", json={**body, "risk_score": 100.5}).status_code == 422
        assert client.post("/records", json={**body, "artifact_digest": "md5:x"}).status_code == 422


def test_proof_and_checkpoint_verify_through_api(make_client, signed, backend):
    records = [signed() for _ in range(4)]
    with make_client() as client:
        for record in records:
            assert post(client, record).status_code == 201
        checkpoint = Checkpoint(**client.get("/checkpoint").json())
        proof = InclusionProof(**client.get(f"/proof/{records[-1].record_id}").json())
    assert verify_inclusion(proof, checkpoint, backend._signer.public_key)
    assert backend.verify_chain().valid


def test_empty_ledger_checkpoint_is_404(make_client):
    with make_client() as client:
        assert client.get("/checkpoint").status_code == 404
