"""Deploy gate: decision rule, the gateway's artifact lookup, and both backends."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from attesta.backends.fabric import FabricBackend
from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.tools.deploy_gate import decide, digest_of
from tests.conftest import SCORER_CERT, SCORER_ID, sha

ALLOW = frozenset({"ALLOW"})


def verdict(*decisions: str) -> dict:
    records = [{"record_id": f"r{i}", "effective_decision": d, "tx_time": i, "tx_id": f"t{i}"}
               for i, d in enumerate(decisions)]
    last = records[-1] if records else {}
    return {"artifact_digest": sha("a"), "found": bool(records), "records": records,
            "latest_record_id": last.get("record_id"),
            "latest_effective_decision": last.get("effective_decision")}


@pytest.mark.parametrize("decisions,allowed,expected", [
    ((), ALLOW, False),                               # never scored: refuse
    (("ALLOW",), ALLOW, True),
    (("REVIEW",), ALLOW, False),
    (("WARN",), ALLOW, False),
    (("WARN",), frozenset({"ALLOW", "WARN"}), True),  # team chose to deploy on WARN
    (("REVIEW", "ALLOW"), ALLOW, True),               # latest decision wins...
    (("BLOCK", "ALLOW"), ALLOW, False),               # ...but a standing BLOCK is never outvoted
    (("ALLOW", "BLOCK"), ALLOW, False),
])
def test_decision_rule(decisions, allowed, expected):
    assert decide(verdict(*decisions), allowed)[0] is expected


def test_digest_of_file_and_literal(tmp_path):
    artifact = tmp_path / "app.tar.gz"
    artifact.write_bytes(b"release bytes")
    assert digest_of(str(artifact)) == "sha256:" + hashlib.sha256(b"release bytes").hexdigest()
    assert digest_of(sha("a")) == sha("a")


def test_gateway_reports_decisions_for_a_digest(backend, registry, policy, signed):
    app = create_app(GatewaySettings(), backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as client:
        assert client.post("/records", json=signed().to_dict()).status_code == 201
        known = client.get(f"/artifacts/{sha('a')}").json()
        unknown = client.get(f"/artifacts/{sha('never-scored')}").json()
        assert client.get("/artifacts/md5:nope").status_code == 422
    assert known["found"] and known["latest_effective_decision"] == "ALLOW"
    assert decide(known, ALLOW)[0] is True
    assert not unknown["found"] and decide(unknown, ALLOW)[0] is False


def test_fabric_backend_passes_the_chaincode_view_through():
    class Bridge:
        def request(self, method, path, body=None):
            assert (method, path) == ("GET", "/v1/artifacts/sha256%3A" + sha("a")[7:])
            return 200, verdict("REVIEW", "ALLOW")

    result = FabricBackend(Bridge()).verify_artifact(sha("a"))
    assert result.found and result.latest_effective_decision == "ALLOW" and len(result.records) == 2
