"""GET /policy: what the gateway enforces and what the chain has approved."""
import pytest
from fastapi.testclient import TestClient

from attesta.backends.base import LedgerUnavailableError
from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.policy.decision import bundle_hash
from tests.conftest import SCORER_CERT, SCORER_ID


@pytest.fixture
def files(tmp_path):
    yaml_file, rego = tmp_path / "policy.yaml", tmp_path / "policy.rego"
    yaml_file.write_text("policy_version: p1\n")
    rego.write_text("package attesta.policy\n")
    return yaml_file, rego


def client(backend, registry, policy, files):
    settings = GatewaySettings(policy_path=files[0], policy_rego_path=files[1])
    app = create_app(settings, backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    return TestClient(app)


def test_local_policy_without_a_chain(backend, registry, policy, files):
    body = client(backend, registry, policy, files).get("/policy").json()
    assert body["local"]["policy_version"] == "p1" and body["onchain"] is None and body["matches"] is False
    assert [b["name"] for b in body["local"]["bands"]] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert body["local"]["rego"] == "package attesta.policy\n"
    assert body["local"]["bundle_hash"] == bundle_hash(*files)
    assert "private" not in str(body).lower()


@pytest.mark.parametrize("pinned,version,expected", [("same", "p1", True), ("other", "p1", False), ("same", "p0", False), (None, "p1", False)])
def test_matches_only_when_hash_and_version_agree(backend, registry, policy, files, pinned, version, expected):
    local_hash = bundle_hash(*files)
    backend.active_policy = lambda: {"policy_version": version, "bands": [],
                                     "bundle_hash": {"same": local_hash, "other": "sha256:" + "ab" * 32, None: None}[pinned]}
    assert client(backend, registry, policy, files).get("/policy").json()["matches"] is expected


def test_an_unavailable_chain_is_reported_as_unknown_not_matching(backend, registry, policy, files):
    def down():
        raise LedgerUnavailableError("peer down")

    backend.active_policy = down
    body = client(backend, registry, policy, files).get("/policy").json()
    assert body["onchain"] is None and body["matches"] is False
