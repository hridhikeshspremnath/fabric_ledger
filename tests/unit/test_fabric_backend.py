"""FabricBackend against an in-memory fake of the Go bridge's JSON API."""
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from attesta.backends.base import (
    DuplicateRecordError, LedgerRejectedError, LedgerUnavailableError, RecordNotFoundError)
from attesta.backends.fabric import FabricBackend, record_hash
from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from tests.conftest import SCORER_CERT, SCORER_ID


class FakeBridge:
    """Mimics bridge/server.go responses (shapes taken from the Go handlers)."""

    def __init__(self) -> None:
        self.views: list[dict[str, Any]] = []
        self.runs: set[str] = set()
        self.force: Optional[tuple[int, Any]] = None
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, body: Optional[dict[str, Any]] = None):
        self.calls.append((method, path))
        if self.force:
            return self.force
        url = urlsplit(path)
        query = parse_qs(url.query)
        if method == "POST" and url.path == "/v1/records":
            assert body is not None
            if body["run_id"] in self.runs:
                return 409, {"error": f"duplicate run_id: {body['run_id']}"}
            self.runs.add(body["run_id"])
            n = len(self.views) + 1
            meta = {"tx_id": f"tx{n}", "tx_time": 1_700_000_000 + n, "submitted_msp": "AttestaMSP",
                    "effective_decision": body["decision"]}
            self.views.append({"record": body, "meta": meta})
            return 201, {"tx_id": meta["tx_id"], "block_number": n + 4, "result": {
                "record_id": body["record_id"], "run_id": body["run_id"], "decision": body["decision"],
                "tx_id": meta["tx_id"], "tx_time": meta["tx_time"]}}
        if method == "GET" and url.path.startswith("/v1/records/"):
            rid = url.path.rsplit("/", 1)[1]
            for view in self.views:
                if view["record"]["record_id"] == rid:
                    return 200, view
            return 404, {"error": f"record not found: {rid}"}
        if method == "GET" and url.path == "/v1/records":
            start = int(query.get("cursor", ["0"])[0])
            limit = int(query["limit"][0])
            items = self.views[start:start + limit]
            more = start + limit < len(self.views)
            return 200, {"items": items, "next_cursor": str(start + limit) if more else ""}
        if method == "GET" and url.path.startswith("/v1/proof/"):
            rid = url.path.rsplit("/", 1)[1]
            for view in self.views:
                if view["record"]["record_id"] == rid:
                    return 200, {"record_id": rid, "proof": {
                        "tx_id": view["meta"]["tx_id"], "block_number": 9, "block_hash": "aa" * 32,
                        "previous_block_hash": "bb" * 32, "data_hash": "cc" * 32,
                        "validation_code": "VALID", "chain_height": 10, "chain_tip_hash": "dd" * 32}}
            return 404, {"error": "record not found"}
        if method == "GET" and url.path == "/v1/checkpoint":
            return 200, {"channel": "attesta-ch", "height": 10, "current_block_hash": "dd" * 32,
                         "previous_block_hash": "bb" * 32}
        return 404, {"error": "no route"}


@pytest.fixture
def bridge() -> FakeBridge:
    return FakeBridge()


@pytest.fixture
def fabric(bridge: FakeBridge) -> FabricBackend:
    return FabricBackend(bridge)


def test_append_maps_bridge_response(fabric, signed):
    record = signed()
    entry = fabric.append(record)
    assert entry.tx_id == "tx1" and entry.block_number == 5 and entry.timestamp == 1_700_000_001
    assert entry.record_hash == record_hash(record)
    assert entry.sequence is None and entry.previous_record_hash is None
    assert entry.effective_decision == "ALLOW"


def test_bridge_errors_map_to_backend_errors(fabric, bridge, signed):
    fabric.append(signed(run_id="same"))
    with pytest.raises(DuplicateRecordError):
        fabric.append(signed(run_id="same"))
    for status, exc in [(422, LedgerRejectedError), (400, LedgerRejectedError),
                        (503, LedgerUnavailableError), (502, LedgerUnavailableError),
                        (500, LedgerUnavailableError)]:
        bridge.force = (status, {"error": "x"})
        with pytest.raises(exc):
            fabric.append(signed())


def test_get_returns_record_meta_and_overrides(fabric, bridge, signed):
    record = signed()
    fabric.append(record)
    bridge.views[0]["meta"]["effective_decision"] = "BLOCK"
    bridge.views[0]["overrides"] = [{"decision": "BLOCK", "reason": "malware", "by_msp": "AuditorMSP"}]
    entry = fabric.get(record.record_id)
    assert entry is not None and entry.record == record
    assert entry.effective_decision == "BLOCK" and entry.overrides[0]["reason"] == "malware"
    assert fabric.get("00000000-0000-4000-8000-000000000000") is None


def test_list_page_follows_cursor(fabric, signed):
    for _ in range(3):
        fabric.append(signed())
    first = fabric.list_page(limit=2)
    assert len(first.entries) == 2 and first.next_cursor == "2"
    second = fabric.list_page(limit=2, cursor=first.next_cursor)
    assert len(second.entries) == 1 and second.next_cursor == ""


def test_proof_and_checkpoint_are_fabric_flavoured(fabric, signed):
    record = signed()
    fabric.append(record)
    proof = fabric.proof(record.record_id)
    assert proof.kind == "fabric" and proof.block_number == 9 and proof.validation_code == "VALID"
    checkpoint = fabric.checkpoint()
    assert checkpoint.kind == "fabric" and checkpoint.height == 10
    with pytest.raises(RecordNotFoundError):
        fabric.proof("00000000-0000-4000-8000-000000000000")


# ---- through the gateway API ------------------------------------------------

@pytest.fixture
def client(fabric, registry, policy):
    app = create_app(GatewaySettings(), fabric, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as c:
        yield c


def test_gateway_over_fabric_backend(client, signed, bridge):
    records = [signed() for _ in range(3)]
    for record in records:
        response = client.post("/records", json=record.to_dict())
        assert response.status_code == 201 and response.json()["tx_id"].startswith("tx")
    assert client.post("/records", json=signed(run_id=records[0].run_id).to_dict()).status_code == 409

    page = client.get("/records?limit=2")
    assert len(page.json()) == 2 and page.headers["X-Next-Cursor"] == "2"
    rest = client.get("/records", params={"limit": 2, "cursor": page.headers["X-Next-Cursor"]})
    assert len(rest.json()) == 1 and rest.headers["X-Next-Cursor"] == ""

    assert client.get(f"/records/{records[0].record_id}").json()["tx_id"] == "tx1"
    assert client.get("/proof/" + records[0].record_id).json()["kind"] == "fabric"
    assert client.get("/checkpoint").json()["kind"] == "fabric"


def test_gateway_maps_ledger_failures(client, signed, bridge):
    bridge.force = (503, {"error": "peer down"})
    assert client.post("/records", json=signed().to_dict()).status_code == 503
    bridge.force = (422, {"error": "chaincode said no"})
    assert client.post("/records", json=signed().to_dict()).status_code == 422
    bridge.force = None
    assert client.get("/records/00000000-0000-4000-8000-000000000000").status_code == 404
