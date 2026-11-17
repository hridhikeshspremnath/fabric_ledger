"""Evidence floors: engine arithmetic, gateway enforcement, fail-strict behaviour, OPA client."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest
from fastapi.testclient import TestClient

from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.policy.engine import evaluate
from attesta.policy.opa import EVIDENCE, OpaUnavailable, opa_floor
from attesta.records.trust_record import Decision
from tests.conftest import SCORER_CERT, SCORER_ID


@pytest.mark.parametrize("score,verified,floor,expected", [
    (100, True, Decision.ALLOW, Decision.ALLOW),
    (100, True, Decision.REVIEW, Decision.REVIEW),   # floor raises a LOW band
    (100, True, Decision.BLOCK, Decision.BLOCK),
    (950, True, Decision.ALLOW, Decision.BLOCK),     # a floor never lowers a band
    (950, True, Decision.REVIEW, Decision.BLOCK),
    (100, False, Decision.ALLOW, Decision.REVIEW),   # attestation downgrade still applies
    (100, False, Decision.BLOCK, Decision.BLOCK),
])
def test_floor_only_makes_decisions_stricter(policy, score, verified, floor, expected):
    assert evaluate(policy, score, verified, floor).decision == expected


def client_with(backend, registry, policy, floor):
    app = create_app(GatewaySettings(), backend, registry, policy, floor=floor)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    return TestClient(app)


def test_gateway_enforces_the_floor(backend, registry, policy, signed):
    seen = []

    def floor(fields):
        seen.append(set(fields))
        return Decision.BLOCK if fields["flag_cred_access"] else Decision.ALLOW

    with client_with(backend, registry, policy, floor) as client:
        flagged = signed(flag_cred_access=True)  # LOW band score
        weak = client.post("/records", json=flagged.to_dict())
        assert weak.status_code == 422                       # ALLOW is weaker than the floor
        strict = signed(flag_cred_access=True, decision="BLOCK")
        assert client.post("/records", json=strict.to_dict()).status_code == 201
        assert client.post("/records", json=signed().to_dict()).status_code == 201
    assert seen and all(s == set(EVIDENCE) for s in seen)    # only evidence fields reach OPA


def test_gateway_fails_strict_when_opa_is_down(backend, registry, policy, signed):
    def down(_fields):
        raise OpaUnavailable("connection refused")

    with client_with(backend, registry, policy, down) as client:
        assert client.post("/records", json=signed().to_dict()).status_code == 503
    assert backend.list() == []


class _Opa(BaseHTTPRequestHandler):
    status, reply = 200, {"result": "REVIEW"}
    last_input: dict = {}

    def do_POST(self):
        type(self).last_input = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(json.dumps(type(self).reply).encode())

    def log_message(self, *_):
        pass


@pytest.fixture
def opa_url():
    server = HTTPServer(("127.0.0.1", 0), _Opa)
    Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


EVIDENCE_FIELDS = {"flag_install_exec": False, "flag_network": True, "flag_obfuscation": False,
                   "flag_cred_access": False, "flag_process_spawn": False,
                   "llm_verdict": "NOT_RUN", "scorer_signature": "secret"}


def test_opa_client_sends_only_evidence_and_parses_the_floor(opa_url):
    _Opa.status, _Opa.reply = 200, {"result": "REVIEW"}
    assert opa_floor(opa_url)(EVIDENCE_FIELDS) == Decision.REVIEW
    assert set(_Opa.last_input["input"]) == set(EVIDENCE)


@pytest.mark.parametrize("status,reply", [(500, {}), (200, {}), (200, {"result": "MAYBE"})])
def test_opa_client_rejects_unusable_answers(opa_url, status, reply):
    _Opa.status, _Opa.reply = status, reply
    with pytest.raises(OpaUnavailable):
        opa_floor(opa_url)(EVIDENCE_FIELDS)


def test_opa_client_reports_an_unreachable_server():
    with pytest.raises(OpaUnavailable):
        opa_floor("http://127.0.0.1:1")(EVIDENCE_FIELDS)
