import json

import pytest
from fastapi.testclient import TestClient

from attesta.scoring import cli
from attesta.scoring.api import create_api
from attesta.scoring.errors import ConfigError, FetchError
from tests.scoring.helpers import FakeFetcher, FakeModel, FakeSubmitter, FixedAttestation, make_targz
from tests.scoring.test_service import _Extractor
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner

TOKEN = "s3cret-token"


@pytest.fixture
def service(policy, scorer_key):
    fetcher = FakeFetcher()
    fetcher.add_pypi("example-package", "1.0.0", make_targz({"p/setup.py": "x"}))
    return ScoringService(ScoringSettings(), fetcher, FakeModel(), _Extractor(), policy,
                          ScorerSigner("k1", scorer_key), FixedAttestation(True), FakeSubmitter())


def test_api_requires_the_bearer_token(service):
    client = TestClient(create_api(service, TOKEN))
    body = {"ecosystem": "pypi", "package": "example-package", "version": "1.0.0"}
    assert client.post("/v1/score", json=body).status_code == 401
    assert client.post("/v1/score", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/healthz").status_code == 200


def test_api_scores_and_maps_errors(service):
    client = TestClient(create_api(service, TOKEN))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    ok = client.post("/v1/score", headers=auth, json={
        "ecosystem": "pypi", "package": "example-package", "version": "1.0.0", "run_id": "42"})
    assert ok.status_code == 200
    data = ok.json()
    assert data["decision"] == "ALLOW" and data["submitted"] and data["flags"]["flag_install_exec"] is False
    assert client.post("/v1/score", headers=auth, json={
        "ecosystem": "pypi", "package": "../x", "version": "1"}).status_code == 422
    assert client.post("/v1/score", headers=auth, json={
        "ecosystem": "pypi", "package": "ghost", "version": "1.0"}).status_code == 502


def test_api_refuses_to_start_without_a_token(service):
    with pytest.raises(ConfigError):
        create_api(service, "")


def test_cli_score_prints_summary_and_fail_on_exit_code(service, monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_service", lambda settings, dry_run_only=False: service)
    monkeypatch.setattr(cli, "load_scoring_settings", lambda path=None: ScoringSettings())
    assert cli.main(["score", "pypi", "example-package", "1.0.0"]) == 0
    assert "decision=ALLOW" in capsys.readouterr().out
    assert cli.main(["score", "pypi", "example-package", "1.0.0", "--json", "--fail-on", "ALLOW"]) == cli.EXIT_THRESHOLD
    assert json.loads(capsys.readouterr().out)["decision"] == "ALLOW"


def test_cli_reports_errors_with_exit_1(service, monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_service", lambda settings, dry_run_only=False: service)
    monkeypatch.setattr(cli, "load_scoring_settings", lambda path=None: ScoringSettings())
    assert cli.main(["score", "pypi", "ghost", "9.9"]) == 1
    assert "ERROR" in capsys.readouterr().err
    assert FetchError  # imported for clarity of the failure type
