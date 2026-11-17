"""CI side of runner attestation: asking GitHub for the job's OIDC token."""
import io
import json

from attesta.ci import scan


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_no_token_without_id_token_permission(monkeypatch):
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    assert scan.fetch_oidc_token("attesta") == ""


def test_requests_the_token_for_the_audience(monkeypatch):
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.example/token?api-version=2")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-secret")
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"], seen["auth"] = request.full_url, request.get_header("Authorization")
        return _Response(json.dumps({"value": "jwt-from-github"}).encode())

    monkeypatch.setattr(scan.urllib.request, "urlopen", fake_urlopen)
    assert scan.fetch_oidc_token("my aud") == "jwt-from-github"
    assert seen["url"] == "https://pipelines.example/token?api-version=2&audience=my%20aud"
    assert seen["auth"] == "Bearer runtime-secret"


def test_failure_falls_back_to_unattested(monkeypatch):
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.example/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")

    def boom(request, timeout):
        raise OSError("network down")

    monkeypatch.setattr(scan.urllib.request, "urlopen", boom)
    assert scan.fetch_oidc_token("attesta") == ""
