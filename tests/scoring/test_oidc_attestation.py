"""GitHub OIDC runner attestation, with a throwaway RSA key standing in for GitHub's."""
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from attesta.scoring.api import create_api
from attesta.scoring.attestation import GITHUB_ISSUER, GithubOidcAttestation
from attesta.scoring.errors import AttestationRejected, ConfigError, FetchError
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from tests.scoring.helpers import FakeFetcher, FakeModel, FakeSubmitter, make_targz
from tests.scoring.test_service import _Extractor

AUDIENCE, REPO = "attesta", "acme/app"
KID = "key-1"


def _pair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(*pairs):
    keys = []
    for kid, key in pairs:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": keys}


class JwksFetcher:
    def __init__(self, *pairs):
        self.jwks, self.calls = _jwks(*pairs), 0

    def get_json(self, url):
        self.calls += 1
        if self.jwks is None:
            raise FetchError("HTTP 503")
        return self.jwks

    def get_bytes(self, url, max_bytes):
        raise AssertionError("not used")


@pytest.fixture
def github_key():
    return _pair()


def token(key, kid=KID, alg="RS256", **overrides):
    now = int(time.time())
    claims = {"iss": GITHUB_ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 300,
              "repository": REPO, "repository_owner": "acme", "ref": "refs/heads/main",
              "sha": "a" * 40, "workflow": "ci", "run_id": "42", "run_attempt": "1",
              "runner_environment": "github-hosted", "event_name": "push",
              "actor": "someone"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def provider(github_key, **kw):
    return GithubOidcAttestation(JwksFetcher((KID, github_key)), AUDIENCE, frozenset({REPO}), **kw)


def test_valid_token_is_verified_and_digest_excludes_personal_fields(github_key):
    att = provider(github_key).get(token(github_key))
    assert att.verified and att.node_attestor == "github-oidc" and att.runner_class == "github-hosted"
    assert att.digest.startswith("sha256:") and len(att.digest) == 71
    assert att.digest == provider(github_key).get(token(github_key, actor="someone-else")).digest


def test_no_token_is_unattested_not_an_error(github_key):
    att = provider(github_key).get(None)
    assert not att.verified and att.digest is None
    assert not provider(github_key).get("").verified


@pytest.mark.parametrize("what,make", [
    ("wrong repository", lambda k: token(k, repository="evil/app")),
    ("wrong audience", lambda k: token(k, aud="someone-else")),
    ("wrong issuer", lambda k: token(k, iss="https://evil.example")),
    ("expired", lambda k: token(k, iat=int(time.time()) - 900, exp=int(time.time()) - 600)),
    ("no expiry", lambda k: token(k, exp=None)),
    ("unknown key id", lambda k: token(k, kid="other")),
    ("signed by another key", lambda k: token(_pair())),
    ("garbage", lambda k: "not.a.jwt"),
])
def test_bad_tokens_are_rejected(github_key, what, make):
    with pytest.raises(AttestationRejected):
        provider(github_key).get(make(github_key))


def test_algorithm_confusion_is_rejected(github_key):
    forged = jwt.encode({"iss": GITHUB_ISSUER, "aud": AUDIENCE, "repository": REPO,
                         "exp": int(time.time()) + 300, "iat": int(time.time())},
                        "secret-the-attacker-chose-that-is-long-enough-for-hs256", algorithm="HS256",
                        headers={"kid": KID})
    with pytest.raises(AttestationRejected):
        provider(github_key).get(forged)
    unsigned = jwt.encode({"repository": REPO}, key=None, algorithm="none", headers={"kid": KID})
    with pytest.raises(AttestationRejected):
        provider(github_key).get(unsigned)


def test_key_rotation_refetches_once_per_gap(github_key):
    clock = [0.0]
    fetcher = JwksFetcher((KID, github_key))
    att = GithubOidcAttestation(fetcher, AUDIENCE, frozenset({REPO}), clock=lambda: clock[0],
                                refresh_gap=60)
    att.get(token(github_key))
    assert fetcher.calls == 1
    new = _pair()
    fetcher.jwks = _jwks((KID, github_key), ("key-2", new))
    with pytest.raises(AttestationRejected):             # too soon: no refetch, key unknown
        att.get(token(new, kid="key-2"))
    assert fetcher.calls == 1
    clock[0] = 61
    assert att.get(token(new, kid="key-2")).verified      # gap passed: refetched, rotation works
    assert fetcher.calls == 2


def test_key_fetch_failure_rejects_rather_than_trusting(github_key):
    fetcher = JwksFetcher((KID, github_key))
    fetcher.jwks = None
    with pytest.raises(AttestationRejected):
        GithubOidcAttestation(fetcher, AUDIENCE, frozenset({REPO})).get(token(github_key))


def test_empty_allow_list_is_a_config_error(github_key):
    with pytest.raises(ConfigError):
        GithubOidcAttestation(JwksFetcher(), AUDIENCE, frozenset())


@pytest.fixture
def service(policy, scorer_key, github_key):
    fetcher = FakeFetcher()
    fetcher.add_pypi("example-package", "1.0.0", make_targz({"p/setup.py": "x"}))
    submitter = FakeSubmitter()
    svc = ScoringService(ScoringSettings(), fetcher, FakeModel(risk=100), _Extractor(), policy,
                         ScorerSigner("k1", scorer_key), provider(github_key), submitter)
    return svc, submitter


def test_verified_token_lets_a_low_score_be_allowed(service, github_key):
    svc, submitter = service
    attested = svc.score("pypi", "example-package", "1.0.0", dry_run=True,
                         attestation_token=token(github_key))
    plain = svc.score("pypi", "example-package", "1.0.0", dry_run=True)
    r = attested.record
    assert r.attestation_verified and r.decision.value == "ALLOW"
    assert r.node_attestor == "github-oidc" and r.runner_class == "github-hosted"
    assert r.attestation_digest and "someone" not in r.attestation_digest
    assert not plain.record.attestation_verified and plain.record.decision.value == "REVIEW"


def test_cache_never_crosses_attested_and_unattested(service, github_key):
    svc, _ = service
    first = svc.score("pypi", "example-package", "1.0.0")                       # unattested, submitted
    second = svc.score("pypi", "example-package", "1.0.0", run_hint="x",
                       attestation_token=token(github_key))                      # must not reuse it
    assert not second.cached and second.record.decision.value == "ALLOW"
    assert first.record.decision.value == "REVIEW"


def test_api_maps_a_bad_token_to_401_and_forwards_a_good_one(service, github_key):
    svc, _ = service
    client = TestClient(create_api(svc, "tok"))
    auth = {"Authorization": "Bearer tok"}
    body = {"ecosystem": "pypi", "package": "example-package", "version": "1.0.0", "dry_run": True}
    bad = client.post("/v1/score", json=body, headers={**auth, "X-Attesta-OIDC": token(github_key, repository="evil/x")})
    assert bad.status_code == 401
    good = client.post("/v1/score", json=body, headers={**auth, "X-Attesta-OIDC": token(github_key)})
    assert good.status_code == 200 and good.json()["decision"] == "ALLOW" and good.json()["attestation_verified"]
