"""ScoringService end to end with a fake model, an offline registry and a fake gateway."""
import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.records.canonical import assert_no_floats
from attesta.records.signing import verify_record_signature
from attesta.scoring.errors import ArchiveError, ConfigError, FetchError, InvalidTarget, SubmitError
from attesta.scoring.builder import make_run_id
from attesta.scoring.service import DRY_RUN_CERT, ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.submit import GatewaySubmitter
from tests.conftest import SCORER_CERT, SCORER_ID
from tests.scoring.helpers import (
    FakeFetcher, FakeModel, FakeSubmitter, FixedAttestation, make_targz)

ARCHIVE = make_targz({"p-1.0/setup.py": "setup()", "p-1.0/p/__init__.py": "x", "p-1.0/p/network.py": "y"})


@pytest.fixture
def fetcher() -> FakeFetcher:
    f = FakeFetcher()
    f.add_pypi("example-package", "1.0.0", ARCHIVE)
    f.add_npm("@scope/pkg", "2.0.0", make_targz({"package/package.json": "{}", "package/index.js": "1"}))
    return f


@pytest.fixture
def make_service(fetcher, policy, scorer_key):
    def build(model=None, submitter="default", attested=True, **settings) -> ScoringService:
        return ScoringService(
            ScoringSettings(max_concurrent=2, result_cache_seconds=60, **settings), fetcher,
            model or FakeModel(), _Extractor(), policy, ScorerSigner("k1", scorer_key),
            FixedAttestation(attested), FakeSubmitter() if submitter == "default" else submitter)
    return build


class _Extractor:
    version = "fake"

    def extract(self, bundle):
        from attesta.scoring.model import ExtractorResult, FLAG_NAMES
        return ExtractorResult({n: False for n in FLAG_NAMES}, {n: () for n in FLAG_NAMES})


def test_record_is_valid_signed_and_float_free(make_service, registry):
    service = make_service()
    result = service.score("pypi", "example-package", "1.0.0", run_hint="123")
    record = result.record
    verify_record_signature(record, registry)          # Ed25519 signature checks out
    assert_no_floats(record.to_dict())
    assert record.risk_score == 120 and record.risk_band.value == "LOW" and record.decision.value == "ALLOW"
    assert record.flag_network and not record.flag_cred_access  # from the model's aux head
    assert record.submitted_by_spiffe_id == SCORER_ID and record.caller_cert_sha256 == SCORER_CERT
    assert record.model_version_hash == FakeModel.version_hash and record.policy_version == "p1"
    assert record.run_id.startswith("123-") and record.attestation_verified
    assert result.ledger and result.ledger["sequence"] == 1


def test_unverified_runner_attestation_downgrades_to_review(make_service):
    result = make_service(attested=False).score("pypi", "example-package", "1.0.0")
    assert result.record.decision.value == "REVIEW" and result.record.risk_band.value == "LOW"
    assert result.record.attestation_digest is None


def test_high_risk_is_blocked(make_service):
    assert make_service(model=FakeModel(risk=950)).score("npm", "@scope/pkg", "2.0.0").record.decision.value == "BLOCK"


def test_result_cache_avoids_refetch_and_resubmit(make_service, fetcher):
    submitter, model = FakeSubmitter(), FakeModel()
    service = make_service(model=model, submitter=submitter)
    first = service.score("pypi", "example-package", "1.0.0")
    fetched = len(fetcher.requests)
    second = service.score("pypi", "example-package", "1.0.0")
    assert second.cached and second.record.record_id == first.record.record_id
    assert len(fetcher.requests) == fetched and model.calls == 1 and len(submitter.records) == 1


def test_dry_run_signs_but_never_submits(make_service):
    submitter = FakeSubmitter()
    result = make_service(submitter=submitter).score("pypi", "example-package", "1.0.0", dry_run=True)
    assert result.ledger is None and not submitter.records
    assert result.record.caller_cert_sha256 == DRY_RUN_CERT


def test_certificate_rotation_race_is_retried_once(make_service):
    submitter = FakeSubmitter(mismatch_first=True)
    result = make_service(submitter=submitter).score("pypi", "example-package", "1.0.0")
    assert len(submitter.records) == 2 and result.ledger is not None


def test_other_submit_errors_are_not_retried(make_service):
    class Refusing(FakeSubmitter):
        def submit(self, record):
            self.records.append(record)
            raise SubmitError("gateway returned 409: duplicate run_id or record_id")

    submitter = Refusing()
    with pytest.raises(SubmitError):
        make_service(submitter=submitter).score("pypi", "example-package", "1.0.0")
    assert len(submitter.records) == 1


def test_errors_surface_before_any_submission(make_service, fetcher):
    submitter = FakeSubmitter()
    service = make_service(submitter=submitter)
    with pytest.raises(InvalidTarget):
        service.score("pypi", "../x", "1.0")
    with pytest.raises(FetchError):
        service.score("pypi", "missing", "9.9.9")
    fetcher.add_pypi("junk", "1.0", b"not an archive")
    with pytest.raises(ArchiveError):
        service.score("pypi", "junk", "1.0")
    assert not submitter.records


def test_run_ids_are_unique_and_pattern_safe():
    ids = {make_run_id("12 34/ab@c") for _ in range(50)}
    assert len(ids) == 50 and all(len(i) <= 128 and "/" not in i and " " not in i for i in ids)
    assert make_run_id("").startswith("adhoc-")


def test_signer_refuses_keys_inside_a_git_worktree(tmp_path, scorer_key, monkeypatch):
    # Hermetic: ignore any stray .git above the temp dir (e.g. in the user's home).
    from attesta.scoring import signer as signer_module
    original = signer_module.inside_git_worktree
    monkeypatch.setattr(signer_module, "inside_git_worktree",
                        lambda path: original(path, boundary=tmp_path))
    pem = scorer_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
    outside = tmp_path / "keys"
    outside.mkdir()
    (outside / "k.pem").write_bytes(pem)
    assert ScorerSigner.load(outside / "k.pem", "k1").key_id == "k1"

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "k.pem").write_bytes(pem)
    with pytest.raises(ConfigError, match="git work tree"):
        ScorerSigner.load(repo / "k.pem", "k1")
    assert ScorerSigner.load(repo / "k.pem", "k1", allow_in_repo=True)

    (outside / "bad.pem").write_text("not a key")
    with pytest.raises(ValueError):
        ScorerSigner.load(outside / "bad.pem", "k1")
    with pytest.raises(ConfigError, match="not found"):
        ScorerSigner.load(outside / "missing.pem", "k1")


def test_through_the_real_gateway_app(make_service, backend, registry, policy):
    """The record the service builds is accepted by the actual gateway (signature, policy, binding)."""
    app = create_app(GatewaySettings(), backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as client:
        class ClientAdapter:
            def request(self, method, path, body=None):
                response = client.request(method, path, json=body)
                return response.status_code, response.json()

        submitter = GatewaySubmitter(ClientAdapter(), lambda: SCORER_CERT)
        service = make_service(submitter=submitter)
        low = service.score("pypi", "example-package", "1.0.0")
        blocked = make_service(model=FakeModel(risk=950), submitter=submitter).score("npm", "@scope/pkg", "2.0.0")
        assert low.ledger["sequence"] == 1 and blocked.ledger["sequence"] == 2
        assert [r["record"]["decision"] for r in client.get("/records").json()] == ["ALLOW", "BLOCK"]
    assert backend.verify_chain().valid


def test_gateway_rejects_a_record_from_a_different_cert(make_service, backend, registry, policy):
    app = create_app(GatewaySettings(), backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, SCORER_CERT)
    with TestClient(app) as client:
        class ClientAdapter:
            def request(self, method, path, body=None):
                response = client.request(method, path, json=body)
                return response.status_code, response.json()

        wrong = GatewaySubmitter(ClientAdapter(), lambda: "cd" * 32)
        with pytest.raises(SubmitError, match="caller_cert_sha256"):
            make_service(submitter=wrong).score("pypi", "example-package", "1.0.0")
