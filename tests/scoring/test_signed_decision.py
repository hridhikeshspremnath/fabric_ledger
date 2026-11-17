"""The scoring service takes its decision from the policy service when one is configured."""
import pytest

from attesta.policy.decision import PolicyUnavailable
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from tests.scoring.helpers import FakeFetcher, FakeModel, FakeSubmitter, FixedAttestation, make_targz
from tests.scoring.test_service import _Extractor
from tests.conftest import sha


def service(policy, scorer_key, decide, risk=100):
    fetcher = FakeFetcher()
    fetcher.add_pypi("example-package", "1.0.0", make_targz({"p/setup.py": "x"}))
    submitter = FakeSubmitter()
    return ScoringService(ScoringSettings(), fetcher, FakeModel(risk=risk), _Extractor(), policy,
                          ScorerSigner("k1", scorer_key), FixedAttestation(True), submitter, decide=decide), submitter


def test_record_carries_the_policy_services_decision_and_signature(policy, scorer_key):
    seen = {}

    def decide(evidence):
        seen.update(evidence)
        return {"decision": "REVIEW", "risk_band": "LOW", "policy_version": "p1", "policy_bundle_hash": sha("b"),
                "decision_key_id": "d1", "decision_signature": "A" * 86 + "=="}

    svc, submitter = service(policy, scorer_key, decide)
    record = svc.score("pypi", "example-package", "1.0.0").record
    # The service's decision wins over what the bands alone would give (ALLOW at score 100).
    assert record.decision.value == "REVIEW" and record.policy_bundle_hash == sha("b")
    assert record.decision_key_id == "d1" and record.decision_signature == "A" * 86 + "=="
    assert submitter.records == [record]
    # It asked about this very record and artifact, and sent evidence only (no keys, no signatures).
    assert seen["record_id"] == record.record_id and seen["artifact_digest"] == record.artifact_digest
    assert not {"scorer_signature", "caller_cert_sha256", "decision"} & set(seen)


def test_without_a_policy_service_records_are_decided_locally_and_unsigned(policy, scorer_key):
    svc, _ = service(policy, scorer_key, decide=None)
    record = svc.score("pypi", "example-package", "1.0.0").record
    assert record.decision.value == "ALLOW" and record.decision_signature is None


def test_an_unreachable_policy_service_fails_the_scan_and_submits_nothing(policy, scorer_key):
    def down(_evidence):
        raise PolicyUnavailable("connection refused")

    svc, submitter = service(policy, scorer_key, down)
    with pytest.raises(PolicyUnavailable):
        svc.score("pypi", "example-package", "1.0.0")
    assert submitter.records == []
