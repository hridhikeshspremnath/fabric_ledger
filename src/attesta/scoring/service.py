"""Orchestration: validate -> download -> read in memory -> extract + model -> sign -> submit."""
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from attesta.policy.engine import PolicyConfig
from attesta.records.trust_record import TrustRecord
from attesta.scoring.attestation import AttestationProvider
from attesta.scoring.builder import BuildContext, build_record
from attesta.scoring.errors import SubmitError
from attesta.scoring.fetch import Fetcher
from attesta.scoring.model import FLAG_NAMES, LabelExtractor, ScoringModel
from attesta.scoring.registry import fetch_artifact
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.source import Limits, read_archive
from attesta.scoring.submit import Submitter
from attesta.scoring.validate import validate_target

DRY_RUN_CERT = "0" * 64  # placeholder: dry runs never contact the gateway


@dataclass(frozen=True)
class ScoreResult:
    record: TrustRecord
    ledger: Optional[dict[str, Any]]  # gateway LedgerEntry JSON, None for dry runs
    cached: bool = False

    def summary(self) -> dict[str, Any]:
        r = self.record
        out: dict[str, Any] = {
            "ecosystem": r.ecosystem, "package": r.package, "version": r.version,
            "artifact_digest": r.artifact_digest, "risk_score": r.risk_score,
            "risk_band": r.risk_band.value, "decision": r.decision.value,
            "flags": {name: getattr(r, name) for name in FLAG_NAMES},
            "record_id": r.record_id, "run_id": r.run_id, "policy_version": r.policy_version,
            "model_version_hash": r.model_version_hash,
            "attestation_verified": r.attestation_verified,
            "submitted": self.ledger is not None, "cached": self.cached,
        }
        if self.ledger:
            out["ledger"] = {k: self.ledger.get(k) for k in ("sequence", "tx_id", "block_number", "record_hash")}
        return out


class ScoringService:
    def __init__(self, settings: ScoringSettings, fetcher: Fetcher, model: ScoringModel,
                 extractors: LabelExtractor, policy: PolicyConfig, signer: ScorerSigner,
                 attestation: AttestationProvider, submitter: Optional[Submitter],
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._s, self._fetcher = settings, fetcher
        self._model, self._extractors = model, extractors
        self._attestation, self._submitter, self._clock = attestation, submitter, clock
        self._ctx = BuildContext(
            policy=policy, signer=signer, scoring_spiffe_id=settings.scoring_spiffe_id,
            model_version_hash=model.version_hash, runner_class=settings.runner_class,
            node_attestor=settings.node_attestor, aux_threshold=settings.aux_threshold_permille)
        self._limits = Limits(settings.max_files, settings.max_file_bytes,
                              settings.max_scanned_bytes, settings.max_uncompressed_bytes)
        self._slots = threading.BoundedSemaphore(settings.max_concurrent)
        self._cache: dict[tuple[str, ...], tuple[float, ScoreResult]] = {}
        self._lock = threading.Lock()

    def _cache_key(self, label: str) -> tuple[str, ...]:
        return (label, self._ctx.model_version_hash, self._ctx.policy.policy_version)

    def _cached(self, key: tuple[str, ...]) -> Optional[ScoreResult]:
        with self._lock:
            hit = self._cache.get(key)
        if hit and self._clock() - hit[0] < self._s.result_cache_seconds:
            return ScoreResult(hit[1].record, hit[1].ledger, cached=True)
        return None

    def score(self, ecosystem: str, package: str, version: str, run_hint: str = "",
              dry_run: bool = False) -> ScoreResult:
        target = validate_target(ecosystem, package, version)
        key = self._cache_key(target.label())
        if not dry_run and (hit := self._cached(key)):
            return hit
        with self._slots:
            artifact = fetch_artifact(self._fetcher, target, self._s.max_download_bytes)
            bundle = read_archive(artifact.data, artifact.filename, self._limits)
            bundle.data, bundle.ecosystem = artifact.data, target.ecosystem
            bundle.package, bundle.version = target.package, target.version
            extracted = self._extractors.extract(bundle)
            output = self._model.predict(bundle)
            result = self._sign_and_submit(target, artifact, bundle, extracted, output, run_hint, dry_run)
        if not dry_run:
            with self._lock:
                self._cache[key] = (self._clock(), result)
        return result

    def _sign_and_submit(self, target, artifact, bundle, extracted, output, run_hint, dry_run):  # type: ignore[no-untyped-def]
        attestation = self._attestation.get()
        if dry_run or self._submitter is None:
            record = build_record(self._ctx, target, artifact, bundle, extracted, output,
                                  attestation, DRY_RUN_CERT, run_hint)
            return ScoreResult(record, None)
        last_error: Optional[SubmitError] = None
        for _ in range(2):  # one retry: the SVID may rotate between signing and connecting
            record = build_record(self._ctx, target, artifact, bundle, extracted, output,
                                  attestation, self._submitter.cert_sha256(), run_hint)
            try:
                return ScoreResult(record, self._submitter.submit(record))
            except SubmitError as exc:
                last_error = exc
                if "caller_cert_sha256" not in str(exc):
                    break
        raise last_error  # type: ignore[misc]
