"""Build and sign a TrustRecord from a scored package. Integers only."""
import re
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from attesta.policy.engine import PolicyConfig, evaluate
from attesta.policy.opa import Floor
from attesta.scoring.llm import Review
from attesta.records.canonical import canonical_bytes, sha256_hex
from attesta.records.trust_record import Decision, TrustRecord
from attesta.scoring.attestation import Attestation
from attesta.scoring.model import FLAG_NAMES, ExtractorResult, ModelOutput
from attesta.scoring.registry import Artifact
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.source import SourceBundle
from attesta.scoring.validate import Target

_BAD_ID_CHARS = re.compile(r"[^A-Za-z0-9._:-]")


def make_run_id(hint: str) -> str:
    """Unique run_id: sanitised CI hint plus a random suffix (matches the ID pattern, <=128)."""
    prefix = _BAD_ID_CHARS.sub("_", hint)[:100] or "adhoc"
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def combine_flags(extracted: ExtractorResult, output: ModelOutput, threshold: int) -> dict[str, bool]:
    """A flag is set if the extractor labelled it OR its aux head is at/above the threshold."""
    return {name: bool(extracted.flags[name]) or output.aux_permille[name] >= threshold
            for name in FLAG_NAMES}


def evidence_hash(target: Target, artifact: Artifact, bundle: SourceBundle,
                  extracted: ExtractorResult, output: ModelOutput) -> str:
    evidence: dict[str, Any] = {
        "target": target.label(), "artifact_file": artifact.filename,
        "artifact_sha256": artifact.sha256_hex, "entries": bundle.total_entries,
        "scanned_files": bundle.scanned_files, "scanned_bytes": bundle.scanned_bytes,
        "truncated": bundle.truncated, "risk_permille": output.risk_permille,
        "aux_permille": dict(output.aux_permille),
        "extractor_hits": {k: list(v) for k, v in extracted.hits.items()},
    }
    return "sha256:" + sha256_hex(canonical_bytes(evidence))


@dataclass(frozen=True)
class BuildContext:
    policy: PolicyConfig
    signer: ScorerSigner
    scoring_spiffe_id: str
    model_version_hash: str
    runner_class: str
    node_attestor: str
    aux_threshold: int
    floor: Optional[Floor] = None  # OPA evidence floor; None = bands only


def build_record(ctx: BuildContext, target: Target, artifact: Artifact, bundle: SourceBundle,
                 extracted: ExtractorResult, output: ModelOutput, attestation: Attestation,
                 cert_sha256: str, run_hint: str = "", review: Optional[Review] = None) -> TrustRecord:
    flags = combine_flags(extracted, output, ctx.aux_threshold)
    verdict = review.verdict.value if review else "NOT_RUN"
    floor = Decision.ALLOW
    if ctx.floor is not None:  # raises OpaUnavailable: never score without the rules
        floor = ctx.floor({**flags, "llm_verdict": verdict})
    result = evaluate(ctx.policy, output.risk_permille, attestation.verified, floor)
    fields: dict[str, Any] = {
        "record_id": str(uuid.uuid4()), "run_id": make_run_id(run_hint),
        "submitted_by_spiffe_id": ctx.scoring_spiffe_id, "caller_cert_sha256": cert_sha256,
        "ecosystem": target.ecosystem, "package": target.package, "version": target.version,
        "artifact_digest": "sha256:" + artifact.sha256_hex,
        "risk_score": output.risk_permille, "risk_band": result.band.value,
        **flags,
        "llm_verdict": verdict, "llm_evidence_hash": review.evidence_hash if review else None,
        "model_version_hash": ctx.model_version_hash, "policy_version": result.policy_version,
        "runner_class": attestation.runner_class or ctx.runner_class,
        "node_attestor": attestation.node_attestor or ctx.node_attestor,
        "attestation_verified": attestation.verified,
        "attestation_digest": attestation.digest if attestation.verified else None,
        "decision": result.decision.value,
        "evidence_hash": evidence_hash(target, artifact, bundle, extracted, output),
    }
    return ctx.signer.sign(fields)
