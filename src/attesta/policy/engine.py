"""Score band -> decision policy, loaded from YAML (permille integers)."""
from pathlib import Path

import yaml
from pydantic import BaseModel, model_validator

from attesta.records.trust_record import Decision, RiskBand

# Decisions that are weakened by missing runner attestation. REVIEW and BLOCK
# are already at least as strict as REVIEW, so they are left unchanged.
_DOWNGRADED = {Decision.ALLOW, Decision.WARN}


class Band(BaseModel):
    name: RiskBand
    min_score: int
    max_score: int
    decision: Decision


class PolicyConfig(BaseModel):
    policy_version: str
    bands: list[Band]

    @model_validator(mode="after")
    def _bands_cover_range(self) -> "PolicyConfig":
        expected_min = 0
        for band in sorted(self.bands, key=lambda b: b.min_score):
            if band.min_score != expected_min or band.max_score < band.min_score:
                raise ValueError("policy bands must be contiguous, starting at 0")
            expected_min = band.max_score + 1
        if expected_min != 1001:
            raise ValueError("policy bands must end at 1000")
        return self


class PolicyResult(BaseModel):
    band: RiskBand
    decision: Decision
    policy_version: str
    downgraded: bool


def load_policy(path: Path) -> PolicyConfig:
    return PolicyConfig(**yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def band_for_score(policy: PolicyConfig, score: int) -> Band:
    for band in policy.bands:
        if band.min_score <= score <= band.max_score:
            return band
    raise ValueError(f"score out of range: {score}")


_RANK = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.REVIEW: 2, Decision.BLOCK: 3}


def stricter(a: Decision, b: Decision) -> Decision:
    return a if _RANK[a] >= _RANK[b] else b


def evaluate(policy: PolicyConfig, score: int, attestation_verified: bool,
             floor: Decision = Decision.ALLOW) -> PolicyResult:
    """Band decision, downgraded without attestation, then raised to `floor` (from the
    OPA evidence rules). A floor can only make the decision stricter."""
    band = band_for_score(policy, score)
    decision = band.decision
    downgraded = not attestation_verified and decision in _DOWNGRADED
    if downgraded:
        decision = Decision.REVIEW
    decision = stricter(decision, floor)
    return PolicyResult(
        band=band.name, decision=decision,
        policy_version=policy.policy_version, downgraded=downgraded,
    )
