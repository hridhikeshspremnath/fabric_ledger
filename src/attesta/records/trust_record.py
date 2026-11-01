"""TrustRecord v1: the signed scoring result the gateway appends to the ledger.

All numbers are integers (risk_score is permille, 0-1000). The scorer signs
`signing_payload()`: canonical JSON of every field except `scorer_signature`.
"""
from enum import Enum
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StringConstraints, model_validator

from attesta.records.canonical import canonical_bytes

SHA256_RE = r"^sha256:[0-9a-f]{64}$"
NAME_RE = r"^[A-Za-z0-9._@/+:-]{1,214}$"
ID_RE = r"^[A-Za-z0-9._:-]{1,128}$"
SPIFFE_RE = r"^spiffe://[a-z0-9.-]+/[A-Za-z0-9._/-]+$"
UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
SIG_RE = r"^[A-Za-z0-9+/]{86}==$"  # base64 of a 64-byte Ed25519 signature


def _s(pattern: str) -> Any:
    return Annotated[str, StringConstraints(pattern=pattern, strict=True)]


Sha256 = _s(SHA256_RE)
Name = _s(NAME_RE)
Ident = _s(ID_RE)
SpiffeId = _s(SPIFFE_RE)
Uuid = _s(UUID_RE)
Signature = _s(SIG_RE)
Ecosystem = _s(r"^[a-z0-9-]{1,32}$")
CertFingerprint = _s(r"^[0-9a-f]{64}$")


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class LlmVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NOT_RUN = "NOT_RUN"


class TrustRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    record_id: Uuid
    run_id: Ident
    submitted_by_spiffe_id: SpiffeId
    caller_cert_sha256: CertFingerprint
    ecosystem: Ecosystem
    package: Name
    version: Name
    artifact_digest: Sha256
    risk_score: StrictInt  # permille, 0..1000 (checked below)
    risk_band: RiskBand
    flag_install_exec: StrictBool
    flag_network: StrictBool
    flag_obfuscation: StrictBool
    flag_cred_access: StrictBool
    flag_process_spawn: StrictBool
    llm_verdict: LlmVerdict
    llm_evidence_hash: Optional[Sha256] = None
    model_version_hash: Sha256
    policy_version: Ident
    runner_class: Ident
    node_attestor: Ident
    attestation_verified: StrictBool
    attestation_digest: Optional[Sha256] = None
    decision: Decision
    evidence_hash: Sha256
    scorer_key_id: Ident
    scorer_signature: Signature

    @model_validator(mode="after")
    def _check_ranges(self) -> "TrustRecord":
        if not 0 <= self.risk_score <= 1000:
            raise ValueError("risk_score must be an integer in 0..1000 (permille)")
        if self.attestation_verified and self.attestation_digest is None:
            raise ValueError("attestation_digest is required when attestation_verified is true")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def signing_payload(self) -> bytes:
        body = self.to_dict()
        del body["scorer_signature"]
        return canonical_bytes(body)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())
