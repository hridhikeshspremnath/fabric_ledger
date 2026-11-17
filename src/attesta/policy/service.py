"""Policy decision service: evidence in, signed decision out.

    python -m attesta.policy.service      (env: ATTESTA_POLICY_PATH, ATTESTA_POLICY_REGO_PATH,
                                           ATTESTA_DECISION_KEY_PATH, ATTESTA_DECISION_KEY_ID,
                                           ATTESTA_OPA_URL, ATTESTA_POLICY_SERVICE_PORT)

It runs the score bands and the OPA evidence floors, computes the decision, and signs it with a
key the scorer does not hold. It decides only for the evidence it is given: it cannot know the
scorer lied about the evidence, so a compromised scorer still needs its own key to get a record
accepted, and the signed decision pins the policy bundle that produced it.
Plain HTTP on the compose network only, like OPA. shortcut: no caller authentication; put it
behind SPIFFE mTLS before it leaves a single trusted network.
"""
import os
from pathlib import Path
from typing import Any, Mapping

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt

from attesta.policy.decision import bundle_hash, sign_decision
from attesta.policy.engine import PolicyConfig, evaluate, load_policy
from attesta.policy.opa import Floor, OpaUnavailable, opa_floor
from attesta.records.trust_record import LlmVerdict, Sha256, Uuid


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: Uuid
    artifact_digest: Sha256
    risk_score: StrictInt
    attestation_verified: StrictBool
    flag_install_exec: StrictBool
    flag_network: StrictBool
    flag_obfuscation: StrictBool
    flag_cred_access: StrictBool
    flag_process_spawn: StrictBool
    llm_verdict: LlmVerdict


def create_decision_app(policy: PolicyConfig, floor: Floor, key: Ed25519PrivateKey, key_id: str,
                        bundle: str) -> FastAPI:
    app = FastAPI(title="Attesta policy service")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "policy_version": policy.policy_version, "policy_bundle_hash": bundle}

    @app.post("/v1/decide")
    def decide(evidence: Evidence) -> dict[str, Any]:
        if not 0 <= evidence.risk_score <= 1000:
            raise HTTPException(status_code=422, detail="risk_score must be in 0..1000")
        try:
            decision_floor = floor(evidence.model_dump())
        except OpaUnavailable as exc:  # fail strict: no rules, no signed decision
            raise HTTPException(status_code=503, detail="policy engine unavailable") from exc
        result = evaluate(policy, evidence.risk_score, evidence.attestation_verified, decision_floor)
        fields: dict[str, Any] = {
            **evidence.model_dump(), "policy_version": result.policy_version,
            "policy_bundle_hash": bundle, "risk_band": result.band, "decision": result.decision}
        signature = sign_decision(fields, key)
        out = {k: getattr(v, "value", v) for k, v in fields.items()}
        return {**out, "decision_key_id": key_id, "decision_signature": signature}

    return app


def main() -> None:
    env: Mapping[str, str] = os.environ
    policy_path = Path(env.get("ATTESTA_POLICY_PATH", "/config/policy.yaml"))
    rego_path = Path(env.get("ATTESTA_POLICY_REGO_PATH", "/config/policy.rego"))
    key = serialization.load_pem_private_key(
        Path(env.get("ATTESTA_DECISION_KEY_PATH", "/run/attesta/decision-dev-1.key")).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("the decision key must be an Ed25519 private key")
    app = create_decision_app(
        load_policy(policy_path), opa_floor(env.get("ATTESTA_OPA_URL", "http://opa:8181")), key,
        env.get("ATTESTA_DECISION_KEY_ID", "decision-dev-1"), bundle_hash(policy_path, rego_path))
    uvicorn.run(app, host="0.0.0.0", port=int(env.get("ATTESTA_POLICY_SERVICE_PORT", "8182")), log_level="warning")


if __name__ == "__main__":
    main()
