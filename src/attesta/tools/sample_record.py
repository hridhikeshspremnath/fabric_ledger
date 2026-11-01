"""Print a signed sample TrustRecord as a `peer chaincode invoke -c` JSON (for Fabric demos).

    python -m attesta.tools.sample_record --key ~/keys/scorer-dev-1.key [--score 900] [--tamper]

--tamper changes the package AFTER signing, so the chaincode must reject the signature.
--policy-mismatch signs a decision that contradicts the policy bands.
"""
import argparse
import hashlib
import json
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from attesta.policy.engine import evaluate, load_policy
from attesta.records.signing import sign_record_fields

SCORER_ID = "spiffe://attesta.example.org/scoring-service"


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def build(args: argparse.Namespace) -> dict:
    policy = load_policy(args.policy)
    result = evaluate(policy, args.score, True)
    decision = "ALLOW" if args.policy_mismatch and result.decision.value != "ALLOW" else result.decision.value
    if args.policy_mismatch and decision == result.decision.value:
        decision = "BLOCK" if decision != "BLOCK" else "ALLOW"
    key = serialization.load_pem_private_key(Path(args.key).expanduser().read_bytes(), password=None)
    fields = {
        "record_id": str(uuid.uuid4()), "run_id": args.run_id or f"showcase-{uuid.uuid4().hex[:8]}",
        "submitted_by_spiffe_id": SCORER_ID, "caller_cert_sha256": "ab" * 32,
        "ecosystem": "pypi", "package": args.package, "version": args.version,
        "artifact_digest": sha(f"{args.package}@{args.version}"),
        "risk_score": args.score, "risk_band": result.band.value,
        "flag_install_exec": False, "flag_network": args.score >= 300, "flag_cred_access": False,
        "flag_obfuscation": False, "flag_process_spawn": False,
        "llm_verdict": "NOT_RUN", "llm_evidence_hash": None,
        "model_version_hash": sha("showcase-model"), "policy_version": result.policy_version,
        "runner_class": "showcase", "node_attestor": "join_token",
        "attestation_verified": True, "attestation_digest": sha("showcase-attestation"),
        "decision": decision, "evidence_hash": sha(f"evidence:{args.package}"),
        "scorer_key_id": args.key_id,
    }
    record = sign_record_fields(fields, key).to_dict()  # type: ignore[arg-type]
    if args.tamper:
        record["package"] = "tampered-" + record["package"]
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True, help="scorer private key (PEM, outside the repo)")
    parser.add_argument("--key-id", default="scorer-dev-1")
    parser.add_argument("--policy", default="config/policy.yaml")
    parser.add_argument("--package", default="demo-package")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--score", type=int, default=120, help="risk score in permille (0-1000)")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--policy-mismatch", action="store_true")
    parser.add_argument("--print-record-id", action="store_true", help="print only the record_id")
    args = parser.parse_args()
    record = build(args)
    if args.print_record_id:
        print(record["record_id"])
        return
    print(json.dumps({"function": "RecordDecision", "Args": [json.dumps(record, separators=(",", ":"))]}))


if __name__ == "__main__":
    main()
