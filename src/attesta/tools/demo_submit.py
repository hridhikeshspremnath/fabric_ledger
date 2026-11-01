"""Submit one signed TrustRecord to the gateway as the scoring-service identity.

Runs in a container as uid 1002 on the compose network. Prints only record
metadata (never keys or SVIDs).
"""
import hashlib
import http.client
import json
import os
import ssl
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from attesta.backends.models import Checkpoint, InclusionProof
from attesta.gateway.identity import identity_from_der
from attesta.gateway.settings import load_settings
from attesta.gateway.svid import create_svid_source
from attesta.gateway.tls import build_client_context
from attesta.policy.engine import evaluate, load_policy
from attesta.records.signing import sign_record_fields

GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "gateway")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "8443"))
KEY_PATH = Path(os.environ.get("SCORER_KEY_PATH", "/run/attesta/scorer-dev-1.key"))
KEY_ID = os.environ.get("SCORER_KEY_ID", "scorer-dev-1")


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def request(ctx: ssl.SSLContext, expected_server_id: str, method: str, path: str,
            body: dict[str, Any] | None = None) -> tuple[int, Any]:
    conn = http.client.HTTPSConnection(GATEWAY_HOST, GATEWAY_PORT, context=ctx, timeout=15)
    try:
        conn.connect()
        server = identity_from_der(conn.sock.getpeercert(binary_form=True))  # type: ignore[union-attr]
        if server.spiffe_id != expected_server_id:
            raise RuntimeError(f"unexpected server identity: {server.spiffe_id}")
        payload = json.dumps(body) if body is not None else None
        conn.request(method, path, body=payload, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read() or b"null")
    finally:
        conn.close()


def build_record(own_cert_sha256: str, own_id: str, policy_path: Path) -> dict[str, Any]:
    policy = load_policy(policy_path)
    score, verified = 120, True
    result = evaluate(policy, score, verified)
    return {
        "record_id": str(uuid.uuid4()), "run_id": f"demo-{uuid.uuid4().hex[:12]}",
        "submitted_by_spiffe_id": own_id, "caller_cert_sha256": own_cert_sha256,
        "ecosystem": "pypi", "package": "example-package", "version": "1.0.0",
        "artifact_digest": sha("demo-artifact"), "risk_score": score,
        "risk_band": result.band.value,
        "flag_install_exec": False, "flag_network": False, "flag_obfuscation": False,
        "flag_cred_access": False, "flag_process_spawn": False,
        "llm_verdict": "NOT_RUN", "llm_evidence_hash": None,
        "model_version_hash": sha("demo-model"), "policy_version": result.policy_version,
        "runner_class": "demo", "node_attestor": "join_token",
        "attestation_verified": verified, "attestation_digest": sha("demo-attestation"),
        "decision": result.decision.value, "evidence_hash": sha("demo-evidence"),
        "scorer_key_id": KEY_ID,
    }


def main() -> None:
    settings = load_settings()
    provider, material = create_svid_source(settings)
    ctx = build_client_context(material)
    own_cert_sha256 = material.leaf_sha256
    private_key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    fields = build_record(own_cert_sha256, settings.allowed_scorer_id, settings.policy_path)
    record = sign_record_fields(fields, private_key)  # type: ignore[arg-type]

    status, body = request(ctx, settings.gateway_spiffe_id, "POST", "/records", record.to_dict())
    print(f"POST /records -> {status}")
    if status != 201:
        raise SystemExit(f"rejected: {body}")
    print(f"record_id={body['record']['record_id']} sequence={body['sequence']} "
          f"record_hash={body['record_hash']}")

    _, checkpoint = request(ctx, settings.gateway_spiffe_id, "GET", "/checkpoint")
    _, proof = request(ctx, settings.gateway_spiffe_id, "GET",
                       f"/proof/{record.record_id}")
    cp, ip = Checkpoint(**checkpoint), InclusionProof(**proof)
    print(f"checkpoint_root={cp.merkle_root} records={cp.record_count}")
    print(f"proof_root_matches_checkpoint={ip.merkle_root == cp.merkle_root}")
    provider.close()


if __name__ == "__main__":
    main()
