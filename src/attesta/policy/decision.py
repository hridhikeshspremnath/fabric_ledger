"""Signed policy decisions: who decided, under which policy bundle.

A policy service (separate process and key from the scorer) computes the decision for a
record's evidence and signs it. The signature covers the evidence it saw, the decision, the
record and artifact it belongs to, and the hash of the policy bundle (score bands + Rego rules)
it ran. The chaincode checks that hash against the one approved on-chain, so a decision made
under any other policy is refused, and the scorer key alone cannot mint a decision.
"""
import base64
import hashlib
import http.client
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attesta.policy.opa import OpaUnavailable
from attesta.records.canonical import canonical_bytes
from attesta.records.signing import KeyRegistry, SignatureRejected

# Everything the decision depends on, plus what binds it to one record and artifact.
DECISION_FIELDS = (
    "record_id", "artifact_digest", "policy_version", "policy_bundle_hash", "risk_score", "risk_band",
    "attestation_verified", "flag_install_exec", "flag_network", "flag_obfuscation", "flag_cred_access",
    "flag_process_spawn", "llm_verdict", "decision")
# The request to the policy service: the evidence, not the decision.
EVIDENCE_FIELDS = (
    "record_id", "artifact_digest", "risk_score", "attestation_verified", "flag_install_exec", "flag_network",
    "flag_obfuscation", "flag_cred_access", "flag_process_spawn", "llm_verdict")


def _plain(value: Any) -> Any:
    return getattr(value, "value", value)  # enums -> their string value


def decision_payload(fields: Mapping[str, Any]) -> bytes:
    """Canonical bytes the policy service signs and the chaincode re-derives from the record."""
    return canonical_bytes({k: _plain(fields[k]) for k in DECISION_FIELDS})


def sign_decision(fields: Mapping[str, Any], key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.sign(decision_payload(fields))).decode("ascii")


def verify_decision(fields: Mapping[str, Any], key_id: str, signature: str, registry: KeyRegistry,
                    now: Optional[datetime] = None) -> None:
    """Raises SignatureRejected unless `signature` is a valid decision signature from an active key."""
    public = registry.active_key(key_id, now).public_key_obj()
    try:
        public.verify(base64.b64decode(signature, validate=True), decision_payload(fields))
    except (InvalidSignature, ValueError) as exc:
        raise SignatureRejected("invalid decision signature") from exc


def bundle_hash(*paths: Path) -> str:
    """sha256 over the per-file sha256s of the policy bundle files, in the order given."""
    outer = hashlib.sha256()
    for path in paths:
        outer.update(hashlib.sha256(Path(path).read_bytes()).digest())
    return "sha256:" + outer.hexdigest()


class PolicyUnavailable(OpaUnavailable):
    """The policy service could not be reached or gave an unusable answer (fail strict)."""


def remote_decide(url: str, timeout: float = 10.0):
    """Client for the policy service: evidence in, signed decision fields out."""
    parts = urlsplit(url)

    def decide(evidence: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps({k: _plain(evidence[k]) for k in EVIDENCE_FIELDS})
        try:
            conn = http.client.HTTPConnection(parts.hostname or "", parts.port or 8182, timeout=timeout)
            try:
                conn.request("POST", "/v1/decide", body, {"Content-Type": "application/json"})
                response = conn.getresponse()
                payload = json.loads(response.read() or b"null")
            finally:
                conn.close()
            if response.status != 200:
                raise PolicyUnavailable(f"policy service returned {response.status}")
            return dict(payload)
        except (OSError, http.client.HTTPException, ValueError, TypeError) as exc:
            raise PolicyUnavailable(f"policy service query failed: {exc}") from exc

    return decide
