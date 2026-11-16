"""Deploy gate: let a deploy proceed only if the ledger holds an ALLOW for this exact artifact.

    python -m attesta.tools.deploy_gate <file | sha256:<hex>> [--allow ALLOW,WARN]

Exit 0 = deploy may proceed, 1 = refused, 2 = could not verify (treat as refused).

The answer comes from the ledger through the gateway (SPIFFE mTLS), not from the CI
job that built the artifact. Any workload in the trust domain may ask; nobody can
change the answer without a scorer-signed record or an auditor override on-chain.
"""
import argparse
import hashlib
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from attesta.backends.bridge_client import SpiffeBridgeClient
from attesta.gateway.settings import load_settings
from attesta.gateway.svid import create_svid_source
from attesta.records.trust_record import SHA256_RE

PASS, REFUSED, UNVERIFIED = 0, 1, 2


def digest_of(target: str) -> str:
    """`sha256:<hex>` as given, otherwise the SHA-256 of the file at that path."""
    if re.fullmatch(SHA256_RE, target):
        return target
    sha = hashlib.sha256()
    with Path(target).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return "sha256:" + sha.hexdigest()


def decide(verdict: dict[str, Any], allowed: frozenset[str]) -> tuple[bool, str]:
    """(may deploy, reason). Fails closed: unknown artifacts and any standing BLOCK refuse."""
    if not verdict.get("found"):
        return False, "no ledger record for this artifact"
    blocked = [r["record_id"] for r in verdict["records"] if r["effective_decision"] == "BLOCK"]
    if blocked:  # a later re-score must not quietly outvote a BLOCK; an auditor has to clear it
        return False, f"BLOCK stands on record {blocked[0]}"
    latest, record_id = verdict["latest_effective_decision"], verdict["latest_record_id"]
    if latest not in allowed:
        return False, f"latest decision is {latest} (record {record_id})"
    return True, f"{latest} (record {record_id})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="artifact file, or its digest as sha256:<64 hex>")
    parser.add_argument("--allow", default="ALLOW",
                        help="comma-separated decisions that may deploy (default: ALLOW)")
    args = parser.parse_args()
    allowed = frozenset(part.strip().upper() for part in args.allow.split(","))
    try:
        digest = digest_of(args.target)
    except OSError as exc:
        print(f"deploy gate: UNVERIFIED cannot read artifact: {exc}")
        raise SystemExit(UNVERIFIED) from exc

    settings = load_settings()
    source, _ = create_svid_source(settings)
    try:
        client = SpiffeBridgeClient(
            os.environ.get("GATEWAY_HOST", "gateway"), int(os.environ.get("GATEWAY_PORT", "8443")),
            settings.gateway_spiffe_id, source, timeout=30.0)
        status, body = client.request("GET", f"/artifacts/{quote(digest, safe='')}")
    finally:
        source.close()
    if status != 200:
        print(f"deploy gate: UNVERIFIED {digest}: gateway returned {status}: {body}")
        raise SystemExit(UNVERIFIED)
    ok, reason = decide(body, allowed)
    print(f"deploy gate: {'PASS' if ok else 'REFUSED'} {digest}: {reason}")
    raise SystemExit(PASS if ok else REFUSED)


if __name__ == "__main__":
    main()
