"""Print `peer chaincode invoke -c` JSON to seed the on-chain policy and scorer key.

Public data only (policy bands, scorer PUBLIC key). Times become unix seconds
because the chaincode keeps integers only.
"""
import argparse
import json
from pathlib import Path

import yaml

from attesta.gateway.settings import load_settings
from attesta.policy.decision import bundle_hash
from attesta.policy.engine import load_policy
from attesta.records.signing import ScorerKey


def policy_ctor(policy_path: Path, allowed_scorer_id: str, rego_path: Path | None = None) -> str:
    policy = load_policy(policy_path)
    doc = {
        "policy_version": policy.policy_version,
        "allowed_scorer_spiffe_id": allowed_scorer_id,
        "bands": [
            {"name": b.name.value, "min_score": b.min_score, "max_score": b.max_score,
             "decision": b.decision.value}
            for b in policy.bands
        ],
    }
    if rego_path is not None:  # pin the policy bundle: decisions must be signed under exactly these files
        doc["bundle_hash"] = bundle_hash(policy_path, rego_path)
    return json.dumps({"function": "SetPolicy", "Args": [json.dumps(doc, separators=(",", ":"))]})


def key_ctor(keys_path: Path, key_id: str | None, function: str = "RegisterScorerKey") -> str:
    data = yaml.safe_load(Path(keys_path).read_text(encoding="utf-8")) or {}
    keys = [ScorerKey(**item) for item in data.get("keys", [])]
    chosen = [k for k in keys if key_id in (None, k.key_id)]
    if len(chosen) != 1:
        raise SystemExit(f"expected exactly one matching key, found {len(chosen)}")
    key = chosen[0]
    doc = {"key_id": key.key_id, "public_key": key.public_key,
           "not_before": int(key.not_before.timestamp()), "not_after": int(key.not_after.timestamp()),
           "revoked": key.revoked}
    return json.dumps({"function": function, "Args": [json.dumps(doc, separators=(",", ":"))]})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("what", choices=["policy", "key", "decision-key"])
    parser.add_argument("--policy", type=Path, default=Path("/config/policy.yaml"))
    parser.add_argument("--keys", type=Path, default=Path("/runtime/scorer_keys.yaml"))
    parser.add_argument("--key-id", default=None)
    parser.add_argument("--rego", type=Path, default=None, help="pin the policy bundle (policy + this Rego file)")
    args = parser.parse_args()
    if args.what == "policy":
        print(policy_ctor(args.policy, load_settings().allowed_scorer_id, args.rego))
    elif args.what == "decision-key":
        print(key_ctor(args.keys, args.key_id, "RegisterDecisionKey"))
    else:
        print(key_ctor(args.keys, args.key_id))


if __name__ == "__main__":
    main()
