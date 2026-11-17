#!/usr/bin/env bash
# Export a read-only snapshot of SPIRE registration entries and agents for the dashboard's
# Workload Identity page: .runtime/identity/snapshot.json (gitignored; no keys, no tokens).
#   scripts/identity-snapshot.sh          one snapshot
#   scripts/identity-snapshot.sh --loop   refresh every 30 s until stopped (run it in the background)
# The dashboard shows the snapshot's age, so a stopped loop is visible as "stale".
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

snap() {
    local out="$RUNTIME_DIR/identity" entries agents
    mkdir -p "$out"
    entries="$(spire_server entry show -output json)" || return 1
    agents="$(spire_server agent list -output json)" || return 1
    ENTRIES="$entries" AGENTS="$agents" TRUST_DOMAIN="$TRUST_DOMAIN" OUT="$out/snapshot.json" python3 - <<'EOF'
import json, os, re, time

td = os.environ["TRUST_DOMAIN"]


def sid(x):  # {"trust_domain", "path"} -> spiffe://...
    # A join-token agent's SPIFFE ID path ends in the token value itself. Tokens are one-time, but
    # keep them out of the dashboard anyway: show only the first 8 characters.
    path = re.sub(r"(/join_token/)([^/]{8})[^/]*", r"\1\2…", x["path"])
    return f"spiffe://{x['trust_domain']}{path}"


entries = json.loads(os.environ["ENTRIES"]).get("entries", [])
agents = json.loads(os.environ["AGENTS"]).get("agents", [])
doc = {
    "taken_at": int(time.time()), "trust_domain": td,
    "entries": [{
        "id": e["id"], "spiffe_id": sid(e["spiffe_id"]), "parent_id": sid(e["parent_id"]),
        "selectors": [f"{s['type']}:{s['value']}" for s in e.get("selectors", [])],
        "x509_svid_ttl": int(e.get("x509_svid_ttl", 0)), "admin": bool(e.get("admin")),
        "created_at": int(e.get("created_at", 0))} for e in entries],
    "agents": [{
        "id": sid(a["id"]), "attestation_type": a["attestation_type"], "version": a.get("agent_version", ""),
        "banned": bool(a.get("banned")), "can_reattest": bool(a.get("can_reattest")),
        "svid_expires_at": int(a.get("x509svid_expires_at", 0))} for a in agents],
}
tmp = os.environ["OUT"] + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f)
os.chmod(tmp, 0o644)  # the dashboard container reads it as another uid
os.replace(tmp, os.environ["OUT"])  # atomic: the dashboard never sees a half-written file
print(f"snapshot: {len(doc['entries'])} entries, {len(doc['agents'])} agents")
EOF
}

if [[ "${1:-}" == "--loop" ]]; then
    while true; do snap || echo "snapshot failed (is the SPIRE server up?)" >&2; sleep 30; done
else
    snap
fi
