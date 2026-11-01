#!/usr/bin/env bash
# Hyperledger Fabric showcase. Needs the network up and seeded (steps 00-05) and an
# activated venv (`pip install -e .`). Uses only the peer CLI: no SPIRE, gateway or bridge.
#
#   SCORER_KEY=~/keys/scorer-dev-1.key network/scripts/08-showcase.sh
#   PAUSE=1 ...   waits for Enter between steps (for live presenting)
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KEY="${SCORER_KEY:-$HOME/keys/scorer-dev-1.key}"
[[ -f "$KEY" ]] || die "scorer key not found: $KEY"
sample() { python -m attesta.tools.sample_record --key "$KEY" "$@"; }
brief() { grep -E 'status:|Error|successful|message|Height|Block|Sequence|Version|Endorsement' || true; }

step() {
    printf '\n\033[1m=== %s ===\033[0m\n' "$1"
    [[ "${PAUSE:-0}" == "1" ]] && read -r -p "(Enter to run) " _
}
cmd() { printf '\033[36m$ %s\033[0m\n' "$*"; }

step "1. The network: 1 orderer, 2 org peers (LevelDB), 2 chaincode servers"
cmd docker ps --filter name=example.com --filter name=attesta-trust
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' \
    --filter name=example.com --filter name=attesta-trust

step "2. The channel (a ledger shared by both orgs): block height and hashes"
use_org attesta
cmd peer channel getinfo -c "$CHANNEL"
peer_cli channel getinfo -c "$CHANNEL"

step "3. The chaincode and its endorsement policy: BOTH orgs must sign every transaction"
cmd peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME"
peer_cli lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME" 2>&1 | brief

step "4. The policy stored ON-CHAIN (bands in permille, allowed scorer identity)"
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"GetPolicy","Args":[""]}'; echo

step "5. ACCEPTED: submit a clean, correctly signed record (score 120 -> ALLOW)"
GOOD_RUN="showcase-$(date +%s)"
CTOR="$(sample --package clean-pkg --score 120 --run-id "$GOOD_RUN")"
RECORD_ID="$(python - "$CTOR" <<'PYEOF'
import json, sys
print(json.loads(json.loads(sys.argv[1])["Args"][0])["record_id"])
PYEOF
)"
cmd "peer chaincode invoke ... RecordDecision (record $RECORD_ID)"
invoke "$CTOR" 2>&1 | brief

step "6. Read it back from the ledger (canonical record + transaction metadata)"
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" \
    -c "{\"function\":\"GetRecord\",\"Args\":[\"$RECORD_ID\"]}"; echo

step "7. REJECTED: replay the same run_id (replay protection)"
invoke "$(sample --package clean-pkg --score 120 --run-id "$GOOD_RUN")" 2>&1 | brief

step "8. REJECTED: tampered after signing (Ed25519 signature check inside the chaincode)"
invoke "$(sample --package other-pkg --score 120 --tamper)" 2>&1 | brief

step "9. REJECTED: decision contradicts the on-chain policy (recomputed by the chaincode)"
invoke "$(sample --package liar-pkg --score 950 --policy-mismatch)" 2>&1 | brief

step "10. Auditor org overrides the decision (append-only, reason required)"
use_org auditor
cmd "peer chaincode invoke ... RecordOverride $RECORD_ID BLOCK"
invoke "{\"function\":\"RecordOverride\",\"Args\":[\"$RECORD_ID\",\"BLOCK\",\"post-install script found in manual review\"]}" 2>&1 | brief
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" \
    -c "{\"function\":\"GetHistory\",\"Args\":[\"$RECORD_ID\"]}"; echo
echo "Records now BLOCKed:"
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"ListByStatus","Args":["BLOCK","10",""]}'; echo

step "11. Two organisations, two signatures: stop the Auditor peer and try to write"
cmd docker stop peer0.auditor.example.com
docker stop peer0.auditor.example.com >/dev/null
use_org attesta
invoke "$(sample --package no-quorum-pkg --score 120)" 2>&1 | brief
cmd docker start peer0.auditor.example.com
docker start peer0.auditor.example.com >/dev/null
echo "(Auditor peer restarted; give it ~10 s to rejoin before the next transaction)"

step "12. Chain height after the demo"
peer_cli channel getinfo -c "$CHANNEL"
