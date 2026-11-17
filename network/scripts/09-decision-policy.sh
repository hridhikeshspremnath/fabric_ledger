#!/usr/bin/env bash
# Register the policy service's public key and activate a policy version that PINS the policy
# bundle hash (config/policy.yaml + config/policy.rego). After this the chaincode refuses any record
# whose decision was not signed by that key under exactly this bundle. Changing either file means
# a new policy_version and another run of this script (SetPolicy needs two orgs' endorsements).
#
# Keys file (public key only): $DECISION_KEYS_FILE or deploy/spire-demo/.runtime/decision_keys.yaml
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

IMAGE="${GATEWAY_IMAGE:-attesta-spire-gateway:local}"
KEYS_FILE="${DECISION_KEYS_FILE:-$ROOT/deploy/spire-demo/.runtime/decision_keys.yaml}"
[[ -f "$KEYS_FILE" ]] || die "missing $KEYS_FILE (run deploy/spire-demo/scripts/gateway-up.sh first)"

payload() {  # <policy|decision-key>
    docker run --rm --entrypoint python \
        -v "$ROOT/config:/config:ro" -v "$(dirname "$KEYS_FILE"):/keys:ro" "$IMAGE" \
        -m attesta.tools.seed_payloads "$1" --policy /config/policy.yaml --rego /config/policy.rego \
        --keys "/keys/$(basename "$KEYS_FILE")"
}

use_org attesta
invoke "$(payload decision-key)"
invoke "$(payload policy)"
sleep 2
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"GetPolicy","Args":[""]}'
echo
