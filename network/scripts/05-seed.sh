#!/usr/bin/env bash
# Seed the on-chain policy and scorer key registry as the Attesta ADMIN identity.
#
# Keys file (public keys only), first match wins:
#   $SCORER_KEYS_FILE  (e.g. ~/keys/scorer_keys.yaml from attesta.tools.gen_scorer_key)
#   deploy/spire-demo/.runtime/scorer_keys.yaml  (created by gateway-up.sh)
# Uses the active Python (venv with `pip install -e .`) if it can import attesta,
# otherwise the gateway image (deploy/spire-demo/scripts/gateway-up.sh builds it).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

IMAGE="${GATEWAY_IMAGE:-attesta-spire-gateway:local}"
KEYS_FILE="${SCORER_KEYS_FILE:-$ROOT/deploy/spire-demo/.runtime/scorer_keys.yaml}"
[[ -f "$KEYS_FILE" ]] || die "missing $KEYS_FILE (set SCORER_KEYS_FILE or run gateway-up.sh)"

payload() {  # <policy|key>
    if python -c "import attesta" 2>/dev/null; then
        python -m attesta.tools.seed_payloads "$1" --policy "$ROOT/config/policy.yaml" --keys "$KEYS_FILE"
    else
        docker run --rm --entrypoint python \
            -v "$ROOT/config:/config:ro" -v "$(dirname "$KEYS_FILE"):/keys:ro" "$IMAGE" \
            -m attesta.tools.seed_payloads "$1" --policy /config/policy.yaml \
            --keys "/keys/$(basename "$KEYS_FILE")"
    fi
}

use_org attesta
invoke "$(payload policy)"
invoke "$(payload key)"
sleep 2
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"GetPolicy","Args":[""]}'
echo
