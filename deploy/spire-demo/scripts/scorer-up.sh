#!/usr/bin/env bash
# Start the scoring service (HTTP API for CI) without touching the running agent.
# The CI bearer token lives in .runtime/scoring_token (gitignored, mode 600); it is
# generated once and never printed. Needs the gateway image (gateway-up.sh builds it)
# and the gateway running.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TOKEN_FILE="$RUNTIME_DIR/scoring_token"
mkdir -p "$RUNTIME_DIR"
if [[ ! -s "$TOKEN_FILE" ]]; then
    umask 077
    head -c 32 /dev/urandom | base64 | tr -d '\n=' > "$TOKEN_FILE"
fi
[[ -f "$RUNTIME_DIR/scorer-dev-1.key" ]] || die "missing demo scorer key; run scripts/gateway-up.sh first"

export ATTESTA_SCORING_API_TOKEN
ATTESTA_SCORING_API_TOKEN="$(cat "$TOKEN_FILE")"
dc --profile scoring up -d --no-deps --wait scorer
echo "Scoring service on http://127.0.0.1:8080 (token file: $TOKEN_FILE)"
