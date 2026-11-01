#!/usr/bin/env bash
# Start server, export trust bundle, mint a one-time join token, start agent,
# register workloads. The token is passed via env only (never written to disk).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

mkdir -p "$RUNTIME_DIR"
dc up -d --wait spire-server

spire_server bundle show > "$RUNTIME_DIR/bootstrap.crt"

JOIN_TOKEN="$(spire_server token generate -spiffeID "$AGENT_ID" -ttl "$JOIN_TOKEN_TTL" \
    | awk '/^Token:/{print $2}')"
[[ -n "$JOIN_TOKEN" ]] || die "join token generation failed"
export JOIN_TOKEN

dc up -d --wait spire-agent
"$(dirname "${BASH_SOURCE[0]}")/register.sh"
echo "Up. Next: scripts/health.sh && scripts/test-client.sh"
