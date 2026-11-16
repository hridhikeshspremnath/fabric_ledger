#!/usr/bin/env bash
# Recover after a Docker/PC restart or an expired server CA. The agent's join token is
# one-time and its cached SVID/bundle goes stale, so a restarted agent cannot rejoin.
# This drops ONLY the agent's cache (server CA, registrations and ledgers are kept),
# removes the workloads that shared its PID namespace, and starts everything again.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
S="$(dirname "${BASH_SOURCE[0]}")"

docker ps -a --filter label=com.docker.compose.project=attesta-spire --format '{{.Names}}' \
    | grep -v spire-server | xargs -r docker rm -f >/dev/null
docker volume rm -f attesta-spire_agent-data >/dev/null

"$S/up.sh"
"$S/gateway-up.sh"
if docker network inspect attesta-fabric >/dev/null 2>&1; then
    "$S/bridge-up.sh"
    "$S/gateway-fabric.sh"
fi
if [[ -n "${ATTESTA_DASHBOARD_DIR:-}" ]]; then "$S/dashboard-up.sh"; fi
