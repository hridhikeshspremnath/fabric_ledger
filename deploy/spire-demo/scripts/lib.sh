#!/usr/bin/env bash
# Shared helpers. Source this; do not execute.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$DEMO_DIR/.runtime"
SERVER_BIN=/opt/spire/bin/spire-server
AGENT_BIN=/opt/spire/bin/spire-agent
AGENT_SOCKET=/run/spire/sockets/agent.sock

load_env() {
    local f="$DEMO_DIR/.env.example"
    [[ -f "$DEMO_DIR/.env" ]] && f="$DEMO_DIR/.env"
    set -a; . "$f"; set +a
}

dc() { docker compose --project-directory "$DEMO_DIR" "$@"; }

spire_server() { dc exec -T spire-server "$SERVER_BIN" "$@"; }

spire_agent() { dc exec -T spire-agent "$AGENT_BIN" "$@"; }

entry_exists() { spire_server entry show -spiffeID "$1" | grep -q '^Entry ID'; }

die() { echo "ERROR: $*" >&2; exit 1; }

load_env
