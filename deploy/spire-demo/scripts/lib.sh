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

dc() {
    local files=(-f "$DEMO_DIR/docker-compose.yml")
    # Trained detector overlay (see docker-compose.dl.yml) when ATTESTA_DL_DIR is set.
    [[ -n "${ATTESTA_DL_DIR:-}" ]] && files+=(-f "$DEMO_DIR/docker-compose.dl.yml")
    # Advisory LLM review overlay (see docker-compose.llm.yml) when ATTESTA_LLM_MODEL is set.
    [[ -n "${ATTESTA_LLM_MODEL:-}" ]] && files+=(-f "$DEMO_DIR/docker-compose.llm.yml")
    # Dashboard overlay (see docker-compose.dashboard.yml) when ATTESTA_DASHBOARD_DIR is set.
    [[ -n "${ATTESTA_DASHBOARD_DIR:-}" ]] && files+=(-f "$DEMO_DIR/docker-compose.dashboard.yml")
    docker compose --project-directory "$DEMO_DIR" "${files[@]}" "$@"
}

spire_server() { dc exec -T spire-server "$SERVER_BIN" "$@"; }

spire_agent() { dc exec -T spire-agent "$AGENT_BIN" "$@"; }

entry_exists() { spire_server entry show -spiffeID "$1" | grep -q '^Entry ID'; }

die() { echo "ERROR: $*" >&2; exit 1; }

load_env
