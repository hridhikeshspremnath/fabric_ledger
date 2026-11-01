#!/usr/bin/env bash
# Health check: server, agent, and both workload entries. Exit 1 on any FAIL.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

rc=0
check() {  # <label> <cmd...>
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '%-22s OK\n' "$label"
    else
        printf '%-22s FAIL\n' "$label"; rc=1
    fi
}

check "spire-server" spire_server healthcheck
check "spire-agent" spire_agent healthcheck -socketPath "$AGENT_SOCKET"
check "entry build-runner" entry_exists "$CI_RUNNER_ID"
check "entry scoring-service" entry_exists "$SCORING_ID"
dc ps --format 'table {{.Service}}\t{{.Status}}'
exit "$rc"
