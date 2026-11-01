#!/usr/bin/env bash
# Idempotently register the two demo workloads under the demo agent.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

register() {  # <spiffe-id> <uid>
    if entry_exists "$1"; then echo "exists:  $1"; return; fi
    spire_server entry create -parentID "$AGENT_ID" -spiffeID "$1" \
        -selector "unix:uid:$2" >/dev/null
    echo "created: $1 (unix:uid:$2)"
}

register "$CI_RUNNER_ID" "$CI_RUNNER_UID"
register "$SCORING_ID" "$SCORING_UID"
register "$GATEWAY_ID" "$GATEWAY_UID"
register "$FABRIC_BRIDGE_ID" "$FABRIC_BRIDGE_UID"
register "$AUDITOR_BRIDGE_ID" "$AUDITOR_BRIDGE_UID"
register "$AUDITOR_ID" "$AUDITOR_UID"
