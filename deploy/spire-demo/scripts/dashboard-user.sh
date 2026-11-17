#!/usr/bin/env bash
# Dashboard sign-in users. Runs the dashboard image's own tool, so no Node install is needed.
#   scripts/dashboard-user.sh --init                 create the session secret and an `admin` user if missing
#   scripts/dashboard-user.sh <username> [password]  add or reset a user (no password = generated, written to
#                                                    .runtime/dashboard_users.json.<username>.password)
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

tool() { docker run --rm --user "$(id -u):$(id -g)" -v "$RUNTIME_DIR:/runtime" --workdir /app \
    --entrypoint node attesta-dashboard:local scripts/user.mjs "$@"; }

if [[ "${1:-}" == "--init" ]]; then
    tool --secret /runtime/dashboard_session_secret
    [[ -f "$RUNTIME_DIR/dashboard_users.json" ]] || tool /runtime/dashboard_users.json admin
else
    [[ $# -ge 1 ]] || die "usage: $0 --init | <username> [password]"
    tool /runtime/dashboard_users.json "$@"
fi
