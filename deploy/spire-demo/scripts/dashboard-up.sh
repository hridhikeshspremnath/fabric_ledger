#!/usr/bin/env bash
# Build and start the dashboard as its own SPIFFE workload WITHOUT touching the running
# agent. Needs ATTESTA_DASHBOARD_DIR in .env and the gateway running.
# Sign-in: users and the session secret live in .runtime (gitignored). The first run creates the
# secret and an `admin` user with a generated password, written to .runtime/dashboard_users.json.admin.password.
# Add or reset users with scripts/dashboard-user.sh.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${ATTESTA_DASHBOARD_DIR:-}" ]] || die "set ATTESTA_DASHBOARD_DIR in .env (path to the dashboard checkout)"
"$(dirname "${BASH_SOURCE[0]}")/register.sh"
mkdir -p "$RUNTIME_DIR"
dc --profile dashboard build dashboard
"$(dirname "${BASH_SOURCE[0]}")/dashboard-user.sh" --init
dc --profile dashboard up -d --no-deps --wait dashboard
echo "Dashboard on http://127.0.0.1:3000 (sign in required)"
