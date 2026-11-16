#!/usr/bin/env bash
# Build and start the dashboard as its own SPIFFE workload WITHOUT touching the running
# agent. Needs ATTESTA_DASHBOARD_DIR in .env and the gateway running.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${ATTESTA_DASHBOARD_DIR:-}" ]] || die "set ATTESTA_DASHBOARD_DIR in .env (path to the dashboard checkout)"
"$(dirname "${BASH_SOURCE[0]}")/register.sh"
dc --profile dashboard up -d --no-deps --build --wait dashboard
echo "Dashboard on http://127.0.0.1:3000/trust-ledger"
