#!/usr/bin/env bash
# Ask the ledger whether an artifact may deploy. Exit 0 = pass, 1 = refused, 2 = unverified.
# Usage: scripts/deploy-gate.sh sha256:<hex> [--allow ALLOW,WARN]
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# -ge 1 ]] || die "usage: $0 sha256:<hex> [--allow ALLOW,WARN]"
dc --profile gate run --rm --no-deps deploy-gate attesta.tools.deploy_gate "$@"
