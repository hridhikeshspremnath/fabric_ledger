#!/usr/bin/env bash
# Recreate ONLY the gateway container with the Fabric backend (ATTESTA_BACKEND=fabric).
# Use scripts/gateway-up.sh (default sqlite) to switch back.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ATTESTA_BACKEND=fabric dc --profile gateway up -d --no-deps --force-recreate --wait gateway
echo "Gateway now uses the Fabric backend. Next: scripts/demo-submit.sh"
