#!/usr/bin/env bash
# Build the bridge image, register the bridge/auditor SPIFFE entries and start
# both bridges WITHOUT touching the running agent. Needs the Fabric network up
# (network/scripts/02..05) and bridge/go.sum (scripts/bridge-tidy.sh).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ROOT_DIR="$(cd "$DEMO_DIR/../.." && pwd)"
[[ -d "$ROOT_DIR/network/organizations" ]] || die "Fabric crypto missing; run network/scripts/01-gen-crypto.sh"
[[ -f "$ROOT_DIR/bridge/go.sum" ]] || die "bridge/go.sum missing; run scripts/bridge-tidy.sh"
docker network inspect attesta-fabric >/dev/null 2>&1 || die "network attesta-fabric not found; run network/scripts/02-up.sh"

dc --profile fabric build fabric-bridge
"$(dirname "${BASH_SOURCE[0]}")/register.sh"
dc --profile fabric up -d --no-deps --wait fabric-bridge fabric-bridge-auditor
echo "Bridges up. Next: scripts/gateway-fabric.sh"
