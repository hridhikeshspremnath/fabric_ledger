#!/usr/bin/env bash
# Stop the Fabric network. --purge also deletes ledgers, generated crypto,
# channel artifacts and chaincode packages (a clean slate).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ "${1:-}" == "--purge" ]]; then
    compose --profile chaincode down -v --remove-orphans
    rm -rf "$ORG_DIR" "$ART_DIR"
else
    compose --profile chaincode down --remove-orphans
fi
