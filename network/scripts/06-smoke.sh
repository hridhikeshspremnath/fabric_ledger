#!/usr/bin/env bash
# Read-only sanity checks against the deployed chaincode.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

use_org attesta
echo "-- active policy"
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"GetPolicy","Args":[""]}'; echo
echo "-- recent records"
peer_cli chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"function":"ListRecent","Args":["5",""]}'; echo
echo "-- chain height"
peer_cli channel getinfo -c "$CHANNEL"
