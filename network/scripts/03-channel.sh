#!/usr/bin/env bash
# Create the channel on the orderer (channel participation API) and join the three peers.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

osnadmin channel join --channelID "$CHANNEL" --config-block "$ART_DIR/$CHANNEL.block" \
    -o localhost:7053 --ca-file "$ORDERER_TLS/ca.crt" \
    --client-cert "$ORDERER_TLS/server.crt" --client-key "$ORDERER_TLS/server.key"

sleep 3
for org in attesta auditor release; do
    use_org "$org"
    peer_cli channel join -b "$ART_DIR/$CHANNEL.block"
done
sleep 3
use_org attesta
peer_cli channel list
