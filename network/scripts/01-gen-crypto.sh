#!/usr/bin/env bash
# Generate dev identities (cryptogen) and the channel genesis block (configtxgen).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -x "$NET_DIR/bin/cryptogen" ]] || die "run 00-bootstrap.sh first"
[[ -d "$ORG_DIR" ]] && die "$ORG_DIR already exists; run 07-down.sh --purge to start over"

cryptogen generate --config="$NET_DIR/config/crypto-config.yaml" --output="$ORG_DIR"

mkdir -p "$ART_DIR"
FABRIC_CFG_PATH="$NET_DIR/config" configtxgen -profile AttestaChannel \
    -outputBlock "$ART_DIR/$CHANNEL.block" -channelID "$CHANNEL"

# DEV ONLY: the bridge containers run as uid 1004/1005 (SPIRE selectors), so
# their org user key must be world-readable. These files are gitignored.
for org in attesta auditor; do
    key_dir="$ORG_DIR/peerOrganizations/$org.example.com/users/User1@$org.example.com/msp/keystore"
    chmod 755 "$key_dir"
    chmod 644 "$key_dir"/*_sk
done
echo "Crypto material and $CHANNEL genesis block created."
