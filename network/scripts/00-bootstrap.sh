#!/usr/bin/env bash
# Download the Fabric CLI binaries (cryptogen, configtxgen, peer, osnadmin) and
# the stock core.yaml. NEEDS NETWORK. Container images are NOT pulled here
# (hyperledger/fabric-peer|orderer:2.5.16 should already be present).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

URL="https://github.com/hyperledger/fabric/releases/download/v${FABRIC_VERSION}/hyperledger-fabric-linux-amd64-${FABRIC_VERSION}.tar.gz"
DL_DIR="$NET_DIR/downloads"

if [[ ! -x "$NET_DIR/bin/peer" ]]; then
    rm -rf "$DL_DIR" && mkdir -p "$DL_DIR/extract"
    curl -fsSL -o "$DL_DIR/fabric.tar.gz" "$URL"
    sha256sum "$DL_DIR/fabric.tar.gz"   # compare with the checksum on the GitHub release page
    # Extract to a scratch dir so the tarball's config/ cannot overwrite network/config/.
    tar -xzf "$DL_DIR/fabric.tar.gz" -C "$DL_DIR/extract" bin config
    mkdir -p "$NET_DIR/bin" "$NET_DIR/peercfg"
    cp "$DL_DIR"/extract/bin/* "$NET_DIR/bin/"
    cp "$DL_DIR/extract/config/core.yaml" "$NET_DIR/peercfg/core.yaml"
fi

# Enable the chaincode-as-a-service external builder shipped in the peer image.
if ! grep -q ccaas_builder "$NET_DIR/peercfg/core.yaml"; then
    sed -i 's|^\( *\)externalBuilders: *\[\]|\1externalBuilders:\n\1  - name: ccaas_builder\n\1    path: /opt/hyperledger/ccaas_builder\n\1    propagateEnvironment:\n\1      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG|' "$NET_DIR/peercfg/core.yaml"
    grep -q ccaas_builder "$NET_DIR/peercfg/core.yaml" || die "could not enable ccaas_builder in core.yaml (edit externalBuilders by hand)"
fi

peer version | head -3
