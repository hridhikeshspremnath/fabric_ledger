#!/usr/bin/env bash
# Shared settings/helpers for the Fabric network scripts. Source, don't execute.
set -euo pipefail

NET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$NET_DIR/.." && pwd)"
export PATH="$NET_DIR/bin:$PATH"

FABRIC_VERSION="${FABRIC_VERSION:-2.5.16}"
CHANNEL="${CHANNEL:-attesta-ch}"
CC_NAME="${CC_NAME:-attesta-trust}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CC_LABEL="${CC_LABEL:-attesta-trust_1}"
CC_POLICY="AND('AttestaMSP.peer','AuditorMSP.peer')"
ORG_DIR="$NET_DIR/organizations"
ART_DIR="$NET_DIR/channel-artifacts"
ORDERER_CA="$ORG_DIR/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORDERER_TLS="$ORG_DIR/ordererOrganizations/example.com/orderers/orderer.example.com/tls"

die() { echo "ERROR: $*" >&2; exit 1; }

compose() { docker compose -f "$NET_DIR/docker-compose.fabric.yaml" "$@"; }

peer_tls_ca() {  # <attesta|auditor>
    echo "$ORG_DIR/peerOrganizations/$1.example.com/peers/peer0.$1.example.com/tls/ca.crt"
}

# Point the `peer` CLI at an org's Admin identity (host ports: attesta 7051, auditor 9051).
use_org() {
    local org="$1" port msp
    case "$org" in
        attesta) port=7051; msp=AttestaMSP ;;
        auditor) port=9051; msp=AuditorMSP ;;
        *) die "unknown org: $org" ;;
    esac
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_LOCALMSPID="$msp"
    export CORE_PEER_ADDRESS="localhost:$port"
    export CORE_PEER_TLS_ROOTCERT_FILE="$(peer_tls_ca "$org")"
    export CORE_PEER_MSPCONFIGPATH="$ORG_DIR/peerOrganizations/$org.example.com/users/Admin@$org.example.com/msp"
}

peer_cli() { FABRIC_CFG_PATH="$NET_DIR/peercfg" peer "$@"; }

ORDERER_ARGS=(-o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA")

# Both orgs must endorse every transaction.
endorse_args() {
    echo --peerAddresses localhost:7051 --tlsRootCertFiles "$(peer_tls_ca attesta)" \
         --peerAddresses localhost:9051 --tlsRootCertFiles "$(peer_tls_ca auditor)"
}

invoke() {  # <ctor-json> -- submits as the current use_org identity with both endorsers
    # shellcheck disable=SC2046
    peer_cli chaincode invoke "${ORDERER_ARGS[@]}" -C "$CHANNEL" -n "$CC_NAME" $(endorse_args) \
        --waitForEvent -c "$1"
}
