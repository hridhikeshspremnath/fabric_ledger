#!/usr/bin/env bash
# Start the orderer and both peers (chaincode servers come later, in step 04).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -d "$ORG_DIR" ]] || die "run 01-gen-crypto.sh first"
[[ -f "$NET_DIR/peercfg/core.yaml" ]] || die "run 00-bootstrap.sh first"
compose up -d orderer.example.com peer0.attesta.example.com peer0.auditor.example.com
compose ps --format 'table {{.Service}}\t{{.Status}}'
