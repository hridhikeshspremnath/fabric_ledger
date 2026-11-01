#!/usr/bin/env bash
# Resolve Go dependencies for the chaincode (writes go.mod/go.sum). Needs network.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.22}"

docker run --rm --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false \
    -v attesta-gopath:/tmp/gopath \
    -v "$ROOT:/repo" -w /repo/chaincode/attesta-trust \
    "$GO_IMAGE" go mod tidy
