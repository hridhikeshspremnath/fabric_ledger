#!/usr/bin/env bash
# Run the chaincode unit tests (including the shared Python/Go vectors).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.22}"

docker run --rm --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false \
    -v attesta-gopath:/tmp/gopath \
    -v "$ROOT:/repo" -w /repo/chaincode/attesta-trust \
    "$GO_IMAGE" go test ./... "$@"
