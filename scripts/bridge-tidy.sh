#!/usr/bin/env bash
# Resolve Go dependencies for the bridge (writes go.mod/go.sum), then run its tests.
# Needs network. Usage: scripts/bridge-tidy.sh [test]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.22}"

run_go() {
    docker run --rm --user "$(id -u):$(id -g)" \
        -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false \
        -v attesta-gopath:/tmp/gopath \
        -v "$ROOT:/repo" -w /repo/bridge \
        "$GO_IMAGE" go "$@"
}

run_go mod tidy
[[ "${1:-}" == "test" ]] && run_go test ./...
exit 0
