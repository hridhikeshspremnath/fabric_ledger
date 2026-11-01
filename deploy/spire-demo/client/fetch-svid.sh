#!/bin/sh
# Fetch this workload's X.509-SVID and print ONLY its SPIFFE ID and the leaf
# certificate's SHA-256 fingerprint. The private key is written to a tmpfs
# scratch dir that is deleted on exit and is never printed.
set -eu

SOCKET="${SPIFFE_SOCKET:-/run/spire/sockets/agent.sock}"
TRIES="${FETCH_TRIES:-10}"

fetch() {
    /opt/spire/bin/spire-agent api fetch x509 -socketPath "$SOCKET" -write "$1" >"$1/fetch.log" 2>&1
}

spiffe_id() {
    grep -m1 '^SPIFFE ID:' "$1/fetch.log" | sed 's/^SPIFFE ID:[[:space:]]*//'
}

leaf_fingerprint() {
    awk '/BEGIN CERTIFICATE/{f=1} f&&!/-----/{print} /END CERTIFICATE/{exit}' "$1/svid.0.pem" \
        | base64 -d | sha256sum | cut -d' ' -f1
}

main() {
    out="$(mktemp -d)"
    trap 'rm -rf "$out"' EXIT
    i=0
    # Entries reach the agent on its next sync, so retry briefly.
    until fetch "$out"; do
        i=$((i + 1))
        [ "$i" -ge "$TRIES" ] && { echo "ERROR: no SVID issued after $TRIES tries" >&2; exit 1; }
        sleep 3
    done
    echo "spiffe_id=$(spiffe_id "$out")"
    echo "cert_sha256=$(leaf_fingerprint "$out")"
}

main
