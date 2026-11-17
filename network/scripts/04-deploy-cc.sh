#!/usr/bin/env bash
# Build the chaincode image, package/install it per org (CCaaS), start the
# chaincode servers, then approve (both orgs) and commit. NEEDS the Go module
# download once (scripts/chaincode-tidy.sh) and the golang:1.22-alpine image.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -f "$ROOT/chaincode/attesta-trust/go.sum" ]] || die "run scripts/chaincode-tidy.sh first"
docker build -t attesta-trust-cc:local "$ROOT/chaincode/attesta-trust"

package_for() {  # <org> <chaincode-host>
    local tmp; tmp="$(mktemp -d)"
    printf '{"address":"%s:9999","dial_timeout":"10s","tls_required":false}' "$2" > "$tmp/connection.json"
    printf '{"type":"ccaas","label":"%s"}' "$CC_LABEL" > "$tmp/metadata.json"
    (cd "$tmp" && tar czf code.tar.gz connection.json && tar czf "$ART_DIR/$CC_NAME-$1.tgz" metadata.json code.tar.gz)
    rm -rf "$tmp"
}

install_for() {  # <org>
    use_org "$1"
    peer_cli lifecycle chaincode install "$ART_DIR/$CC_NAME-$1.tgz" || true   # already installed is fine
    peer_cli lifecycle chaincode calculatepackageid "$ART_DIR/$CC_NAME-$1.tgz" > "$ART_DIR/pkgid-$1"
}

package_for attesta attesta-trust-attesta
package_for auditor attesta-trust-auditor
package_for release attesta-trust-release
install_for attesta
install_for auditor
install_for release

ATTESTA_CC_ID="$(cat "$ART_DIR/pkgid-attesta")" AUDITOR_CC_ID="$(cat "$ART_DIR/pkgid-auditor")" \
    RELEASE_CC_ID="$(cat "$ART_DIR/pkgid-release")" \
    compose --profile chaincode up -d attesta-trust-attesta attesta-trust-auditor attesta-trust-release

approve_for() {  # <org>
    use_org "$1"
    peer_cli lifecycle chaincode approveformyorg "${ORDERER_ARGS[@]}" --channelID "$CHANNEL" \
        --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
        --package-id "$(cat "$ART_DIR/pkgid-$1")" --signature-policy "$CC_POLICY"
}
approve_for attesta
approve_for auditor
approve_for release

use_org attesta
# shellcheck disable=SC2046
peer_cli lifecycle chaincode commit "${ORDERER_ARGS[@]}" --channelID "$CHANNEL" \
    --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
    --signature-policy "$CC_POLICY" $(endorse_args)
sleep 3
peer_cli lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME"
