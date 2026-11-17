#!/usr/bin/env bash
# Build the gateway image, create a demo scorer key (once), register the
# gateway entry, and start the gateway WITHOUT touching the running agent.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

IMAGE=attesta-spire-gateway:local
KEY_ID=scorer-dev-1

dc --profile gateway build gateway

mkdir -p "$RUNTIME_DIR"
if [[ ! -f "$RUNTIME_DIR/$KEY_ID.key" ]]; then
    # Demo key only, kept in the gitignored .runtime dir. Mode 644 so the
    # demo-submit container (uid 1002) can read it; use a real KMS/HSM later.
    docker run --rm --user "$(id -u):$(id -g)" -v "$RUNTIME_DIR:/out" \
        --entrypoint python "$IMAGE" -m attesta.tools.gen_scorer_key \
        --out-dir /out --key-id "$KEY_ID" --key-mode 644
fi

"$(dirname "${BASH_SOURCE[0]}")/register.sh"
dc --profile gateway up -d --no-deps --wait opa
dc --profile gateway up -d --no-deps --wait gateway
echo "Gateway up. Next: scripts/demo-submit.sh"
