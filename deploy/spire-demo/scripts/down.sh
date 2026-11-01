#!/usr/bin/env bash
# Stop the stack. Pass --purge to also delete volumes and .runtime (fresh CA).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ "${1:-}" == "--purge" ]]; then
    dc --profile clients --profile gateway --profile fabric --profile auditor --profile scoring --profile scoring-cli down -v --remove-orphans
    rm -rf "$RUNTIME_DIR"
else
    dc --profile clients --profile gateway --profile fabric --profile auditor --profile scoring --profile scoring-cli down --remove-orphans
fi
