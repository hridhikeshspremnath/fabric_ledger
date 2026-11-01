#!/usr/bin/env bash
# Override a record's effective decision as the Auditor.
# Usage: scripts/auditor-override.sh <record_id> <ALLOW|WARN|REVIEW|BLOCK> "<reason>"
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# -eq 3 ]] || die "usage: $0 <record_id> <decision> \"<reason>\""
dc --profile auditor run --rm --no-deps auditor-cli attesta.tools.auditor_override "$@"
