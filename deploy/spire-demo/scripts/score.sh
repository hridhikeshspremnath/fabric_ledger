#!/usr/bin/env bash
# Score one package as the scoring-service identity and submit the TrustRecord.
# Usage: scripts/score.sh <pypi|npm> <package> <version> [--dry-run] [--json] [--fail-on BLOCK]
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# -ge 3 ]] || die "usage: $0 <pypi|npm> <package> <version> [options]"
dc --profile scoring-cli run --rm --no-deps scorer-cli attesta.scoring.cli score "$@"
