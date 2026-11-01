#!/usr/bin/env bash
# Submit one signed TrustRecord as the scoring-service identity, over mTLS.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dc run --rm --no-deps demo-submit
