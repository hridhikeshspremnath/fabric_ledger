#!/usr/bin/env bash
# Fetch an SVID as each workload (or just one: ci-runner | scoring-service).
# Prints only SPIFFE ID + cert SHA-256. --no-deps keeps the running agent
# untouched (it would otherwise be recreated without JOIN_TOKEN).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(ci-runner scoring-service)

for t in "${targets[@]}"; do
    echo "== $t"
    dc run --rm --no-deps "$t"
done
