#!/usr/bin/env bash
# Report SPIRE image sizes and live container memory.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

docker image ls --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}' | grep -E 'REPOSITORY|spiffe/spire'
docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}' \
    $(dc ps -q 2>/dev/null)
