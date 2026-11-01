# Minimal workload stand-in: alpine (sh, awk, base64, sha256sum) plus the
# static spire-agent binary, used only for `api fetch x509`.
FROM ghcr.io/spiffe/spire-agent:1.15.3 AS spire

FROM alpine:3.20
COPY --from=spire /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY fetch-svid.sh /client/fetch-svid.sh
ENTRYPOINT ["/bin/sh", "/client/fetch-svid.sh"]
