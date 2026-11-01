# Gateway + demo_submit image. Build context is the repo root (see compose).
# spire-agent binary is only used by the optional fetch-loop fallback.
FROM ghcr.io/spiffe/spire-agent:1.15.3 AS spire

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=spire /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY config /config
# /data is the ledger volume; created owned by the gateway uid so a fresh
# named volume inherits writable ownership.
RUN pip install . && mkdir -p /data /run/attesta && chown 1003:1003 /data

USER 1003
ENTRYPOINT ["python", "-m"]
CMD ["attesta.gateway.serve"]
