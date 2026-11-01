"""Gateway entry point: `python -m attesta.gateway.serve` (mTLS via the SPIRE agent)."""
import asyncio
import logging

import uvicorn

from attesta.backends.factory import create_backend
from attesta.gateway.app import create_app
from attesta.gateway.protocol import MtlsH11Protocol
from attesta.gateway.settings import GatewaySettings, load_settings
from attesta.gateway.svid import SvidSource, create_svid_source
from attesta.gateway.tls import build_server_context, reload_context
from attesta.policy.engine import load_policy
from attesta.records.signing import KeyRegistry

log = logging.getLogger("attesta.gateway")


async def refresh_loop(provider: SvidSource, ctx, interval: int, current: str) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            material = provider.snapshot()
            if material.leaf_sha256 != current:
                reload_context(ctx, material)
                current = material.leaf_sha256
                log.info("reloaded gateway SVID")
        except Exception:  # keep serving with the previous SVID
            log.exception("SVID refresh failed")


async def run(settings: GatewaySettings) -> None:
    provider, material = create_svid_source(settings)
    ctx = build_server_context(material)

    backend = create_backend(settings, provider)
    app = create_app(settings, backend, KeyRegistry.load(settings.scorer_keys_path),
                     load_policy(settings.policy_path))

    config = uvicorn.Config(
        app, host=settings.listen_host, port=settings.listen_port,
        http=MtlsH11Protocol, ssl_context_factory=lambda _cfg, _default: ctx, log_level="info")
    refresher = asyncio.create_task(
        refresh_loop(provider, ctx, provider.refresh_seconds, material.leaf_sha256))
    try:
        await uvicorn.Server(config).serve()
    finally:
        refresher.cancel()
        provider.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run(load_settings()))


if __name__ == "__main__":
    main()
