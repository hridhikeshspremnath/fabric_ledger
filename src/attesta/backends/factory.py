"""Choose the ledger backend from settings."""
from __future__ import annotations

from attesta.backends.base import LedgerBackend
from attesta.backends.bridge_client import SpiffeBridgeClient
from attesta.backends.fabric import FabricBackend
from attesta.backends.sqlite import SqliteBackend
from attesta.gateway.settings import GatewaySettings
from attesta.gateway.svid import SvidSource
from attesta.ledger.checkpoints import CheckpointSigner


def create_backend(settings: GatewaySettings, svid_source: SvidSource) -> LedgerBackend:
    if settings.backend == "sqlite":
        return SqliteBackend(settings.db_path, CheckpointSigner.load_or_create(settings.checkpoint_key_dir))
    if settings.backend == "fabric":
        client = SpiffeBridgeClient(
            settings.bridge_host, settings.bridge_port, settings.bridge_spiffe_id, svid_source,
            refresh_seconds=settings.svid_refresh_seconds)
        return FabricBackend(client)
    raise ValueError(f"unknown backend: {settings.backend!r} (use 'sqlite' or 'fabric')")
