"""Single-writer queue: every ledger append runs on one worker, in order."""
import asyncio
from typing import Optional

from attesta.backends.base import LedgerBackend
from attesta.backends.models import LedgerEntry
from attesta.records.trust_record import TrustRecord


class SingleWriter:
    def __init__(self, backend: LedgerBackend, maxsize: int = 256) -> None:
        self._backend = backend
        self._queue: asyncio.Queue[tuple[TrustRecord, asyncio.Future[LedgerEntry]]] = (
            asyncio.Queue(maxsize=maxsize))
        self._worker: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        self._worker = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._worker:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass

    async def submit(self, record: TrustRecord) -> LedgerEntry:
        future: asyncio.Future[LedgerEntry] = asyncio.get_running_loop().create_future()
        await self._queue.put((record, future))
        return await future

    async def _run(self) -> None:
        while True:
            record, future = await self._queue.get()
            try:
                entry = await asyncio.to_thread(self._backend.append, record)
                future.set_result(entry)
            except Exception as exc:  # delivered to the waiting request
                future.set_exception(exc)
