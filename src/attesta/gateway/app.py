"""FastAPI gateway. Only the scoring-service identity may write; reads need any
valid in-trust-domain client (enforced by the TLS layer plus `require_peer`)."""
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query

from attesta.backends.base import (
    DuplicateRecordError, LedgerBackend, LedgerEmptyError, RecordNotFoundError)
from attesta.backends.models import Checkpoint, InclusionProof, LedgerEntry
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.gateway.writer import SingleWriter
from attesta.policy.engine import PolicyConfig, evaluate
from attesta.records.signing import KeyRegistry, SignatureRejected, verify_record_signature
from attesta.records.trust_record import TrustRecord


def create_app(settings: GatewaySettings, backend: LedgerBackend,
               registry: KeyRegistry, policy: PolicyConfig) -> FastAPI:
    writer = SingleWriter(backend, settings.queue_maxsize)
    trust_prefix = f"spiffe://{settings.trust_domain}/"

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await writer.start()
        yield
        await writer.stop()

    app = FastAPI(title="Attesta gateway", lifespan=lifespan)

    def require_peer(peer: PeerIdentity = Depends(get_peer_identity)) -> PeerIdentity:
        if not peer.spiffe_id.startswith(trust_prefix):
            raise HTTPException(status_code=403, detail="peer outside trust domain")
        return peer

    def check_caller(record: TrustRecord, peer: PeerIdentity) -> None:
        if peer.spiffe_id != settings.allowed_scorer_id:
            raise HTTPException(status_code=403, detail="caller is not the scoring service")
        if record.submitted_by_spiffe_id != peer.spiffe_id:
            raise HTTPException(status_code=403, detail="submitted_by_spiffe_id != caller identity")
        if record.caller_cert_sha256 != peer.cert_sha256:
            raise HTTPException(status_code=403, detail="caller_cert_sha256 != caller certificate")

    def check_signature(record: TrustRecord) -> None:
        try:
            verify_record_signature(record, registry)
        except SignatureRejected as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def check_policy(record: TrustRecord) -> None:
        if record.policy_version != policy.policy_version:
            raise HTTPException(status_code=422, detail="policy_version mismatch")
        expected = evaluate(policy, record.risk_score, record.attestation_verified)
        if record.risk_band != expected.band or record.decision != expected.decision:
            raise HTTPException(status_code=422, detail="risk_band/decision do not match policy")

    @app.post("/records", status_code=201, response_model=LedgerEntry)
    async def post_record(record: TrustRecord,
                          peer: PeerIdentity = Depends(require_peer)) -> LedgerEntry:
        check_caller(record, peer)
        check_signature(record)
        check_policy(record)
        try:
            return await writer.submit(record)
        except DuplicateRecordError as exc:
            raise HTTPException(status_code=409, detail="duplicate run_id or record_id") from exc

    @app.get("/records", response_model=list[LedgerEntry])
    def list_records(limit: int = Query(100, ge=1, le=500), after: int = Query(0, ge=0),
                     _: PeerIdentity = Depends(require_peer)) -> list[LedgerEntry]:
        return backend.list(limit=limit, after_sequence=after)

    @app.get("/records/{record_id}", response_model=LedgerEntry)
    def get_record(record_id: str, _: PeerIdentity = Depends(require_peer)) -> LedgerEntry:
        entry: Optional[LedgerEntry] = backend.get(record_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="record not found")
        return entry

    @app.get("/proof/{record_id}", response_model=InclusionProof)
    def get_proof(record_id: str, _: PeerIdentity = Depends(require_peer)) -> InclusionProof:
        try:
            return backend.proof(record_id)
        except (RecordNotFoundError, LedgerEmptyError) as exc:
            raise HTTPException(status_code=404, detail="record not found") from exc

    @app.get("/checkpoint", response_model=Checkpoint)
    def get_checkpoint(_: PeerIdentity = Depends(require_peer)) -> Checkpoint:
        try:
            return backend.checkpoint()
        except LedgerEmptyError as exc:
            raise HTTPException(status_code=404, detail="ledger is empty") from exc

    return app
