"""FastAPI gateway. Only the scoring-service identity may write; reads need any
valid in-trust-domain client (enforced by the TLS layer plus `require_peer`)."""
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Response

from attesta.backends.base import (
    DuplicateRecordError, LedgerBackend, LedgerEmptyError, LedgerRejectedError,
    LedgerUnavailableError, RecordNotFoundError)
from attesta.backends.models import AnyCheckpoint, ArtifactVerdict, LedgerEntry, Proof
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.gateway.writer import SingleWriter
from attesta.policy.decision import DECISION_FIELDS, verify_decision
from attesta.policy.engine import PolicyConfig, evaluate
from attesta.policy.opa import EVIDENCE, Floor, OpaUnavailable
from attesta.records.signing import KeyRegistry, SignatureRejected, verify_record_signature
from attesta.records.trust_record import SHA256_RE, Decision, TrustRecord


def create_app(settings: GatewaySettings, backend: LedgerBackend,
               registry: KeyRegistry, policy: PolicyConfig,
               floor: Optional[Floor] = None, decision_keys: Optional[KeyRegistry] = None,
               bundle: Optional[str] = None) -> FastAPI:
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
        if decision_keys is not None:  # signed decisions are required: made by the approved policy bundle
            if record.policy_bundle_hash != bundle:
                raise HTTPException(status_code=422, detail="policy_bundle_hash is not this gateway's policy bundle")
            if not record.decision_key_id or not record.decision_signature:
                raise HTTPException(status_code=403, detail="decision signature required")
            try:
                verify_decision({k: getattr(record, k) for k in DECISION_FIELDS}, record.decision_key_id,
                                record.decision_signature, decision_keys)
            except SignatureRejected as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
        decision_floor = Decision.ALLOW
        if floor is not None:
            try:
                decision_floor = floor({k: getattr(record, k) for k in EVIDENCE})
            except OpaUnavailable as exc:  # fail strict: no rules, no record
                raise HTTPException(status_code=503, detail="policy engine unavailable") from exc
        expected = evaluate(policy, record.risk_score, record.attestation_verified, decision_floor)
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
        except LedgerRejectedError as exc:
            raise HTTPException(status_code=422, detail=f"ledger rejected the record: {exc}") from exc
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail="ledger unavailable") from exc

    @app.get("/records", response_model=list[LedgerEntry])
    def list_records(response: Response, limit: int = Query(100, ge=1, le=500),
                     cursor: str = Query("", max_length=2048),
                     _: PeerIdentity = Depends(require_peer)) -> list[LedgerEntry]:
        """Oldest-first page. Pass the X-Next-Cursor response header back as `cursor`."""
        try:
            page = backend.list_page(limit=limit, cursor=cursor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail="ledger unavailable") from exc
        response.headers["X-Next-Cursor"] = page.next_cursor
        return page.entries

    @app.get("/records/{record_id}", response_model=LedgerEntry)
    def get_record(record_id: str, _: PeerIdentity = Depends(require_peer)) -> LedgerEntry:
        entry: Optional[LedgerEntry] = backend.get(record_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="record not found")
        return entry

    @app.get("/proof/{record_id}", response_model=Proof)
    def get_proof(record_id: str, _: PeerIdentity = Depends(require_peer)) -> Proof:
        try:
            return backend.proof(record_id)
        except (RecordNotFoundError, LedgerEmptyError) as exc:
            raise HTTPException(status_code=404, detail="record not found") from exc
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail="ledger unavailable") from exc

    @app.get("/artifacts/{digest}", response_model=ArtifactVerdict)
    def verify_artifact(digest: str = Path(pattern=SHA256_RE),
                        _: PeerIdentity = Depends(require_peer)) -> ArtifactVerdict:
        """Every decision recorded for an artifact digest (used by the deploy gate)."""
        try:
            return backend.verify_artifact(digest)
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail="ledger unavailable") from exc

    @app.get("/checkpoint", response_model=AnyCheckpoint)
    def get_checkpoint(_: PeerIdentity = Depends(require_peer)) -> AnyCheckpoint:
        try:
            return backend.checkpoint()
        except LedgerEmptyError as exc:
            raise HTTPException(status_code=404, detail="ledger is empty") from exc
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail="ledger unavailable") from exc

    return app
