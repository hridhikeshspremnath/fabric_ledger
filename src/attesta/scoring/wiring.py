"""Composition root: build a ScoringService from settings."""
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from attesta.backends.bridge_client import SpiffeBridgeClient
from attesta.gateway.identity import identity_from_der
from attesta.gateway.svid import create_svid_source
from attesta.policy.engine import load_policy
from attesta.policy.opa import opa_floor
from attesta.scoring.attestation import build_attestation
from attesta.scoring.errors import ConfigError
from attesta.scoring.fetch import UrllibFetcher
from attesta.scoring.model import load_factory
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.submit import GatewaySubmitter


def build_gateway_submitter(settings: ScoringSettings) -> GatewaySubmitter:
    """mTLS client using this process's SPIRE SVID, which must be the scoring-service ID."""
    source, material = create_svid_source(settings)  # type: ignore[arg-type]  # duck-typed settings
    leaf = x509.load_pem_x509_certificate(material.cert_chain_pem.encode("ascii"))
    own_id = identity_from_der(leaf.public_bytes(serialization.Encoding.DER)).spiffe_id
    if own_id != settings.scoring_spiffe_id:
        source.close()
        raise ConfigError(f"running as {own_id}, expected {settings.scoring_spiffe_id}")
    client = SpiffeBridgeClient(settings.gateway_host, settings.gateway_port,
                                settings.gateway_spiffe_id, source,
                                refresh_seconds=settings.svid_refresh_seconds)
    return GatewaySubmitter(client, client.leaf_sha256)


def build_service(settings: ScoringSettings, dry_run_only: bool = False) -> ScoringService:
    signer = ScorerSigner.load(settings.scorer_key_path, settings.scorer_key_id,
                               settings.allow_key_in_repo)
    return ScoringService(
        settings=settings,
        fetcher=UrllibFetcher(timeout=settings.fetch_timeout_seconds),
        model=load_factory(settings.model_factory, settings),
        extractors=load_factory(settings.extractor_factory, settings),
        policy=load_policy(settings.policy_path),
        signer=signer,
        attestation=build_attestation(settings),
        submitter=None if dry_run_only else build_gateway_submitter(settings),
        floor=opa_floor(settings.opa_url) if settings.opa_url else None)
