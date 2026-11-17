"""Scoring-service settings: YAML file, overridable by ATTESTA_SCORING_<FIELD> env vars.

Several field names (spiffe_socket, trust_domain, svid_*) deliberately match
GatewaySettings so `create_svid_source` works with either.
"""
import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel


class ScoringSettings(BaseModel):
    # SPIFFE identity and gateway transport
    trust_domain: str = "attesta.example.org"
    spiffe_socket: str = "unix:///run/spire/sockets/agent.sock"
    svid_refresh_seconds: int = 300
    svid_fallback: bool = False
    svid_fallback_refresh_seconds: int = 1200
    spire_agent_bin: Path = Path("/opt/spire/bin/spire-agent")
    scoring_spiffe_id: str = "spiffe://attesta.example.org/scoring-service"
    gateway_host: str = "gateway"
    gateway_port: int = 8443
    gateway_spiffe_id: str = "spiffe://attesta.example.org/gateway"

    # Signing key (must live outside the git work tree) and policy
    scorer_key_path: Path = Path("/run/attesta/scorer-dev-1.key")
    scorer_key_id: str = "scorer-dev-1"
    allow_key_in_repo: bool = False  # dev escape hatch for gitignored demo keys
    policy_path: Path = Path("/config/policy.yaml")
    opa_url: str = ""  # OPA server for evidence floors (config/policy.rego); empty = bands only

    # Pluggable model and label extractors ("package.module:callable")
    model_factory: str = "attesta.scoring.reference:build_model"
    extractor_factory: str = "attesta.scoring.reference:build_extractors"
    model_path: Optional[Path] = None
    aux_threshold_permille: int = 500

    # Record metadata
    runner_class: str = "scoring-service"
    node_attestor: str = "join_token"
    attestation_mode: str = "none"  # none | static (dev only) | github-oidc
    attestation_digest: Optional[str] = None
    # github-oidc: repositories ("owner/name", comma-separated) whose workflows may attest,
    # and the audience the CI job must request for its token.
    attestation_repos: str = ""
    attestation_audience: str = "attesta"
    attestation_issuer: str = "https://token.actions.githubusercontent.com"
    attestation_jwks_url: str = "https://token.actions.githubusercontent.com/.well-known/jwks"

    # Download / archive limits (all in-memory; nothing is installed or executed)
    max_download_bytes: int = 50 * 1024 * 1024
    max_uncompressed_bytes: int = 200 * 1024 * 1024
    max_scanned_bytes: int = 20 * 1024 * 1024
    max_file_bytes: int = 1024 * 1024
    max_files: int = 5000
    fetch_timeout_seconds: float = 30.0

    # Service behaviour
    result_cache_seconds: int = 3600
    max_concurrent: int = 4
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_token_env: str = "ATTESTA_SCORING_API_TOKEN"


def load_scoring_settings(path: Optional[Path] = None) -> ScoringSettings:
    path = path or Path(os.environ.get("ATTESTA_SCORING_CONFIG", "/config/scoring.yaml"))
    data: dict[str, Any] = {}
    if Path(path).exists():
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for field in ScoringSettings.model_fields:
        value = os.environ.get(f"ATTESTA_SCORING_{field.upper()}")
        if value is not None:
            data[field] = value
    return ScoringSettings(**data)
