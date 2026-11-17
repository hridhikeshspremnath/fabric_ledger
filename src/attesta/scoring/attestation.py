"""Runner-attestation input for the TrustRecord.

With no credential the record is unattested (attestation_verified=false) and the policy
downgrades ALLOW/WARN to REVIEW. A GitHub Actions OIDC token proves WHICH repository's
workflow is asking; it is verified here and only then is the record marked attested.

An invalid or expired token is an error (401), never a silent downgrade: a CI job that
presents a bad token should fail loudly, not look like a job with no token.
"""
import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

import jwt

from attesta.records.canonical import canonical_bytes
from attesta.scoring.errors import AttestationRejected, ConfigError, FetchError
from attesta.scoring.fetch import Fetcher
from attesta.scoring.settings import ScoringSettings

log = logging.getLogger("attesta.scoring")

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_URL = GITHUB_ISSUER + "/.well-known/jwks"
# Claims that identify the run. Personal fields (actor, email) are deliberately left out.
_DIGEST_CLAIMS = ("iss", "aud", "repository", "repository_owner", "ref", "sha", "workflow",
                  "job_workflow_ref", "run_id", "run_attempt", "runner_environment", "event_name")
_SAFE = re.compile(r"[^A-Za-z0-9._:-]")


@dataclass(frozen=True)
class Attestation:
    verified: bool
    digest: Optional[str]  # "sha256:<hex>" of the verified claims, if any
    runner_class: Optional[str] = None   # e.g. github-hosted / self-hosted
    node_attestor: Optional[str] = None  # e.g. github-oidc


class AttestationProvider(Protocol):
    def get(self, credential: Optional[str] = None) -> Attestation: ...


class NoAttestation:
    def get(self, credential: Optional[str] = None) -> Attestation:
        return Attestation(verified=False, digest=None)


class StaticAttestation:
    """DEV ONLY: trust a configured digest without verifying anything."""

    def __init__(self, digest: str) -> None:
        self._digest = digest

    def get(self, credential: Optional[str] = None) -> Attestation:
        return Attestation(verified=True, digest=self._digest)


class GithubOidcAttestation:
    """Verify a GitHub Actions OIDC token against GitHub's published signing keys.

    Checks: RS256 signature (the algorithm is pinned, so `none` and HMAC-with-public-key
    tricks fail), issuer, audience, expiry, and that `repository` is on the allow-list.
    No credential gives an unattested result.
    """

    def __init__(self, fetcher: Fetcher, audience: str, repositories: frozenset[str],
                 issuer: str = GITHUB_ISSUER, jwks_url: str = GITHUB_JWKS_URL,
                 clock: Callable[[], float] = time.monotonic,
                 jwks_ttl: float = 3600.0, refresh_gap: float = 60.0) -> None:
        if not repositories:
            raise ConfigError("attestation_mode=github-oidc requires attestation_repos")
        self._fetcher, self._aud, self._repos = fetcher, audience, repositories
        self._iss, self._jwks_url, self._clock = issuer, jwks_url, clock
        self._ttl, self._gap = jwks_ttl, refresh_gap
        self._keys: dict[str, Any] = {}
        self._fetched: Optional[float] = None
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        try:
            jwks = self._fetcher.get_json(self._jwks_url)
            self._keys = {k["kid"]: jwt.PyJWK(k).key for k in jwks["keys"] if k.get("kty") == "RSA"}
        except (FetchError, KeyError, TypeError, jwt.PyJWTError) as exc:
            raise AttestationRejected(f"cannot load the signing keys: {exc}") from exc
        self._fetched = self._clock()

    def _key(self, kid: Optional[str]) -> Any:
        with self._lock:
            now = self._clock()
            if self._fetched is None or now - self._fetched > self._ttl:
                self._refresh()
            if kid not in self._keys and now - (self._fetched or 0) > self._gap:
                self._refresh()  # key rotation: at most one refetch per refresh_gap
            if kid not in self._keys:
                raise AttestationRejected("token signed by an unknown key")
            return self._keys[kid]

    def get(self, credential: Optional[str] = None) -> Attestation:
        if not credential:
            return Attestation(verified=False, digest=None)
        try:
            header = jwt.get_unverified_header(credential)
            if header.get("alg") != "RS256":
                raise AttestationRejected("token must be signed with RS256")
            claims = jwt.decode(
                credential, self._key(header.get("kid")), algorithms=["RS256"],
                audience=self._aud, issuer=self._iss, leeway=30,
                options={"require": ["exp", "iat", "iss", "aud"]})
        except jwt.PyJWTError as exc:
            raise AttestationRejected(f"invalid token: {exc}") from exc
        repository = claims.get("repository")
        if repository not in self._repos:
            raise AttestationRejected(f"repository {repository!r} is not allowed")
        evidence = {k: claims[k] for k in _DIGEST_CLAIMS if k in claims}
        digest = "sha256:" + hashlib.sha256(canonical_bytes(evidence)).hexdigest()
        runner = _SAFE.sub("_", str(claims.get("runner_environment") or "unknown"))[:64]
        return Attestation(True, digest, runner_class=runner, node_attestor="github-oidc")


def build_attestation(settings: ScoringSettings, fetcher: Optional[Fetcher] = None) -> AttestationProvider:
    if settings.attestation_mode == "none":
        return NoAttestation()
    if settings.attestation_mode == "static":
        if not settings.attestation_digest:
            raise ConfigError("attestation_mode=static requires attestation_digest")
        log.warning("attestation_mode=static: attestation is NOT verified (dev only)")
        return StaticAttestation(settings.attestation_digest)
    if settings.attestation_mode == "github-oidc":
        if fetcher is None:
            raise ConfigError("github-oidc attestation needs a fetcher")
        repos = frozenset(r.strip() for r in settings.attestation_repos.split(",") if r.strip())
        return GithubOidcAttestation(fetcher, settings.attestation_audience, repos,
                                     settings.attestation_issuer, settings.attestation_jwks_url)
    raise ConfigError(f"unknown attestation_mode: {settings.attestation_mode!r}")
