"""Runner-attestation input for the TrustRecord.

Default is "none": attestation_verified=false, so the policy downgrades
ALLOW/WARN to REVIEW. Real verification (e.g. GitHub OIDC) plugs in here later.
"""
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

from attesta.scoring.errors import ConfigError
from attesta.scoring.settings import ScoringSettings

log = logging.getLogger("attesta.scoring")


@dataclass(frozen=True)
class Attestation:
    verified: bool
    digest: Optional[str]  # "sha256:<hex>" of the attestation evidence, if any


class AttestationProvider(Protocol):
    def get(self) -> Attestation: ...


class NoAttestation:
    def get(self) -> Attestation:
        return Attestation(verified=False, digest=None)


class StaticAttestation:
    """DEV ONLY: trust a configured digest without verifying anything."""

    def __init__(self, digest: str) -> None:
        self._digest = digest

    def get(self) -> Attestation:
        return Attestation(verified=True, digest=self._digest)


def build_attestation(settings: ScoringSettings) -> AttestationProvider:
    if settings.attestation_mode == "none":
        return NoAttestation()
    if settings.attestation_mode == "static":
        if not settings.attestation_digest:
            raise ConfigError("attestation_mode=static requires attestation_digest")
        log.warning("attestation_mode=static: attestation is NOT verified (dev only)")
        return StaticAttestation(settings.attestation_digest)
    raise ConfigError(f"unknown attestation_mode: {settings.attestation_mode!r}")
