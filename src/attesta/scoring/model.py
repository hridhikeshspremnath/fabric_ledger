"""Contracts for the exported model and the label extractors, plus the loader.

Floats exist only inside a model adapter. Everything crossing this boundary is
an integer permille, so no float can reach a TrustRecord.
"""
import hashlib
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from attesta.scoring.errors import ConfigError
from attesta.scoring.source import SourceBundle

FLAG_NAMES = ("flag_install_exec", "flag_network", "flag_cred_access",
              "flag_obfuscation", "flag_process_spawn")


@dataclass(frozen=True)
class ModelOutput:
    risk_permille: int
    aux_permille: Mapping[str, int]  # one entry per FLAG_NAMES (the model's aux heads)

    def __post_init__(self) -> None:
        if not 0 <= self.risk_permille <= 1000:
            raise ValueError("risk_permille must be in 0..1000")
        missing = set(FLAG_NAMES) - set(self.aux_permille)
        if missing:
            raise ValueError(f"aux_permille missing heads: {sorted(missing)}")
        if any(not isinstance(v, int) or not 0 <= v <= 1000 for v in self.aux_permille.values()):
            raise ValueError("aux_permille values must be integers in 0..1000")


@dataclass(frozen=True)
class ExtractorResult:
    flags: Mapping[str, bool]            # one entry per FLAG_NAMES
    hits: Mapping[str, tuple[str, ...]]  # rule ids that fired, per flag (evidence)


class ScoringModel(Protocol):
    version_hash: str  # "sha256:<hex>" identifying the exported weights + preprocessing

    def predict(self, bundle: SourceBundle) -> ModelOutput: ...


class LabelExtractor(Protocol):
    version: str

    def extract(self, bundle: SourceBundle) -> ExtractorResult: ...


def to_permille(probability: float) -> int:
    """Clamp a 0..1 probability and round to an integer permille (half-even, deterministic)."""
    return max(0, min(1000, round(probability * 1000)))


def hash_files(paths: Iterable[Path]) -> str:
    """Stable identifier for a set of model artifacts: sha256 over per-file sha256s."""
    outer = hashlib.sha256()
    for path in sorted(Path(p) for p in paths):
        outer.update(hashlib.sha256(path.read_bytes()).digest())
    return "sha256:" + outer.hexdigest()


def load_factory(spec: str, settings: Any) -> Any:
    """Import "package.module:callable" and call it with the settings."""
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ConfigError(f"factory must look like 'package.module:callable', got {spec!r}")
    try:
        factory = getattr(importlib.import_module(module_name), attr)
    except (ImportError, AttributeError) as exc:
        raise ConfigError(f"cannot load factory {spec!r}: {exc}") from exc
    return factory(settings)
