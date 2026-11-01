"""Stand-in model so the service runs end to end before the exported model is wired in.

NOT the trained model: risk is a weighted sum of extractor flags. Replace it by
setting `model_factory` to a factory that wraps the exported model.
"""
import hashlib
from typing import Any

from attesta.scoring.extractors import HeuristicExtractor
from attesta.scoring.model import FLAG_NAMES, ModelOutput
from attesta.scoring.source import SourceBundle

_WEIGHTS = {"flag_install_exec": 250, "flag_network": 150, "flag_cred_access": 300,
            "flag_obfuscation": 250, "flag_process_spawn": 150}
_VERSION = "heuristic-model-1:" + ",".join(f"{k}={v}" for k, v in sorted(_WEIGHTS.items()))


class HeuristicModel:
    version_hash = "sha256:" + hashlib.sha256(_VERSION.encode()).hexdigest()

    def __init__(self) -> None:
        self._extractor = HeuristicExtractor()

    def predict(self, bundle: SourceBundle) -> ModelOutput:
        flags = self._extractor.extract(bundle).flags
        risk = min(1000, sum(_WEIGHTS[name] for name in FLAG_NAMES if flags[name]))
        return ModelOutput(risk_permille=risk,
                           aux_permille={name: 1000 if flags[name] else 0 for name in FLAG_NAMES})


def build_model(settings: Any) -> HeuristicModel:
    return HeuristicModel()


def build_extractors(settings: Any) -> HeuristicExtractor:
    return HeuristicExtractor()
