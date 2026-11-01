import json

import pytest

from attesta.scoring.errors import ConfigError
from attesta.scoring.extractors import HeuristicExtractor
from attesta.scoring.model import (
    FLAG_NAMES, ModelOutput, hash_files, load_factory, to_permille)
from attesta.scoring.reference import HeuristicModel
from attesta.scoring.source import SourceBundle


def bundle(**files: str) -> SourceBundle:
    return SourceBundle(filename="x.tgz", files={k.replace("__", "/"): v.encode() for k, v in files.items()})


def test_extractor_flags_and_evidence():
    b = bundle(setup_py="", pkg__net_py="import urllib.request\nurllib.request.urlopen(u)",
               pkg__spawn_py="import subprocess\nsubprocess.run(['ls'])",
               pkg__obf_py="import base64\nexec(base64.b64decode(x))",
               pkg__cred_py="open('/home/u/.ssh/id_rsa')")
    b.files["setup.py"] = b"from setuptools import setup\nsetup(cmdclass={'install': X})"
    result = HeuristicExtractor().extract(b)
    assert result.flags["flag_network"] and result.flags["flag_process_spawn"]
    assert result.flags["flag_obfuscation"] and result.flags["flag_cred_access"]
    assert result.flags["flag_install_exec"] and "py.setup.cmdclass" in result.hits["flag_install_exec"]


def test_clean_package_has_no_flags_and_npm_install_script_is_detected():
    clean = HeuristicExtractor().extract(bundle(pkg__ok_py="def f():\n    return 1\n"))
    assert not any(clean.flags.values())
    hooked = SourceBundle("x.tgz", {"package/package.json": json.dumps(
        {"scripts": {"postinstall": "node x.js"}}).encode()})
    assert HeuristicExtractor().extract(hooked).flags["flag_install_exec"]


def test_reference_model_scores_with_integers_only():
    out = HeuristicModel().predict(bundle(pkg__net_py="requests.get(u)"))
    assert isinstance(out.risk_permille, int) and out.risk_permille == 150
    assert all(isinstance(v, int) for v in out.aux_permille.values())


def test_model_output_validation():
    aux = {name: 0 for name in FLAG_NAMES}
    ModelOutput(0, aux)
    with pytest.raises(ValueError):
        ModelOutput(1001, aux)
    with pytest.raises(ValueError):
        ModelOutput(5, {"flag_network": 0})
    with pytest.raises(ValueError):
        ModelOutput(5, {**aux, "flag_network": 0.5})  # type: ignore[dict-item]


def test_to_permille_clamps_and_rounds_deterministically():
    assert [to_permille(p) for p in (-1.0, 0.0, 0.1234, 0.9996, 1.5)] == [0, 0, 123, 1000, 1000]
    assert to_permille(0.0005) == 0 and to_permille(0.0015) == 2  # half-even


def test_load_factory(tmp_path):
    assert isinstance(load_factory("attesta.scoring.reference:build_model", None), HeuristicModel)
    for bad in ("nocolon", "no.such.module:f", "attesta.scoring.reference:nope"):
        with pytest.raises(ConfigError):
            load_factory(bad, None)


def test_hash_files_is_order_independent(tmp_path):
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    a.write_bytes(b"1")
    b.write_bytes(b"2")
    assert hash_files([a, b]) == hash_files([b, a]) and hash_files([a]) != hash_files([a, b])
