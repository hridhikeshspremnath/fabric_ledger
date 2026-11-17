import json

import pytest

from attesta.ci import scan
from attesta.ci.lockfiles import Dep, parse_package_lock, parse_requirements

LOCK_V3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
    "node_modules/@scope/pkg": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"},
    "node_modules/a/node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/devtool": {"version": "0.1.0", "dev": True},
    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git"},
    "node_modules/linked": {"resolved": "packages/linked", "link": True},
}})
LOCK_V1 = json.dumps({"lockfileVersion": 1, "dependencies": {
    "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
          "dependencies": {"b": {"version": "2.0.0", "dev": True}}}}})
REQS = """\
# comment
requests==2.31.0  # inline
Foo_Bar[extra]==1.0 ; python_version > "3.8"
flask>=2.0
-r other.txt
git+https://github.com/x/y.git
pkg @ https://example.org/pkg.whl
numpy==1.26.4 \\
    --hash=sha256:abc
"""


def test_package_lock_v3_dedupes_and_skips_unscorable():
    deps, skipped = parse_package_lock(LOCK_V3)
    assert set(deps) == {Dep("npm", "left-pad", "1.3.0"), Dep("npm", "@scope/pkg", "2.0.0"),
                         Dep("npm", "devtool", "0.1.0")}
    assert any("gitdep" in s for s in skipped)
    no_dev, _ = parse_package_lock(LOCK_V3, include_dev=False)
    assert Dep("npm", "devtool", "0.1.0") not in no_dev


def test_package_lock_v1_nested():
    deps, _ = parse_package_lock(LOCK_V1)
    assert set(deps) == {Dep("npm", "a", "1.0.0"), Dep("npm", "b", "2.0.0")}
    assert parse_package_lock(LOCK_V1, include_dev=False)[0] == [Dep("npm", "a", "1.0.0")]


def test_requirements_pins_only():
    deps, skipped = parse_requirements(REQS)
    assert set(deps) == {Dep("pypi", "requests", "2.31.0"), Dep("pypi", "foo-bar", "1.0"),
                         Dep("pypi", "numpy", "1.26.4")}
    assert len(skipped) == 4 and any("flask" in s for s in skipped)


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(LOCK_V1)
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ATTESTA_API_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    return tmp_path


def fake_scores(decisions):
    def score(api_url, token, dep, run_id, timeout, retries=2, oidc_audience=""):
        decision = decisions.get(dep.name, "ALLOW")
        if decision == "ERROR":
            raise scan.ScanError("HTTP 502: boom")
        return {"decision": decision, "risk_score": 100, "risk_band": "LOW", "record_id": "r-" + dep.name,
                "flags": {"flag_network": decision != "ALLOW"}}
    return score


def run(*extra):
    return scan.main(["--api-url", "https://scorer.example.org", *extra])


def test_block_fails_the_build_and_prints_annotations(project, monkeypatch, capsys):
    monkeypatch.setattr(scan, "score_dep", fake_scores({"a": "BLOCK", "b": "REVIEW", "requests": "WARN"}))
    assert run() == 1
    out = capsys.readouterr().out
    assert "::error title=Attesta BLOCK::npm:a@1.0.0" in out
    assert "::warning title=Attesta REVIEW::npm:b@2.0.0" in out
    assert "::warning title=Attesta WARN::pypi:requests@2.31.0" in out
    summary = (project / "summary.md").read_text()
    assert "| `npm:a@1.0.0` | BLOCK |" in summary


def test_review_and_warn_do_not_fail_by_default(project, monkeypatch, capsys):
    monkeypatch.setattr(scan, "score_dep", fake_scores({"a": "REVIEW", "requests": "WARN"}))
    assert run() == 0
    assert run("--fail-on", "REVIEW") == 1


def test_errors_fail_closed_unless_warn(project, monkeypatch, capsys):
    monkeypatch.setattr(scan, "score_dep", fake_scores({"a": "ERROR"}))
    assert run() == 1
    assert "::error title=Attesta error::npm:a@1.0.0" in capsys.readouterr().out
    assert run("--on-error", "warn") == 0


def test_missing_token_and_empty_projects(project, monkeypatch, capsys):
    monkeypatch.delenv("ATTESTA_API_TOKEN")
    assert run() == 2
    monkeypatch.setenv("ATTESTA_API_TOKEN", "tok")
    (project / "package-lock.json").unlink()
    (project / "requirements.txt").unlink()
    assert run() == 0 and "no scorable dependencies" in capsys.readouterr().out


def test_max_deps_limits_the_scan(project, monkeypatch, capsys):
    calls = []
    inner = fake_scores({})
    monkeypatch.setattr(scan, "score_dep", lambda *a, **k: (calls.append(a[2].name), inner(*a, **k))[1])
    assert run("--max-deps", "1") == 0
    assert len(calls) == 1 and "scanning first 1 of 3" in capsys.readouterr().out


def test_annotation_escaping():
    assert scan.gh_escape("a%b\nc\r") == "a%25b%0Ac%0D"
