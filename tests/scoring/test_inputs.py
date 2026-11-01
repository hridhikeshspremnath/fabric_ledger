"""Validation, registry resolution, hash checks and in-memory archive reading."""
import pytest

from attesta.scoring.errors import ArchiveError, FetchError, InvalidTarget
from attesta.scoring.fetch import DEFAULT_HOSTS, check_url
from attesta.scoring.registry import fetch_artifact
from attesta.scoring.source import Limits, read_archive
from attesta.scoring.validate import validate_target
from tests.scoring.helpers import FakeFetcher, make_targz, make_zip


@pytest.mark.parametrize("eco,pkg,ver", [
    ("pypi", "requests", "2.31.0"), ("pypi", "Foo_Bar.baz", "1.0"), ("npm", "left-pad", "1.3.0"),
    ("npm", "@scope/pkg", "2.0.0-beta.1"),
])
def test_valid_targets(eco, pkg, ver):
    assert validate_target(eco, pkg, ver).version == ver


@pytest.mark.parametrize("eco,pkg,ver", [
    ("gem", "x", "1.0"), ("pypi", "../etc/passwd", "1.0"), ("pypi", "a b", "1.0"),
    ("npm", "UPPER", "1.0.0"), ("npm", "a/b", "1.0.0"), ("npm", "ok", "1.0/../x"),
    ("npm", "ok", "1!2.0"), ("pypi", "x" * 300, "1.0"), ("pypi", "ok", ""), ("npm", "ok", "v1;rm"),
])
def test_invalid_targets(eco, pkg, ver):
    with pytest.raises(InvalidTarget):
        validate_target(eco, pkg, ver)


def test_pypi_names_are_normalised():
    assert validate_target("pypi", "Foo_Bar.baz", "1.0").package == "foo-bar-baz"


def test_url_allowlist():
    check_url("https://files.pythonhosted.org/x", DEFAULT_HOSTS)
    for bad in ("http://pypi.org/x", "https://evil.example.org/x", "file:///etc/passwd"):
        with pytest.raises(FetchError):
            check_url(bad, DEFAULT_HOSTS)


def test_pypi_prefers_sdist_and_verifies_sha256():
    fetcher, archive = FakeFetcher(), make_targz({"p-1/setup.py": "x"})
    url = fetcher.add_pypi("p", "1.0", archive)
    artifact = fetch_artifact(fetcher, validate_target("pypi", "p", "1.0"), 10_000)
    assert artifact.data == archive and url in fetcher.requests
    assert artifact.filename.endswith(".tar.gz")  # not the wheel


def test_hash_mismatch_is_rejected():
    fetcher = FakeFetcher()
    fetcher.add_pypi("p", "1.0", make_targz({"a.py": "x"}), sha256="f" * 64)
    with pytest.raises(FetchError, match="mismatch"):
        fetch_artifact(fetcher, validate_target("pypi", "p", "1.0"), 10_000)


def test_npm_scoped_package_and_integrity():
    fetcher = FakeFetcher()
    fetcher.add_npm("@scope/pkg", "1.0.0", make_targz({"package/package.json": "{}"}))
    artifact = fetch_artifact(fetcher, validate_target("npm", "@scope/pkg", "1.0.0"), 10_000)
    assert artifact.filename.endswith(".tgz")
    assert any("%2F" in url for url in fetcher.requests)  # scope slash encoded in the API URL

    bad = FakeFetcher()
    bad.add_npm("pkg", "1.0.0", make_targz({"a.js": "x"}), integrity="sha512-" + "AAAA" * 22 + "AA==")
    with pytest.raises(FetchError, match="mismatch"):
        fetch_artifact(bad, validate_target("npm", "pkg", "1.0.0"), 10_000)


def test_download_cap_and_foreign_host_are_rejected():
    fetcher = FakeFetcher()
    fetcher.add_pypi("p", "1.0", make_targz({"a.py": "x" * 5000}))
    with pytest.raises(FetchError, match="exceeds"):
        fetch_artifact(fetcher, validate_target("pypi", "p", "1.0"), 10)
    foreign = FakeFetcher()
    foreign.add_pypi("q", "1.0", make_targz({"a.py": "x"}), host="evil.example.org")
    with pytest.raises(FetchError, match="not allowed"):
        fetch_artifact(foreign, validate_target("pypi", "q", "1.0"), 10_000)


def test_tar_reading_keeps_only_candidate_regular_files():
    data = make_targz({"p/setup.py": "print(1)", "p/readme.md": "doc", "p/a.js": "x", "p/img.png": "zz"},
                      symlinks={"p/evil.py": "/etc/passwd"})
    bundle = read_archive(data, "p.tar.gz", Limits())
    assert sorted(bundle.files) == ["p/a.js", "p/setup.py"]
    assert bundle.total_entries == 5 and not bundle.truncated


def test_zip_reading_and_oversize_files():
    data = make_zip({"p/__init__.py": "ok", "p/big.py": "x" * 5000})
    bundle = read_archive(data, "p.whl", Limits(max_file_bytes=1000))
    assert list(bundle.files) == ["p/__init__.py"] and bundle.truncated


def test_archive_budgets_stop_a_bomb():
    data = make_targz({f"p/f{i}.py": "x" * 100 for i in range(50)})
    assert read_archive(data, "p.tgz", Limits(max_files=5)).scanned_files == 5
    capped = read_archive(data, "p.tgz", Limits(max_uncompressed_bytes=1000))
    assert capped.truncated and capped.scanned_files < 50


def test_bad_archives_raise_archive_error():
    with pytest.raises(ArchiveError):
        read_archive(b"not an archive", "p.tar.gz", Limits())
    with pytest.raises(ArchiveError):
        read_archive(b"not a zip", "p.whl", Limits())
    with pytest.raises(ArchiveError, match="unsupported"):
        read_archive(b"", "p.rar", Limits())
