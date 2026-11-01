"""Resolve (ecosystem, package, version) to a downloadable artifact and verify its hash."""
import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote

from attesta.scoring.errors import FetchError
from attesta.scoring.fetch import Fetcher, check_url, DEFAULT_HOSTS
from attesta.scoring.validate import Target


@dataclass(frozen=True)
class ArtifactRef:
    url: str
    filename: str
    expected: Optional[tuple[str, str]]  # (hash algorithm, lowercase hex) from the registry


@dataclass(frozen=True)
class Artifact:
    data: bytes
    filename: str
    sha256_hex: str


def resolve_pypi(fetcher: Fetcher, target: Target) -> ArtifactRef:
    meta = fetcher.get_json(f"https://pypi.org/pypi/{quote(target.package)}/{quote(target.version)}/json")
    files: list[dict[str, Any]] = meta.get("urls") or []
    if not files:
        raise FetchError(f"no files published for {target.label()}")
    chosen = next((f for f in files if f.get("packagetype") == "sdist"), files[0])  # prefer source
    digest = (chosen.get("digests") or {}).get("sha256")
    return ArtifactRef(chosen["url"], chosen["filename"], ("sha256", digest) if digest else None)


def _npm_expected(dist: dict[str, Any]) -> Optional[tuple[str, str]]:
    for token in str(dist.get("integrity", "")).split():
        if token.startswith("sha512-"):
            return "sha512", base64.b64decode(token[7:]).hex()
    shasum = dist.get("shasum")
    return ("sha1", shasum.lower()) if shasum else None


def resolve_npm(fetcher: Fetcher, target: Target) -> ArtifactRef:
    meta = fetcher.get_json(
        f"https://registry.npmjs.org/{target.package.replace('/', '%2F')}/{quote(target.version)}")
    dist = meta.get("dist") or {}
    tarball = dist.get("tarball")
    if not tarball:
        raise FetchError(f"no tarball published for {target.label()}")
    return ArtifactRef(tarball, tarball.rsplit("/", 1)[-1], _npm_expected(dist))


def fetch_artifact(fetcher: Fetcher, target: Target, max_bytes: int,
                   hosts: frozenset[str] = DEFAULT_HOSTS) -> Artifact:
    ref = resolve_pypi(fetcher, target) if target.ecosystem == "pypi" else resolve_npm(fetcher, target)
    check_url(ref.url, hosts)
    data = fetcher.get_bytes(ref.url, max_bytes)
    if ref.expected:
        algo, want = ref.expected
        if hashlib.new(algo, data).hexdigest() != want:
            raise FetchError(f"{algo} mismatch for {ref.filename}: registry and download disagree")
    return Artifact(data=data, filename=ref.filename, sha256_hex=hashlib.sha256(data).hexdigest())
