"""Fakes for the scoring tests: a tiny model, an offline registry, an in-memory gateway client."""
import base64
import hashlib
import io
import tarfile
import zipfile
from typing import Any, Optional, Union

from attesta.records.trust_record import TrustRecord
from attesta.scoring.attestation import Attestation
from attesta.scoring.errors import FetchError, SubmitError
from attesta.scoring.model import FLAG_NAMES, ModelOutput
from attesta.scoring.source import SourceBundle
from tests.conftest import SCORER_CERT

Content = Union[str, bytes]


def _b(content: Content) -> bytes:
    return content.encode() if isinstance(content, str) else content


def make_targz(files: dict[str, Content], symlinks: Optional[dict[str, str]] = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = _b(content)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buf.getvalue()


def make_zip(files: dict[str, Content]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, _b(content))
    return buf.getvalue()


class FakeModel:
    """Tiny deterministic model: risk grows with the number of scanned files; an aux head
    fires when a file path mentions the flag (e.g. 'network' in the file name)."""

    version_hash = "sha256:" + "11" * 32

    def __init__(self, risk: Optional[int] = None) -> None:
        self.risk, self.calls = risk, 0

    def predict(self, bundle: SourceBundle) -> ModelOutput:
        self.calls += 1
        risk = self.risk if self.risk is not None else min(1000, 40 * bundle.scanned_files)
        aux = {name: (900 if any(name.removeprefix("flag_") in path for path in bundle.files) else 0)
               for name in FLAG_NAMES}
        return ModelOutput(risk, aux)


class FixedAttestation:
    def __init__(self, verified: bool = True) -> None:
        self.verified = verified

    def get(self, credential=None) -> Attestation:
        return Attestation(self.verified, "sha256:" + "ee" * 32 if self.verified else None)


class FakeFetcher:
    """Offline PyPI/npm: URL -> JSON metadata or archive bytes."""

    def __init__(self) -> None:
        self.json: dict[str, Any] = {}
        self.blobs: dict[str, bytes] = {}
        self.requests: list[str] = []

    def get_json(self, url: str) -> Any:
        self.requests.append(url)
        if url not in self.json:
            raise FetchError(f"HTTP 404 for {url}")
        return self.json[url]

    def get_bytes(self, url: str, max_bytes: int) -> bytes:
        self.requests.append(url)
        if url not in self.blobs:
            raise FetchError(f"HTTP 404 for {url}")
        if len(self.blobs[url]) > max_bytes:
            raise FetchError(f"download exceeds {max_bytes} bytes")
        return self.blobs[url]

    def add_pypi(self, name: str, version: str, archive: bytes, filename: str = "pkg-1.0.0.tar.gz",
                 sha256: Optional[str] = None, host: str = "files.pythonhosted.org") -> str:
        url = f"https://{host}/packages/{filename}"
        digest = sha256 if sha256 is not None else hashlib.sha256(archive).hexdigest()
        self.json[f"https://pypi.org/pypi/{name}/{version}/json"] = {"urls": [
            {"packagetype": "bdist_wheel", "url": url + ".whl", "filename": filename + ".whl",
             "digests": {"sha256": "0" * 64}},
            {"packagetype": "sdist", "url": url, "filename": filename, "digests": {"sha256": digest}}]}
        self.blobs[url] = archive
        return url

    def add_npm(self, name: str, version: str, tarball: bytes, integrity: Optional[str] = None) -> str:
        url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        sri = integrity or "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        self.json[f"https://registry.npmjs.org/{name.replace('/', '%2F')}/{version}"] = {
            "dist": {"tarball": url, "integrity": sri}}
        self.blobs[url] = tarball
        return url


class FakeSubmitter:
    """Stands in for the gateway client; can force a cert-mismatch failure on the first call."""

    def __init__(self, cert: str = SCORER_CERT, mismatch_first: bool = False) -> None:
        self.cert, self.mismatch_first = cert, mismatch_first
        self.records: list[TrustRecord] = []

    def cert_sha256(self) -> str:
        return self.cert

    def submit(self, record: TrustRecord) -> dict[str, Any]:
        if self.mismatch_first and not self.records:
            self.records.append(record)
            raise SubmitError("gateway returned 403: caller_cert_sha256 != caller certificate")
        self.records.append(record)
        return {"sequence": len(self.records), "tx_id": None, "block_number": None,
                "record_hash": "ab" * 32}
