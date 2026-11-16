"""Read candidate source files out of a downloaded archive, entirely in memory.

Nothing is extracted to disk, installed or executed. Only regular files with
scannable extensions are read, with per-file, per-archive and total-size caps.
"""
import io
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field

from attesta.scoring.errors import ArchiveError

_TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".json", ".sh", ".bat", ".cmd", ".ps1",
             ".toml", ".cfg", ".ini"}
_TEXT_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "package.json", "install",
               "preinstall", "postinstall", "makefile"}
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
_ZIP_SUFFIXES = (".zip", ".whl", ".egg")


@dataclass(frozen=True)
class Limits:
    max_files: int = 5000
    max_file_bytes: int = 1024 * 1024
    max_scanned_bytes: int = 20 * 1024 * 1024
    max_uncompressed_bytes: int = 200 * 1024 * 1024


@dataclass
class SourceBundle:
    filename: str
    files: dict[str, bytes] = field(default_factory=dict)
    total_entries: int = 0
    scanned_bytes: int = 0
    truncated: bool = False
    # Filled in by the service so a model adapter can run its own (training-time)
    # preprocessing on the exact archive that was downloaded.
    data: bytes = b""
    ecosystem: str = ""
    package: str = ""
    version: str = ""

    @property
    def scanned_files(self) -> int:
        return len(self.files)


def _wanted(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    dot = name.rfind(".")
    return name in _TEXT_NAMES or (dot >= 0 and name[dot:] in _TEXT_EXT)


class _Budget:
    """Tracks limits while an archive is walked."""

    def __init__(self, limits: Limits, bundle: SourceBundle) -> None:
        self.limits, self.bundle, self.seen = limits, bundle, 0

    def exhausted(self) -> bool:
        b, lim = self.bundle, self.limits
        return (b.scanned_files >= lim.max_files or b.scanned_bytes >= lim.max_scanned_bytes
                or self.seen >= lim.max_uncompressed_bytes)

    def see(self, size: int) -> None:
        self.seen += max(size, 0)

    def add(self, path: str, content: bytes) -> None:
        self.bundle.files[path] = content
        self.bundle.scanned_bytes += len(content)


def _read_tar(data: bytes, bundle: SourceBundle, limits: Limits) -> None:
    budget = _Budget(limits, bundle)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for member in tar:
            bundle.total_entries += 1
            budget.see(member.size)
            if budget.exhausted():
                bundle.truncated = True
                return
            if not member.isreg() or not _wanted(member.name):
                continue  # skips symlinks, hardlinks, devices, directories
            if member.size > limits.max_file_bytes:
                bundle.truncated = True
                continue
            handle = tar.extractfile(member)
            if handle is not None:
                budget.add(member.name, handle.read(limits.max_file_bytes + 1)[: limits.max_file_bytes])


def _read_zip(data: bytes, bundle: SourceBundle, limits: Limits) -> None:
    budget = _Budget(limits, bundle)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            bundle.total_entries += 1
            budget.see(info.file_size)
            if budget.exhausted():
                bundle.truncated = True
                return
            if info.is_dir() or not _wanted(info.filename):
                continue
            if info.file_size > limits.max_file_bytes:
                bundle.truncated = True
                continue
            with archive.open(info) as handle:
                content = handle.read(limits.max_file_bytes + 1)  # declared sizes can lie
            if len(content) > limits.max_file_bytes:
                bundle.truncated = True
                continue
            budget.add(info.filename, content)


def read_archive(data: bytes, filename: str, limits: Limits) -> SourceBundle:
    bundle = SourceBundle(filename=filename)
    lower = filename.lower()
    try:
        if lower.endswith(_TAR_SUFFIXES):
            _read_tar(data, bundle, limits)
        elif lower.endswith(_ZIP_SUFFIXES):
            _read_zip(data, bundle, limits)
        else:
            raise ArchiveError(f"unsupported archive type: {filename}")
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, zlib.error, OSError) as exc:
        raise ArchiveError(f"cannot read {filename}: {exc}") from exc
    return bundle
