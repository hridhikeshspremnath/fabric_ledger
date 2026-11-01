"""Strict input validation. Names end up in URLs and in TrustRecord fields, so
only characters that both allow are accepted (this rejects npm `~` and PyPI epochs `!`)."""
import re
from dataclasses import dataclass

from attesta.scoring.errors import InvalidTarget

ECOSYSTEMS = ("pypi", "npm")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,212}[A-Za-z0-9])?$")
_NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]{0,213}/)?[a-z0-9][a-z0-9._-]{0,213}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


@dataclass(frozen=True)
class Target:
    ecosystem: str
    package: str
    version: str

    def label(self) -> str:
        return f"{self.ecosystem}:{self.package}@{self.version}"


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_target(ecosystem: str, package: str, version: str) -> Target:
    if ecosystem not in ECOSYSTEMS:
        raise InvalidTarget(f"unsupported ecosystem: {ecosystem!r} (use one of {ECOSYSTEMS})")
    name_re = _PYPI_NAME if ecosystem == "pypi" else _NPM_NAME
    if not name_re.match(package) or len(package) > 214:
        raise InvalidTarget(f"invalid {ecosystem} package name: {package!r}")
    if not _VERSION.match(version):
        raise InvalidTarget(f"invalid version: {version!r}")
    return Target(ecosystem, normalize_pypi(package) if ecosystem == "pypi" else package, version)
