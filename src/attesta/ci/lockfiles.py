"""Parse dependency lockfiles. Stdlib only."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

NPM_REGISTRY = "https://registry.npmjs.org/"
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+-]+)\s*$")


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    name: str
    version: str

    def label(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


def _npm_name(key: str, meta: dict[str, Any]) -> str:
    return str(meta.get("name") or key.rsplit("node_modules/", 1)[-1])


def _walk_v1(deps: dict[str, Any], include_dev: bool, out: dict[Dep, None], skipped: list[str]) -> None:
    for name, meta in deps.items():
        version, resolved = meta.get("version"), str(meta.get("resolved", ""))
        if meta.get("dev") and not include_dev:
            continue
        if not version or (resolved and not resolved.startswith(NPM_REGISTRY)):
            skipped.append(f"npm:{name} (not a registry package)")
        else:
            out[Dep("npm", name, version)] = None
        _walk_v1(meta.get("dependencies") or {}, include_dev, out, skipped)


def parse_package_lock(text: str, include_dev: bool = True) -> tuple[list[Dep], list[str]]:
    data = json.loads(text)
    found: dict[Dep, None] = {}
    skipped: list[str] = []
    if "packages" in data:  # lockfileVersion 2 and 3
        for key, meta in data["packages"].items():
            if key == "" or meta.get("link"):
                continue
            if meta.get("dev") and not include_dev:
                continue
            name, version, resolved = _npm_name(key, meta), meta.get("version"), str(meta.get("resolved", ""))
            if not version or (resolved and not resolved.startswith(NPM_REGISTRY)):
                skipped.append(f"npm:{name} (not a registry package)")
            else:
                found[Dep("npm", name, version)] = None
    else:  # lockfileVersion 1
        _walk_v1(data.get("dependencies") or {}, include_dev, found, skipped)
    return list(found), sorted(set(skipped))


def parse_requirements(text: str) -> tuple[list[Dep], list[str]]:
    found: dict[Dep, None] = {}
    skipped: list[str] = []
    for raw in re.sub(r"\\\r?\n", " ", text).splitlines():  # join backslash continuations
        line = re.sub(r"\s+#.*$", "", raw).split(";")[0].replace("\\", "").strip()
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-") or "://" in line or " @ " in line:
            skipped.append(f"{line} (option, URL or VCS requirement)")
            continue
        match = _REQ.match(line)
        if not match:
            skipped.append(f"{line} (not pinned with ==)")
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        found[Dep("pypi", name, match.group(3))] = None
    return list(found), skipped
