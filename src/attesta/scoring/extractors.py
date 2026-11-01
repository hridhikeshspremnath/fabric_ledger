"""Reference rule-based label extractors for the five aux flags.

These are deliberately simple regex heuristics (a baseline and a test double
for the real extractors). Plug the real ones in via `extractor_factory`.
"""
import json
import re

from attesta.scoring.model import FLAG_NAMES, ExtractorResult
from attesta.scoring.source import SourceBundle

_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")

_RULES: dict[str, dict[str, re.Pattern[str]]] = {
    "flag_install_exec": {
        "py.setup.cmdclass": re.compile(r"cmdclass\s*=", re.I),
        "py.setup.exec": re.compile(r"(os\.system|subprocess\.|exec\()"),
    },
    "flag_network": {
        "py.net": re.compile(r"(urllib\.request|http\.client|requests\.(get|post)|socket\.socket|urlopen\()"),
        "js.net": re.compile(r"(require\(['\"](https?|net|dgram)['\"]\)|\bfetch\(|XMLHttpRequest|axios)"),
    },
    "flag_cred_access": {
        "creds.files": re.compile(r"(\.ssh/|id_rsa|\.aws/credentials|\.npmrc|\.pypirc|\.netrc)"),
        "creds.env": re.compile(r"(GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET|PYPI_TOKEN)"),
    },
    "flag_obfuscation": {
        "obf.eval": re.compile(r"(\beval\(|\bexec\(compile|new Function\()"),
        "obf.b64": re.compile(r"(base64\.b64decode|atob\(|Buffer\.from\([^)]*['\"]base64['\"])"),
        "obf.charcode": re.compile(r"(String\.fromCharCode|\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,})"),
    },
    "flag_process_spawn": {
        "py.spawn": re.compile(r"(subprocess\.(run|Popen|call|check_output)|os\.(system|popen|exec[lv]p?))"),
        "js.spawn": re.compile(r"(child_process|execSync\(|spawnSync\(|\.spawn\()"),
    },
}
_LONG_LINE = 2000


def _npm_install_hook(files: dict[str, bytes]) -> bool:
    for path, content in files.items():
        if path.rsplit("/", 1)[-1] != "package.json":
            continue
        try:
            scripts = json.loads(content).get("scripts", {})
        except (ValueError, AttributeError):
            continue
        if isinstance(scripts, dict) and any(name in scripts for name in _INSTALL_SCRIPTS):
            return True
    return False


class HeuristicExtractor:
    version = "heuristic-1"

    def extract(self, bundle: SourceBundle) -> ExtractorResult:
        hits: dict[str, list[str]] = {name: [] for name in FLAG_NAMES}
        for path, content in bundle.files.items():
            text = content.decode("utf-8", errors="replace")
            for flag, rules in _RULES.items():
                if flag == "flag_install_exec" and not path.endswith("setup.py"):
                    continue  # python install hooks only matter in setup.py
                for rule_id, pattern in rules.items():
                    if pattern.search(text) and rule_id not in hits[flag]:
                        hits[flag].append(rule_id)
            if any(len(line) > _LONG_LINE and line.count(" ") < len(line) // 40
                   for line in text.splitlines()):
                hits["flag_obfuscation"].append("obf.long-line")
        if _npm_install_hook(bundle.files):
            hits["flag_install_exec"].append("npm.install-script")
        return ExtractorResult(
            flags={name: bool(hits[name]) for name in FLAG_NAMES},
            hits={name: tuple(sorted(set(hits[name]))) for name in FLAG_NAMES})
