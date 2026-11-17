"""GitHub Actions dependency scan: lockfiles -> scoring service -> annotations + exit code.

    python -m attesta.ci.scan --api-url https://scorer.example.org [--fail-on BLOCK]

Stdlib only. The bearer token is read from an environment variable, never argv.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional, Sequence

from attesta.ci.lockfiles import Dep, parse_package_lock, parse_requirements

SEVERITY = {"ALLOW": 0, "WARN": 1, "REVIEW": 2, "BLOCK": 3}
DEFAULT_PATHS = ("package-lock.json", "requirements.txt")


class ScanError(Exception):
    """A dependency could not be scored."""


def gh_escape(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotate(level: str, title: str, message: str) -> None:
    print(f"::{level} title={gh_escape(title)}::{gh_escape(message)}")


def fetch_oidc_token(audience: str, timeout: float = 15.0) -> str:
    """This job's GitHub OIDC token for `audience`, or "" when the job did not grant
    `permissions: id-token: write` (the scorer then treats the run as unattested)."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not url or not bearer:
        return ""
    request = urllib.request.Request(
        url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(audience),
        headers={"Authorization": f"Bearer {bearer}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return str(json.loads(response.read()).get("value", ""))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return ""  # fall back to unattested rather than failing the scan


def score_dep(api_url: str, token: str, dep: Dep, run_id: str, timeout: float,
              retries: int = 2, oidc_audience: str = "") -> dict[str, Any]:
    body = json.dumps({"ecosystem": dep.ecosystem, "package": dep.name,
                       "version": dep.version, "run_id": run_id}).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if oidc_audience and (oidc := fetch_oidc_token(oidc_audience)):  # fresh per dependency: tokens are short-lived
        headers["X-Attesta-OIDC"] = oidc
    request = urllib.request.Request(
        api_url.rstrip("/") + "/v1/score", data=body, method="POST", headers=headers)
    last = "unknown error"
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read(300).decode('utf-8', 'replace')}"
            if exc.code < 500:
                break  # client errors will not improve on retry
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last = str(exc)
        time.sleep(min(2 ** attempt, 5))
    raise ScanError(last)


def load_deps(paths: Sequence[str], include_dev: bool) -> tuple[list[Dep], list[str]]:
    deps: dict[Dep, None] = {}
    skipped: list[str] = []
    for path in paths:
        file = Path(path)
        if not file.is_file():
            continue
        text = file.read_text(encoding="utf-8")
        if file.name == "package-lock.json":
            found, skip = parse_package_lock(text, include_dev)
        elif file.name.endswith(".txt"):
            found, skip = parse_requirements(text)
        else:
            skipped.append(f"{path} (unsupported file)")
            continue
        deps.update(dict.fromkeys(found))
        skipped.extend(f"{path}: {item}" for item in skip)
    return list(deps), skipped


def report(dep: Dep, result: dict[str, Any]) -> None:
    decision = result["decision"]
    flags = ",".join(k.removeprefix("flag_") for k, v in result.get("flags", {}).items() if v) or "-"
    text = (f"{dep.label()} score={result['risk_score']} band={result['risk_band']} "
            f"flags={flags} record={result['record_id']}")
    if decision == "BLOCK":
        annotate("error", "Attesta BLOCK", text)
    elif decision in ("REVIEW", "WARN"):
        annotate("warning", f"Attesta {decision}", text)
    else:
        print(f"ok     {text}")


def write_summary(rows: list[tuple[Dep, Optional[dict[str, Any]], str]]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["| Dependency | Decision | Score (permille) | Flags |", "|---|---|---|---|"]
    for dep, result, error in rows:
        if result is None:
            lines.append(f"| `{dep.label()}` | ERROR | - | {error[:80]} |")
            continue
        flags = ", ".join(k.removeprefix("flag_") for k, v in result["flags"].items() if v) or "-"
        lines.append(f"| `{dep.label()}` | {result['decision']} | {result['risk_score']} | {flags} |")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def run(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    if not token:
        print(f"ERROR: environment variable {args.token_env} (API token) is empty", file=sys.stderr)
        return 2
    deps, skipped = load_deps(args.paths, args.include_dev)
    for item in skipped:
        annotate("notice", "Attesta skipped", item)
    if not deps:
        print("no scorable dependencies found")
        return 0
    if len(deps) > args.max_deps:
        annotate("warning", "Attesta limit", f"scanning first {args.max_deps} of {len(deps)} dependencies")
        deps = deps[: args.max_deps]

    run_id = os.environ.get("GITHUB_RUN_ID", "ci")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [(dep, pool.submit(score_dep, args.api_url, token, dep, run_id, args.timeout,
                                     oidc_audience=args.oidc_audience))
                   for dep in deps]
    rows: list[tuple[Dep, Optional[dict[str, Any]], str]] = []
    worst, errors = 0, 0
    for dep, future in futures:
        try:
            result = future.result()
        except ScanError as exc:
            errors += 1
            rows.append((dep, None, str(exc)))
            annotate("error" if args.on_error == "fail" else "warning", "Attesta error",
                     f"{dep.label()}: {exc}")
            continue
        rows.append((dep, result, ""))
        report(dep, result)
        worst = max(worst, SEVERITY.get(result["decision"], 3))  # unknown decisions count as BLOCK
    write_summary(rows)

    print(f"scanned {len(deps)} dependencies: {errors} errors, worst decision "
          f"{[k for k, v in SEVERITY.items() if v == worst][0]}")
    if worst >= SEVERITY[args.fail_on]:
        return 1
    return 1 if errors and args.on_error == "fail" else 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--token-env", default="ATTESTA_API_TOKEN")
    parser.add_argument("--paths", nargs="*", default=list(DEFAULT_PATHS))
    parser.add_argument("--fail-on", choices=["WARN", "REVIEW", "BLOCK"], default="BLOCK")
    parser.add_argument("--on-error", choices=["fail", "warn"], default="fail")
    parser.add_argument("--include-dev", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--max-deps", type=int, default=300)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--oidc-audience", default="attesta",
                        help="audience for the GitHub OIDC token sent as runner attestation; "
                             "empty disables it")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
