"""CLI:  attesta score <ecosystem> <package> <version>   |   attesta serve"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from attesta.scoring.errors import ScoringError
from attesta.scoring.settings import load_scoring_settings
from attesta.scoring.wiring import build_service

SEVERITY = {"ALLOW": 0, "WARN": 1, "REVIEW": 2, "BLOCK": 3}
EXIT_THRESHOLD = 10  # exit status when --fail-on is met


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attesta", description=__doc__)
    parser.add_argument("--config", type=Path, default=None, help="scoring.yaml path")
    sub = parser.add_subparsers(dest="command", required=True)

    score = sub.add_parser("score", help="score one package and submit the TrustRecord")
    score.add_argument("ecosystem", choices=["pypi", "npm"])
    score.add_argument("package")
    score.add_argument("version")
    score.add_argument("--dry-run", action="store_true", help="score and sign but do not submit")
    score.add_argument("--json", action="store_true", help="print the full JSON summary")
    score.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    score.add_argument("--fail-on", choices=list(SEVERITY), default=None,
                       help=f"exit {EXIT_THRESHOLD} if the decision is at least this severe")

    serve = sub.add_parser("serve", help="run the HTTP API used by CI")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--tls-cert", type=Path, default=None)
    serve.add_argument("--tls-key", type=Path, default=None)
    return parser


def _score(args: argparse.Namespace) -> int:
    settings = load_scoring_settings(args.config)
    service = build_service(settings, dry_run_only=args.dry_run)
    result = service.score(args.ecosystem, args.package, args.version,
                           run_hint=args.run_id, dry_run=args.dry_run)
    summary = result.summary()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        flags = ",".join(k.removeprefix("flag_") for k, v in summary["flags"].items() if v) or "-"
        where = "dry-run" if args.dry_run else ("cached" if summary["cached"] else "submitted")
        print(f"{args.ecosystem}:{args.package}@{args.version} score={summary['risk_score']}permille "
              f"band={summary['risk_band']} decision={summary['decision']} flags={flags} "
              f"record={summary['record_id']} ({where})")
    if args.fail_on and SEVERITY[summary["decision"]] >= SEVERITY[args.fail_on]:
        return EXIT_THRESHOLD
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from attesta.scoring.api import create_api

    settings = load_scoring_settings(args.config)
    token = os.environ.get(settings.api_token_env, "")
    if not token:
        print(f"ERROR: set {settings.api_token_env} (the CI bearer token)", file=sys.stderr)
        return 1
    app = create_api(build_service(settings), token)
    uvicorn.run(app, host=args.host or settings.api_host, port=args.port or settings.api_port,
                ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
                ssl_keyfile=str(args.tls_key) if args.tls_key else None)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _score(args) if args.command == "score" else _serve(args)
    except ScoringError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
