#!/usr/bin/env bash
# Presentation demo: shows each INPUT (the command) and its OUTPUT.
# Run inside the activated venv:  source .venv/bin/activate && scripts/demo.sh
# Needs network for the real-package steps only (PyPI, a few KB).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

KEY="${ATTESTA_SCORING_SCORER_KEY_PATH:-$HOME/keys/scorer-dev-1.key}"
export ATTESTA_SCORING_SCORER_KEY_PATH="$KEY"
export ATTESTA_SCORING_POLICY_PATH="${ATTESTA_SCORING_POLICY_PATH:-config/policy.yaml}"
[[ -f "$KEY" ]] || python -m attesta.tools.gen_scorer_key --out-dir "$(dirname "$KEY")" >/dev/null

SCORE=(python -m attesta.scoring --config config/scoring.yaml score)
ATTEST=(env ATTESTA_SCORING_ATTESTATION_MODE=static
        "ATTESTA_SCORING_ATTESTATION_DIGEST=sha256:$(printf 'a%.0s' {1..64})")

section() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
show() {  # print the command (INPUT), run it (OUTPUT), print the exit code
    printf '\n\033[36m$ %s\033[0m\n' "$*"
    "$@"
    printf '\033[2m[exit code %s]\033[0m\n' "$?"
}

section "1. A real package from PyPI (downloaded in memory, never installed)"
show "${SCORE[@]}" pypi six 1.16.0 --dry-run
echo "-> REVIEW, not ALLOW: the runner is not attested, so the policy downgrades ALLOW."

section "2. Same package with a verified runner attestation (dev setting), full JSON"
show "${ATTEST[@]}" "${SCORE[@]}" pypi six 1.16.0 --dry-run --json

section "3. Clean vs malicious vs invalid (offline, made-up packages)"
show env PYTHONPATH=src:. python docs/examples/offline_demo.py

section "4. Bad input is rejected before any download"
show "${SCORE[@]}" pypi "../etc/passwd" 1.0 --dry-run

section "5. Automated tests (signature, policy, gateway, mTLS, CI gate)"
show python -m pytest -q -p no:cacheprovider tests/scoring tests/unit
