# Scoring service and CI step

```
CI (GitHub-hosted runner)                 your host (SPIRE + gateway)
 attesta-scan action ──HTTPS+bearer──►  scorer (uid 1002, SVID .../scoring-service)
  parses lockfiles                        1. validate (ecosystem, package, version)
  fails on BLOCK                          2. download from PyPI/npm, in memory, hash-checked
                                          3. read source files from the archive (never installed)
                                          4. label extractors + exported model -> integer permille
                                          5. build TrustRecord, sign Ed25519 (key outside repo)
                                          6. POST /records to the gateway over SPIFFE mTLS
```

## Safety properties
- **Download only.** Archives are opened with `tarfile`/`zipfile` from a `BytesIO`; nothing is
  extracted to disk, installed or executed. Per-file, per-archive and total-size caps apply,
  symlinks/devices are skipped, and only scannable extensions are read.
- **Fetch hardening.** HTTPS only, host allowlist (`pypi.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`) including redirects, registry hash verified (PyPI sha256, npm sha512/sha1).
- **No floats.** Model adapters convert to integer permille (`to_permille`); `ModelOutput` rejects anything else.
- **Key hygiene.** The scorer key path must be outside any git work tree (`allow_key_in_repo` is a dev escape).
- **Identity.** At startup the service checks its own SVID is `.../scoring-service`; the gateway also
  checks `caller_cert_sha256` against the mTLS certificate (one retry covers SVID rotation).
- **Runner attestation.** `attestation_mode: none` (default) leaves records unattested, so the policy
  downgrades ALLOW/WARN to REVIEW. `attestation_mode: github-oidc` verifies the CI job's GitHub OIDC
  token (header `X-Attesta-OIDC`): RS256 signature against GitHub's published keys (algorithm pinned),
  issuer, audience (`attestation_audience`, default `attesta`), expiry, and `repository` on the
  `attestation_repos` allow-list (comma-separated `owner/name`). Only then is the record attested, with
  `node_attestor=github-oidc`, `runner_class` from the token's `runner_environment`, and
  `attestation_digest` = hash of the verified run claims (no actor or email). A bad or expired token is a
  401, not a silent downgrade; no token means unattested. The CI action requests the token itself when
  the job has `permissions: id-token: write`. Limits: the gateway and chaincode trust the scorer's signed
  `attestation_verified` flag, they do not see the token; and this proves which repository's workflow
  ran, not that its code is trustworthy.

## Plugging in the exported model
Set in `config/scoring.yaml`:
```yaml
model_factory: my_pkg.export:build_model         # (settings) -> ScoringModel
extractor_factory: my_pkg.labels:build_extractors  # (settings) -> LabelExtractor
```
`ScoringModel` has `version_hash` ("sha256:..." of weights + preprocessing; see `hash_files`) and
`predict(bundle) -> ModelOutput(risk_permille, aux_permille{5 heads})`. `LabelExtractor` has `version`
and `extract(bundle) -> ExtractorResult(flags, hits)`. A flag is set when the extractor labels it **or** its
aux head is at least `aux_threshold_permille`. The built-in heuristic model/extractors are stand-ins.

### The trained detector (attesta_DL)
`attesta_DL/src/infer/attesta_adapter.py` provides both factories for the trained CNN
(`m2_noshort` by default; `model_path` picks another checkpoint directory). The service puts the
downloaded archive and package identity on the bundle (`bundle.data`, `.ecosystem`, `.package`,
`.version`), so the adapter runs the same preprocessing as training. In the SPIRE demo, set
`ATTESTA_DL_DIR` in `deploy/spire-demo/.env`; `scripts/score.sh` and `scorer-up.sh` then use it.

## Commands (WSL2, `export DOCKER_CONFIG=~/.docker-nocreds` if your credential helper is missing)
```bash
# tests (no network, no containers)
pytest tests/scoring
# local dry run of the CLI (needs a signing key outside the repo and config/scoring.yaml paths)
ATTESTA_SCORING_SCORER_KEY_PATH=~/keys/scorer.key ATTESTA_SCORING_POLICY_PATH=config/policy.yaml \
  attesta --config config/scoring.yaml score pypi requests 2.31.0 --dry-run
# in the SPIRE demo (rebuild the image so it contains attesta.scoring)
deploy/spire-demo/scripts/gateway-up.sh          # rebuilds image, registers entries, starts gateway
deploy/spire-demo/scripts/score.sh pypi requests 2.31.0
deploy/spire-demo/scripts/scorer-up.sh           # HTTP API on 127.0.0.1:8080, token in .runtime/scoring_token
```

## GitHub Actions
`.github/actions/attesta-scan` reads `package-lock.json` (v1/v2/v3) and pinned `requirements.txt`
entries, calls `POST /v1/score` per dependency, prints REVIEW/WARN as warnings, fails on BLOCK (or
`fail-on`), and fails closed when scoring errors (`on-error: warn` to relax). It is stdlib-only and
passes its inputs through environment variables. See `docs/examples/dependency-scan.yml`.
GitHub-hosted runners must be able to reach the scoring service over HTTPS (reverse proxy or tunnel
with TLS in front); the SPIFFE-authenticated hop stays between the scorer and the gateway.
