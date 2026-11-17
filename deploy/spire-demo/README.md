# Attesta SPIRE demo (Docker Compose)

Trust domain `attesta.example.org`, SPIRE 1.15.3, `join_token` node attestation,
`unix` workload attestation. Independent of the WSL scripts in `/scripts`.

## Run (from WSL2 or Git Bash, in this folder)

    scripts/up.sh            # server -> bundle -> join token -> agent -> register
    scripts/health.sh        # server, agent, entries
    scripts/test-client.sh   # prints SPIFFE ID + cert SHA-256 per workload
    scripts/sizes.sh         # image sizes + memory
    scripts/down.sh          # stop (keeps CA/state); --purge wipes everything

## Workloads

| Service | SPIFFE ID | Selector |
|---|---|---|
| ci-runner | `spiffe://attesta.example.org/ci/build-runner` | `unix:uid:1001` |
| scoring-service | `spiffe://attesta.example.org/scoring-service` | `unix:uid:1002` |

Parent of both: `spiffe://attesta.example.org/agent/demo` (the join-token agent).
UIDs and IDs live in `.env.example` (copy to `.env` to override).

## How workload attestation works here

The agent's `unix` attestor identifies a caller by the PID it receives from
the socket (`SO_PEERCRED`), then reads `/proc/<pid>` for the UID. Containers
normally have separate PID namespaces, so that PID would be meaningless.
Therefore:

- Client services set `pid: "service:spire-agent"` so they share the agent's
  PID namespace; the PID the agent sees is the real one.
- The Workload API socket lives in the `agent-socket` named volume, mounted
  read-only into clients.
- Each client runs as a different `user:` UID (1001 / 1002), which is what the
  registration selectors match.
- Clients also get `network_mode: none`, read-only rootfs, `cap_drop: ALL`.

## Security notes (demo grade)

- Agent trust bootstrap uses the server bundle (`.runtime/bootstrap.crt`,
  gitignored), not `insecure_bootstrap`.
- The join token is one-time, 5 min TTL, passed by env only and never written
  to disk. It is visible in `docker inspect` of the agent while the stack
  exists. Fine for a demo; use a real node attestor in production.
- The test client writes the private key to a tmpfs scratch dir that is deleted
  on exit and never prints it. Only SPIFFE ID and cert SHA-256 are output.
- UID selectors prove only the UID, not the image or code. Production should
  use the `docker` attestor or k8s selectors.
- Do not run `docker compose up` directly (agent would start without a token);
  use `scripts/up.sh`.

## Gateway (mTLS) and demo submit

    scripts/gateway-up.sh    # build image, demo scorer key, register gateway entry, start gateway
    scripts/demo-submit.sh   # uid 1002 (scoring-service) submits one signed record

- Gateway: `spiffe://attesta.example.org/gateway`, uid 1003, port 8443 on the
  compose network only (not published). Server cert comes from py-spiffe's
  X509Source; the trust bundle is the client CA; peer SPIFFE ID is read from the
  URI SAN only. SVID is re-read every 5 min and hot-swapped.
- Writes require the scoring-service ID, a matching `caller_cert_sha256`, a valid
  Ed25519 signature from an active key in the registry, and a band/decision/
  policy_version that matches `config/policy.yaml`.
- Fallback: set `svid_fallback: true` in `config/gateway.yaml` (or `ATTESTA_SVID_FALLBACK=true`)
  to use `spire-agent api fetch x509` with a 20-minute refresh, only if X509Source fails to connect.
- Demo scorer key lives in `.runtime/` (gitignored, mode 644 for the demo only).
- Always use `--no-deps` (the scripts do) so the running agent is never recreated.

## Fabric backend, trained detector, dashboard

Fabric network and bridges: see `network/README.md` (steps 3-9). Then, with `.env`
copied from `.env.example` and the two optional paths set:

    scripts/score.sh pypi six 1.16.0   # score + sign + submit; prints tx id and block
    scripts/dashboard-up.sh            # http://127.0.0.1:3000/trust-ledger
    scripts/agent-reset.sh             # after a Docker/PC restart: bring everything back
    scripts/deploy-gate.sh sha256:<hex>   # exit 0 only if the ledger says this artifact may deploy

- Deploy gate (`attesta.tools.deploy_gate`): passes only when the latest effective
  decision for that exact digest is ALLOW (or one named in `--allow`) and no record for
  it is BLOCK. Unknown artifacts are refused. Exit 1 = refused, 2 = could not verify.
  It reads through the gateway (`GET /artifacts/{digest}`) as the CI runner identity.

- OPA evidence floors (`config/policy.rego`, tests: `opa test config/policy.rego config/policy_test.rego`):
  the scoring service and the gateway both ask the `opa` container for the least strict decision
  the evidence allows; the effective decision is max(score band, floor), so evidence can only make
  a decision stricter. The chaincode accepts a decision at least as strict as the band's, never
  weaker. If OPA is down, scoring and the gateway refuse (503), they do not fall back to bands.
  Set `ATTESTA_OPA_URL=` (empty) in `.env` to run on bands alone. After editing `policy.rego`,
  recreate OPA (`dc --profile gateway up -d --no-deps --force-recreate opa`): the file is bind-mounted.
  Chaincode changes need `docker build -t attesta-trust-cc:local chaincode/attesta-trust` and
  recreating the two chaincode containers (CCaaS: no lifecycle change).
- `ATTESTA_DL_DIR` (attesta_DL checkout): the scoring services use the trained CNN
  (`docker-compose.dl.yml`, image `attesta-spire-scorer-dl:local`) instead of the
  heuristic stand-in. Only code, configs, the `m2_noshort` checkpoint and the name
  index are mounted, read-only.
- `ATTESTA_DASHBOARD_DIR` (dashboard checkout): the dashboard runs as
  `spiffe://attesta.example.org/dashboard` (uid 1007) and reads the ledger through the
  gateway over mTLS (`docker-compose.dashboard.yml`). Published on localhost only.
- The scorer key in `.runtime/` must be the one registered on-chain by
  `network/scripts/05-seed.sh`. On-chain keys cannot be replaced, so a mismatch shows
  up as `422 ledger rejected the record`.
- After a restart the agent cannot rejoin (one-time join token, 1 h SVID, 24 h CA).
  `scripts/agent-reset.sh` drops only the agent's cache and restarts the workloads.
