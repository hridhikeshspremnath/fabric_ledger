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

## Out of scope

FabricBackend (stub only), real scorer, dashboard UI.
