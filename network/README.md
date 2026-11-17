# Attesta Fabric network (2.5.16, dev)

3 orgs (AttestaMSP, AuditorMSP, ReleaseMSP), 1 peer each (LevelDB), 1 Raft orderer
(batch timeout 500 ms), chaincode `attesta-trust` as a service, endorsement
`OutOf(2,'AttestaMSP.peer','AuditorMSP.peer','ReleaseMSP.peer')`: any two of the three orgs
must endorse, so one org can be down and writes still commit. Dev identities come from cryptogen.

Run everything from WSL2 inside the Linux filesystem (not /mnt/c).

| Step | Command (repo root) | Needs |
|---|---|---|
| 1 | `scripts/chaincode-tidy.sh` and `scripts/bridge-tidy.sh test` | network, `golang:1.22` image |
| 2 | `scripts/chaincode-test.sh` | Go modules from step 1 |
| 3 | `network/scripts/00-bootstrap.sh` | network (Fabric CLI tarball) |
| 4 | `network/scripts/01-gen-crypto.sh` then `02-up.sh` then `03-channel.sh` | peer/orderer images present |
| 5 | `network/scripts/04-deploy-cc.sh` | `golang:1.22-alpine` image |
| 6 | `deploy/spire-demo/scripts/gateway-up.sh` | SPIRE stack up; builds gateway image and demo key |
| 7 | `network/scripts/05-seed.sh` then `06-smoke.sh` | gateway image, scorer key |
| 8 | `deploy/spire-demo/scripts/bridge-up.sh` then `gateway-fabric.sh` | Fabric network up |
| 9 | `deploy/spire-demo/scripts/demo-submit.sh` | prints tx id and block number |
| 10 | `deploy/spire-demo/scripts/auditor-override.sh <record_id> BLOCK "<reason>"` | auditor bridge up |
| 11 | `network/scripts/09-decision-policy.sh` | policy key in `deploy/spire-demo/.runtime` (made by `gateway-up.sh`) |
| down | `deploy/spire-demo/scripts/down.sh` and `network/scripts/07-down.sh [--purge]` | |

## Trust boundaries

- CI workloads never hold Fabric identities; only the Go bridges do
  (Attesta bridge uid 1004 submits records, Auditor bridge uid 1005 submits overrides).
- Bridges accept exactly one SPIFFE client ID each (gateway / auditor CLI).
- The chaincode re-validates schema, Ed25519 signature, key validity (tx timestamp),
  policy band/decision and replay, so both orgs' peers verify independently.
- cryptogen keys, `organizations/`, `bin/` and `channel-artifacts/` are gitignored.
- Peer-to-chaincode traffic is plaintext on the private Docker network (dev only).

## Known limits

- Fabric proofs are block references (tx id, block hash chain), not Merkle proofs.
- Two PKIs: SPIRE for workloads, cryptogen for Fabric (move to Fabric CA later).

## Orgs and roles
- **Attesta** (engineering): its bridge submits scorer records; its peer is the gateway's entry point.
- **Auditor** (security): the only org whose identity may record decision overrides.
- **Release**: a third independent endorser (peer 11051 on the host). Intended home for the deploy gate's
  own-org reads; today it endorses and holds a full copy of the ledger. All three orgs run on one host
  with dev cryptogen identities, so this models separation of duty, it does not provide it.
- Tested on 2026-11-17: Auditor down or Release down: writes commit; both down: refused
  ("no combination of peers can satisfy the endorsement policy").
- Recreating the network (`07-down.sh --purge`, then steps 01-05) wipes the ledger. Take a copy of
  `/api/ledger` first if you want to keep the records.

## Signed policy decisions
A separate policy service (`attesta.policy.service`, own key, `policy` container) computes each decision
(score bands + OPA floors) and signs it over the evidence, the record and artifact ids, the decision and
the policy bundle hash (`config/policy.yaml` + `config/policy.rego`). Step 09 registers its public key and
activates a policy version that pins that bundle hash. From then on the chaincode refuses a record unless
`policy_bundle_hash` is the approved one and `decision_signature` verifies against an active registered
policy key (the scorer key cannot stand in). Tested by sending a correctly scorer-signed record straight to
the chaincode: refused. Changing either policy file means a new `policy_version` and another run of step 09
(`SetPolicy` is endorsed by two orgs). Limits: the policy service signs whatever evidence it is given, so a
compromised scorer can still lie about evidence; and records written before step 09 are unsigned.
