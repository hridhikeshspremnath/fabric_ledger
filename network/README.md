# Attesta Fabric network (2.5.16, dev)

2 orgs (AttestaMSP, AuditorMSP), 1 peer each (LevelDB), 1 Raft orderer
(batch timeout 500 ms), chaincode `attesta-trust` as a service, endorsement
`AND('AttestaMSP.peer','AuditorMSP.peer')`. Dev identities come from cryptogen.

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
