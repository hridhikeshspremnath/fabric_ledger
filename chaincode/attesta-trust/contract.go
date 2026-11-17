package main

import (
	"os"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Contract exposes Service through the Fabric contract API.
type Contract struct {
	contractapi.Contract
}

func configFromEnv() Config {
	cfg := Config{AttestaMSP: "AttestaMSP", AuditorMSP: "AuditorMSP"}
	if v := os.Getenv("ATTESTA_MSP"); v != "" {
		cfg.AttestaMSP = v
	}
	if v := os.Getenv("AUDITOR_MSP"); v != "" {
		cfg.AuditorMSP = v
	}
	return cfg
}

func svc(ctx contractapi.TransactionContextInterface) *Service {
	return NewService(newStubState(ctx), configFromEnv())
}

// Submit transactions.

func (c *Contract) RecordDecision(ctx contractapi.TransactionContextInterface, recordJSON string) (string, error) {
	return svc(ctx).RecordDecision(recordJSON)
}

func (c *Contract) RecordOverride(ctx contractapi.TransactionContextInterface, recordID, decision, reason string) (string, error) {
	return svc(ctx).RecordOverride(recordID, decision, reason)
}

func (c *Contract) RegisterScorerKey(ctx contractapi.TransactionContextInterface, keyJSON string) error {
	return svc(ctx).RegisterScorerKey(keyJSON)
}

func (c *Contract) RegisterDecisionKey(ctx contractapi.TransactionContextInterface, keyJSON string) error {
	return svc(ctx).RegisterDecisionKey(keyJSON)
}

func (c *Contract) GetDecisionKey(ctx contractapi.TransactionContextInterface, keyID string) (string, error) {
	return svc(ctx).GetDecisionKey(keyID)
}

func (c *Contract) RevokeScorerKey(ctx contractapi.TransactionContextInterface, keyID string) error {
	return svc(ctx).RevokeScorerKey(keyID)
}

func (c *Contract) SetPolicy(ctx contractapi.TransactionContextInterface, policyJSON string) error {
	return svc(ctx).SetPolicy(policyJSON)
}

func (c *Contract) AnchorCheckpoint(ctx contractapi.TransactionContextInterface, id, merkleRoot string, recordCount int, source string) (string, error) {
	return svc(ctx).AnchorCheckpoint(id, merkleRoot, recordCount, source)
}

// Evaluate (read-only) transactions.

func (c *Contract) GetRecord(ctx contractapi.TransactionContextInterface, recordID string) (string, error) {
	return svc(ctx).GetRecord(recordID)
}

func (c *Contract) GetHistory(ctx contractapi.TransactionContextInterface, recordID string) (string, error) {
	return svc(ctx).GetHistory(recordID)
}

func (c *Contract) ListRecent(ctx contractapi.TransactionContextInterface, pageSize int, bookmark string) (string, error) {
	return svc(ctx).ListRecent(pageSize, bookmark)
}

func (c *Contract) ListByPackage(ctx contractapi.TransactionContextInterface, ecosystem, pkg, version string, pageSize int, bookmark string) (string, error) {
	return svc(ctx).ListByPackage(ecosystem, pkg, version, pageSize, bookmark)
}

func (c *Contract) ListByStatus(ctx contractapi.TransactionContextInterface, decision string, pageSize int, bookmark string) (string, error) {
	return svc(ctx).ListByStatus(decision, pageSize, bookmark)
}

func (c *Contract) VerifyArtifact(ctx contractapi.TransactionContextInterface, digest string) (string, error) {
	return svc(ctx).VerifyArtifact(digest)
}

func (c *Contract) GetCheckpoint(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	return svc(ctx).GetCheckpoint(id)
}

func (c *Contract) GetScorerKey(ctx contractapi.TransactionContextInterface, keyID string) (string, error) {
	return svc(ctx).GetScorerKey(keyID)
}

func (c *Contract) GetPolicy(ctx contractapi.TransactionContextInterface, version string) (string, error) {
	return svc(ctx).GetPolicy(version)
}
