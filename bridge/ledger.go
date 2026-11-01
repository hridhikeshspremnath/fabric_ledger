package main

import "encoding/json"

// Ledger is what the HTTP API needs from Fabric. The real implementation is
// fabricLedger; tests use a fake.
type Ledger interface {
	// Submit endorses (both orgs), orders and waits for commit.
	Submit(fn string, args ...string) (*TxResult, error)
	// Evaluate runs a read-only query on one peer.
	Evaluate(fn string, args ...string) ([]byte, error)
	// Proof describes the block that contains txID.
	Proof(txID string) (*ProofInfo, error)
	ChainInfo() (*ChainInfo, error)
}

type TxResult struct {
	TxID        string          `json:"tx_id"`
	BlockNumber uint64          `json:"block_number"`
	Result      json.RawMessage `json:"result"`
}

// ProofInfo is Fabric's inclusion evidence for a transaction.
type ProofInfo struct {
	TxID            string `json:"tx_id"`
	BlockNumber     uint64 `json:"block_number"`
	BlockHash       string `json:"block_hash"`
	PreviousHash    string `json:"previous_block_hash"`
	DataHash        string `json:"data_hash"`
	ValidationCode  string `json:"validation_code"`
	ChainHeight     uint64 `json:"chain_height"`
	ChainTipHash    string `json:"chain_tip_hash"`
}

type ChainInfo struct {
	Channel           string `json:"channel"`
	Height            uint64 `json:"height"`
	CurrentBlockHash  string `json:"current_block_hash"`
	PreviousBlockHash string `json:"previous_block_hash"`
}

// ErrKind classifies ledger failures so the API can pick an HTTP status.
type ErrKind int

const (
	KindRejected    ErrKind = iota // chaincode or commit rejected the request
	KindNotFound                   // record/tx does not exist
	KindUnavailable                // peer/orderer unreachable or timed out
	KindOther
)

type LedgerError struct {
	Kind ErrKind
	Msg  string
}

func (e *LedgerError) Error() string { return e.Msg }
