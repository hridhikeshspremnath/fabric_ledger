package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// fabricLedger implements Ledger with the Fabric Gateway client. The bridge's
// Fabric identity lives only here; callers never see it.
type fabricLedger struct {
	cfg      Config
	gw       *client.Gateway
	conn     *grpc.ClientConn
	contract *client.Contract
	qscc     *client.Contract
}

func newFabricLedger(cfg Config) (*fabricLedger, error) {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, err
	}

	caPEM, err := os.ReadFile(cfg.PeerTLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("read peer TLS CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("peer TLS CA contains no certificate")
	}
	conn, err := grpc.NewClient(cfg.PeerEndpoint,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, cfg.PeerHostAlias)))
	if err != nil {
		return nil, err
	}
	gw, err := client.Connect(id, client.WithSign(sign), client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second), client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(10*time.Second), client.WithCommitStatusTimeout(60*time.Second))
	if err != nil {
		conn.Close()
		return nil, err
	}
	network := gw.GetNetwork(cfg.Channel)
	return &fabricLedger{cfg: cfg, gw: gw, conn: conn,
		contract: network.GetContract(cfg.Chaincode), qscc: network.GetContract("qscc")}, nil
}

func (f *fabricLedger) Close() {
	f.gw.Close()
	f.conn.Close()
}

// classify turns Gateway/gRPC errors into LedgerError kinds.
func classify(err error) *LedgerError {
	st := status.Convert(err)
	msg := st.Message()
	switch {
	case st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded:
		return &LedgerError{Kind: KindUnavailable, Msg: msg}
	case strings.Contains(msg, "not found"):
		return &LedgerError{Kind: KindNotFound, Msg: msg}
	case st.Code() == codes.Aborted || st.Code() == codes.FailedPrecondition || st.Code() == codes.Unknown:
		return &LedgerError{Kind: KindRejected, Msg: msg}
	default:
		return &LedgerError{Kind: KindOther, Msg: err.Error()}
	}
}

func (f *fabricLedger) Submit(fn string, args ...string) (*TxResult, error) {
	proposal, err := f.contract.NewProposal(fn, client.WithArguments(args...))
	if err != nil {
		return nil, &LedgerError{Kind: KindOther, Msg: err.Error()}
	}
	tx, err := proposal.Endorse()
	if err != nil {
		return nil, classify(err)
	}
	submitted, err := tx.Submit()
	if err != nil {
		return nil, classify(err)
	}
	st, err := submitted.Status()
	if err != nil {
		return nil, classify(err)
	}
	if !st.Successful {
		return nil, &LedgerError{Kind: KindRejected,
			Msg: fmt.Sprintf("transaction %s failed validation: %s", st.TransactionID, peer.TxValidationCode_name[int32(st.Code)])}
	}
	result := json.RawMessage(tx.Result())
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	return &TxResult{TxID: st.TransactionID, BlockNumber: st.BlockNumber, Result: result}, nil
}

func (f *fabricLedger) Evaluate(fn string, args ...string) ([]byte, error) {
	out, err := f.contract.EvaluateTransaction(fn, args...)
	if err != nil {
		return nil, classify(err)
	}
	return out, nil
}

func (f *fabricLedger) ChainInfo() (*ChainInfo, error) {
	raw, err := f.qscc.EvaluateTransaction("GetChainInfo", f.cfg.Channel)
	if err != nil {
		return nil, classify(err)
	}
	var info common.BlockchainInfo
	if err := proto.Unmarshal(raw, &info); err != nil {
		return nil, &LedgerError{Kind: KindOther, Msg: err.Error()}
	}
	return &ChainInfo{Channel: f.cfg.Channel, Height: info.GetHeight(),
		CurrentBlockHash:  hex.EncodeToString(info.GetCurrentBlockHash()),
		PreviousBlockHash: hex.EncodeToString(info.GetPreviousBlockHash())}, nil
}

// txIndex finds txID inside block.Data and returns its position.
func txIndex(block *common.Block, txID string) (int, bool) {
	for i, raw := range block.GetData().GetData() {
		var env common.Envelope
		var payload common.Payload
		var ch common.ChannelHeader
		if proto.Unmarshal(raw, &env) != nil || proto.Unmarshal(env.GetPayload(), &payload) != nil ||
			proto.Unmarshal(payload.GetHeader().GetChannelHeader(), &ch) != nil {
			continue
		}
		if ch.GetTxId() == txID {
			return i, true
		}
	}
	return 0, false
}

func (f *fabricLedger) Proof(txID string) (*ProofInfo, error) {
	raw, err := f.qscc.EvaluateTransaction("GetBlockByTxID", f.cfg.Channel, txID)
	if err != nil {
		return nil, classify(err)
	}
	var block common.Block
	if err := proto.Unmarshal(raw, &block); err != nil {
		return nil, &LedgerError{Kind: KindOther, Msg: err.Error()}
	}
	hash, err := blockHeaderHash(block.GetHeader())
	if err != nil {
		return nil, &LedgerError{Kind: KindOther, Msg: err.Error()}
	}
	code := "UNKNOWN"
	md := block.GetMetadata().GetMetadata()
	if idx, ok := txIndex(&block, txID); ok && len(md) > int(common.BlockMetadataIndex_TRANSACTIONS_FILTER) {
		filter := md[common.BlockMetadataIndex_TRANSACTIONS_FILTER]
		if idx < len(filter) {
			code = peer.TxValidationCode_name[int32(filter[idx])]
		}
	}
	info, err := f.ChainInfo()
	if err != nil {
		return nil, err
	}
	return &ProofInfo{TxID: txID, BlockNumber: block.GetHeader().GetNumber(),
		BlockHash:      hex.EncodeToString(hash),
		PreviousHash:   hex.EncodeToString(block.GetHeader().GetPreviousHash()),
		DataHash:       hex.EncodeToString(block.GetHeader().GetDataHash()),
		ValidationCode: code, ChainHeight: info.Height, ChainTipHash: info.CurrentBlockHash}, nil
}
