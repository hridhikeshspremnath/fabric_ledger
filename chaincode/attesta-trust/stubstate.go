package main

import (
	"errors"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// stubState adapts the Fabric stub to State.
type stubState struct {
	ctx contractapi.TransactionContextInterface
}

func newStubState(ctx contractapi.TransactionContextInterface) State {
	return &stubState{ctx: ctx}
}

func (s *stubState) Key(objectType string, attrs ...string) (string, error) {
	return s.ctx.GetStub().CreateCompositeKey(objectType, attrs)
}

func (s *stubState) Get(key string) ([]byte, error) { return s.ctx.GetStub().GetState(key) }

func (s *stubState) Put(key string, value []byte) error {
	return s.ctx.GetStub().PutState(key, value)
}

func (s *stubState) Del(key string) error { return s.ctx.GetStub().DelState(key) }

func (s *stubState) Scan(objectType string, attrs []string, pageSize int, bookmark string) ([]KV, string, error) {
	stub := s.ctx.GetStub()
	it, meta, err := stub.GetStateByPartialCompositeKeyWithPagination(objectType, attrs, int32(pageSize), bookmark)
	if err != nil {
		return nil, "", err
	}
	defer it.Close()
	var out []KV
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, "", err
		}
		_, parts, err := stub.SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, "", err
		}
		out = append(out, KV{Attrs: parts, Value: kv.Value})
	}
	next := ""
	if meta != nil && len(out) >= pageSize {
		next = meta.Bookmark
	}
	return out, next, nil
}

func (s *stubState) TxID() string { return s.ctx.GetStub().GetTxID() }

func (s *stubState) TxTime() (int64, error) {
	ts, err := s.ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	return ts.Seconds, nil
}

func (s *stubState) Emit(name string, payload []byte) error {
	return s.ctx.GetStub().SetEvent(name, payload)
}

func (s *stubState) Caller() (Caller, error) {
	id := s.ctx.GetClientIdentity()
	msp, err := id.GetMSPID()
	if err != nil {
		return Caller{}, err
	}
	cert, err := id.GetX509Certificate()
	if err != nil {
		return Caller{}, err
	}
	if cert == nil {
		return Caller{}, errors.New("caller has no X.509 certificate")
	}
	admin := false
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, "admin") {
			admin = true
		}
	}
	return Caller{MSPID: msp, Admin: admin}, nil
}
