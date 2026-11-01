package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

// Fabric's block header hash: SHA-256 over the ASN.1 DER of
// SEQUENCE { INTEGER number, OCTET STRING previousHash, OCTET STRING dataHash }.
type asn1Header struct {
	Number       *big.Int
	PreviousHash []byte
	DataHash     []byte
}

func headerHash(number uint64, previousHash, dataHash []byte) ([]byte, error) {
	der, err := asn1.Marshal(asn1Header{
		Number: new(big.Int).SetUint64(number), PreviousHash: previousHash, DataHash: dataHash,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

func blockHeaderHash(h *common.BlockHeader) ([]byte, error) {
	return headerHash(h.GetNumber(), h.GetPreviousHash(), h.GetDataHash())
}
