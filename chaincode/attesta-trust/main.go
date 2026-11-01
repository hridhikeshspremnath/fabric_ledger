package main

// Chaincode-as-a-service entry point. The peer connects to this server; see
// network/ for the connection.json packaging. TLS between peer and chaincode
// is disabled for the dev network (private Docker network only).

import (
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(&Contract{})
	if err != nil {
		log.Fatalf("create chaincode: %v", err)
	}
	server := &shim.ChaincodeServer{
		CCID:     os.Getenv("CHAINCODE_ID"),
		Address:  os.Getenv("CHAINCODE_SERVER_ADDRESS"),
		CC:       cc,
		TLSProps: shim.TLSProperties{Disabled: true},
	}
	if err := server.Start(); err != nil {
		log.Fatalf("start chaincode server: %v", err)
	}
}
