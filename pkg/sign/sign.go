package sign

import (
	"crypto/ecdsa"
	"log"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Sign signs an ethereum message
func Sign(message string, privateKey *ecdsa.PrivateKey) (common.Hash, []byte) {
	validationMsg := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)) + message

	hash := crypto.Keccak256Hash([]byte(validationMsg))

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	return hash, signature
}
