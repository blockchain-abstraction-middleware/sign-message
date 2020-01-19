package verify

import (
	"bytes"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Verify verfies a signature
func Verify(hexHash string, hexSignature string, address string) bool {
	pubAddress := ParseAddressFromSignedMessage(hexHash, hexSignature)

	matches := bytes.Equal(pubAddress.Bytes(), common.FromHex(address))
	fmt.Println(matches)

	return matches
}

// ParseAddressFromSignedMessage parses the eth address after getting the public key from the signature
func ParseAddressFromSignedMessage(hexHash string, hexSignature string) common.Address {
	hash := common.HexToHash(hexHash)
	signature, _ := hexutil.Decode(hexSignature)

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	pubAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA)

	return pubAddress
}
