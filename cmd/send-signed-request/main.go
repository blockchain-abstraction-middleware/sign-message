package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	sign "github.com/blockchain-abstraction-middleware/sign-message/pkg/sign"
	verify "github.com/blockchain-abstraction-middleware/sign-message/pkg/verify"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type APIKeyResponse struct {
	APIKey     string `json:"apiKey"`
	StatusCode int    `json:"statusCode"`
}

func main() {
	host := "http://localhost:8080"

	// example key ok to commit !
	privateKey, err := crypto.HexToECDSA("89D43369D1B4570C82599A6958D588BFB0168E0614A5475FC0CE3D1BF739E1E7")
	if err != nil {
		log.Fatal(err)
	}

	// Eth address of private key
	// 0x8c6253A7dCCE198b4385f17f390bC6fcE34A19Ea

	hash, signature := sign.Sign("Authorization Request: ", privateKey)

	fmt.Println(hash.Hex())
	fmt.Println(hexutil.Encode(signature))

	values := map[string]string{"hexHash": hash.Hex(), "hexSignature": hexutil.Encode(signature), "hexEthAddress": "0x96216849c49358B10257cb55b28eA603c874b05E"}

	jsonValue, _ := json.Marshal(values)

	response, err := http.Post(host+"/api/v1/auth/serve-api-key", "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	getAPIKeyPayload := new(APIKeyResponse)
	json.NewDecoder(response.Body).Decode(&getAPIKeyPayload)

	fmt.Println(getAPIKeyPayload.APIKey)
	fmt.Println(response.StatusCode)

	ok := verify.Verify(hash.Hex(), hexutil.Encode(signature), "0x8c6253A7dCCE198b4385f17f390bC6fcE34A19Ea")
	if !ok {
		log.Fatal("Invalid")
	}
}
