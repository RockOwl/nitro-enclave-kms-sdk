package main

import (
	"fmt"
	kms "github.com/brodyxchen/nitro-enclave-kms-sdk"
)

func main() {
	cli, err := kms.NewClient()
	if err != nil {
		panic(err)
	}
	cli.SetRegion("us-west-1")
	cli.SetCredential("keyId", "secretKey", "sessionToken")
	nonceStr, err := cli.GenerateRandom(64)
	if err != nil {
		fmt.Printf("err: %+v", err)
	}
	fmt.Println("kms. generate() random str :", string(nonceStr))
}
