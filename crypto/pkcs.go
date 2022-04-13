package crypto

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/pkcs7"
	"github.com/pkg/errors"
)

func DecryptEnvelopedRecipient(priKey crypto.PrivateKey, data string) ([]byte, error) {
	fmt.Println("EnvelopedRecipient : ", data)

	recipient, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	pkcs, err := pkcs7.Parse(recipient)
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs7.Parse err : ", err)
		return nil, errors.WithStack(err)
	}

	outBytes, err := pkcs.DecryptWithNoCert(priKey)
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs.DecryptWithNoCert err : ", err)
		return nil, errors.WithStack(err)
	}
	return outBytes, nil
}
