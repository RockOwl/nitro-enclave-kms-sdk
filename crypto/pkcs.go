package crypto

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/pkcs7"
	"github.com/pkg/errors"
)

func DecryptEnvelopedRecipient(priKey crypto.PrivateKey, data []byte) ([]byte, error) {

	b64 := base64.StdEncoding.EncodeToString(data)
	fmt.Println("EnvelopedRecipientB64 : ", b64)

	pkcs, err := pkcs7.Parse(data)
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
