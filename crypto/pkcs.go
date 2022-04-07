package crypto

import (
	"crypto"
	"github.com/RockOwl/nitro-enclave-kms-sdk/log"
	"github.com/RockOwl/nitro-enclave-kms-sdk/pkcs7"
	"github.com/pkg/errors"
)

func DecryptEnvelopedRecipient(priKey crypto.PrivateKey, data []byte) ([]byte, error) {
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
