package crypto

import (
	"crypto"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/pkcs7"
	"github.com/pkg/errors"
)

func DecryptEnvelopedRecipient(priKey crypto.PrivateKey, data []byte) ([]byte, error) {
	pkcs, err := pkcs7.Parse(data)
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs7.Parse err : ", err)

		//pkcs7.Parse err :  asn1: structure error: tags don't match (16 vs {class:2 tag:0 length:32 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} issuerAndSerial @5

		return nil, errors.WithStack(err)
	}

	outBytes, err := pkcs.DecryptWithNoCert(priKey)
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs.DecryptWithNoCert err : ", err)
		return nil, errors.WithStack(err)
	}
	return outBytes, nil
}
