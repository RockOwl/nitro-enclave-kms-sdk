package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/pkg/errors"
)

func GenerateRsaKey(bits int) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Error("GenerateRsaKey() rsa.GenerateKey err : ", err)
		return nil, nil, errors.WithStack(err)
	}

	x509PriKey := x509.MarshalPKCS1PrivateKey(privateKey) //通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	if err != nil {
		return nil, nil, err
	}
	x509PriKeyB64 := base64.StdEncoding.EncodeToString(x509PriKey)
	fmt.Println("x509PriKeyB64 : ", x509PriKeyB64)

	x509PubKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Error("GenerateRsaKey() x509.MarshalPKIXPublicKey err : ", err)
		return nil, nil, errors.WithStack(err)
	}

	return privateKey, x509PubKey, nil
}
