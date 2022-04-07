package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"kms/log"
)

func GenerateRsaKey(bits int) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Error("GenerateRsaKey() rsa.GenerateKey err : ", err)
		return nil, nil, errors.WithStack(err)
	}

	//x509PriKey := x509.MarshalPKCS1PrivateKey(privateKey) //通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	//if err != nil {
	//	return nil, nil, err
	//}

	x509PubKey := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Error("GenerateRsaKey() x509.MarshalPKCS1PublicKey err : ", err)
		return nil, nil, errors.WithStack(err)
	}

	return privateKey, x509PubKey, nil
}
