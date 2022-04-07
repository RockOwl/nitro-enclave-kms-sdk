package nitro

import (
	"crypto/rand"
	"fmt"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/pkg/errors"
	"math/big"
	"nitro-enclave-kms-sdk/log"
)

func generateBigPrime() (*big.Int, error) {
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}

	return rand.Prime(sess, 2048) // 大素数
}

//func signCert() {
//	cer := &x509.Certificate{
//		SerialNumber: big.NewInt(rd.Int63()), //证书序列号
//		Subject: pkix.Name{
//			Country:            []string{"CN"},
//			Organization:       []string{"Easy"},
//			OrganizationalUnit: []string{"Easy"},
//			Province:           []string{"ShenZhen"},
//			CommonName:         equi.Code,
//			Locality:           []string{"ShenZhen"},
//		},
//		NotBefore:             time.Now(),                                                                 //证书有效期开始时间
//		NotAfter:              time.Now().AddDate(1, 0, 0),                                                //证书有效期结束时间
//		BasicConstraintsValid: true,                                                                       //基本的有效性约束
//		IsCA:                  false,                                                                      //是否是根证书
//		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途(客户端认证，数据加密)
//		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
//		EmailAddresses:        []string{"test@test.com"},
//		IPAddresses:           []net.IP{net.ParseIP("192.168.1.59")},
//	}
//}

// Attest takes as input a nonce, user-provided data and a public key, and then
// asks the Nitro hypervisor to return a signed attestation document that
// contains all three values.
func Attest(nonce, data, publicKey []byte) ([]byte, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Error("attest() nsm.OpenDefaultSession : ", err)
		return nil, errors.WithStack(err)
	}
	defer func() {
		if err = s.Close(); err != nil {
			fmt.Printf("Attestation: Failed to close default NSM session: %s", err)
		}
	}()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  data, //certFingerprint,
		PublicKey: publicKey,
	})
	if err != nil {
		log.Error("attest() nsm.Send : ", err)
		return nil, errors.WithStack(err)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, fmt.Errorf("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}
