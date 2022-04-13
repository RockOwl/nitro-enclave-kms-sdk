package kms

import (
	crypto2 "crypto"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/crypto"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/env"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/models"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/nitro"
	_ "github.com/brodyxchen/nitro-enclave-kms-sdk/randseed"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/types"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/viproxy"
	"github.com/mdlayher/vsock"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	httpTimeout       = 180 * time.Second
	amzDateTimeFormat = "20060102T150405Z"
	amzDateFormat     = "20060102"

	DataKeySpecAes256 types.DataKeySpec = "AES_256"
	DataKeySpecAes128 types.DataKeySpec = "AES_128"

	LocalEnv   = env.LocalEnv
	ReleaseEnv = env.ReleaseEnv
)

func NewClient(inEnv env.Env, inPort, outPort int) (*Client, error) {
	env.Set(inEnv)

	cli := &Client{
		inTcpPort: inPort,
		outVPort:  outPort,
	}

	err := cli.init()
	if err != nil {
		return nil, err
	}
	return cli, nil
}

type Client struct {
	region          string
	accessKeyId     string
	accessSecretKey string
	sessionToken    string

	rsaKey    crypto2.PrivateKey
	rsaPubKey []byte // PKIXPublicKey

	httpCli *http.Client

	inTcpPort int // "443"
	outVPort  int // "1443"
}

//func (cli *Client) withSocksProxy() (*http.Client, error) {
//	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
//	if err != nil {
//		fmt.Println("can't connect to the proxy:", err)
//		return nil, err
//	}
//
//	dc := dialer.(interface {
//		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
//	})
//
//	// setup a http client
//	httpTransport := &http.Transport{}
//	httpClient := &http.Client{Transport: httpTransport, Timeout: time.Second * 180}
//	// set our socks5 as the dialer
//	httpTransport.DialContext = dc.DialContext
//	return httpClient, nil
//}
func (cli *Client) withHttpProxy() (*http.Client, error) {
	//url := "http://127.0.0.1:443"
	//proxyUrl, _ := url2.Parse(url)
	//transport := &http.Transport{
	//	Proxy:           http.ProxyURL(proxyUrl),
	//	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//}

	return &http.Client{
		//Transport: transport,
		Timeout: httpTimeout,
	}, nil
}

func (cli *Client) init() error {
	httpCli, _ := cli.withHttpProxy()
	cli.httpCli = httpCli

	if err := cli.initProxy(); err != nil {
		return err
	}

	priKey, pubKey, err := crypto.GenerateRsaKey(2048)
	if err != nil {
		log.Errorf("client.init() GenerateRsaKey err : %v", err)
		return err
	}

	log.Debug("client.init() generate rsa priKey.size : ", priKey.Size())

	cli.rsaKey = priKey
	cli.rsaPubKey = pubKey
	return nil
}

func (cli *Client) initProxy() error {
	if env.IsLocal() {
		return nil
	}

	inAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:"+strconv.Itoa(cli.inTcpPort)) // tcp://127.0.0.1:1080
	if err != nil {
		return fmt.Errorf("failed to resolve proxy from config: %s", err)
	}

	tuple := &viproxy.Tuple{
		InAddr:  inAddr,                                                        // tcp://127.0.0.1:443
		OutAddr: &vsock.Addr{ContextID: uint32(3), Port: uint32(cli.outVPort)}, // vsock://3:1443
	}
	fmt.Printf("inAddr := %+v, outAddr := %+v\n", tuple.InAddr, tuple.OutAddr)
	proxyCli := viproxy.NewVIProxy([]*viproxy.Tuple{tuple})
	if err := proxyCli.Start(); err != nil { // 监听tcp://127.0.0.1:443,  转发到  vsock://3:1443
		return fmt.Errorf("failed to start VIProxy: %s", err)
	}
	return nil
}

func (cli *Client) SetRegion(region string) {
	cli.region = region
}
func (cli *Client) SetCredential(keyId, secretKey, sessionToken string) {
	cli.accessKeyId = keyId
	cli.accessSecretKey = secretKey
	cli.sessionToken = sessionToken
}

func (cli *Client) GenerateRandom(byteCount int) ([]byte, error) {
	if byteCount < 1 || byteCount > 1024 {
		return nil, fmt.Errorf("invalid random byte count %v", byteCount)
	}

	awsTarget := "TrentService.GenerateRandom"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, err
	}
	req := &models.GenerateRandomRequest{
		NumberOfBytes: byteCount,
		Recipient:     recipient,
	}

	var rsp models.GenerateRandomResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, err
	}

	if env.IsLocal() {
		fmt.Println("rsp : ", rsp)
		return []byte(rsp.Plaintext), nil
	}
	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func (cli *Client) GenerateDataKey(keySpec types.DataKeySpec, kmsKeyId string) ([]byte, []byte, error) {
	awsTarget := "TrentService.GenerateDataKey"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, nil, err
	}
	req := &models.GenerateDataKeyRequest{
		KeyId:       kmsKeyId,
		GrantTokens: []string{cli.sessionToken},
		KeySpec:     keySpec,
		Recipient:   recipient,
	}

	var rsp models.GenerateDataKeyResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, nil, err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(rsp.CiphertextBlob)
	if err != nil {
		return nil, nil, err
	}

	if env.IsLocal() {
		fmt.Println("rsp : ", rsp) // b64
		plainBytes, err := base64.StdEncoding.DecodeString(rsp.Plaintext)
		if err != nil {
			return nil, nil, err
		}

		return plainBytes, cipherBytes, nil
	}
	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, nil, err
	}

	return plainBytes, cipherBytes, nil
}

func (cli *Client) Decrypt(ciphertextBlob []byte, kmsKeyId string) ([]byte, error) {
	awsTarget := "TrentService.Decrypt"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, err
	}
	req := &models.DecryptRequest{
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		GrantTokens:         []string{cli.sessionToken},
		KeyId:               kmsKeyId,
		Recipient:           recipient,
	}

	var rsp models.DecryptResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, err
	}

	if env.IsLocal() {
		fmt.Println("rspLocal : ", rsp) // plainB64
		plainBytes, err := base64.StdEncoding.DecodeString(rsp.Plaintext)
		if err != nil {
			return nil, err
		}
		return plainBytes, nil
	}
	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func (cli *Client) withRecipientInfo() (*models.RecipientInfo, error) {
	if env.IsLocal() {
		return nil, nil
	}
	nonceStr := crypto.RandomString(16)
	attest, err := nitro.Attest([]byte(nonceStr), []byte("key-creator"), cli.rsaPubKey)
	if err != nil {
		return nil, err
	}

	attestB64 := base64.StdEncoding.EncodeToString(attest)
	return &models.RecipientInfo{
		KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_1",
		AttestationDocument:    attestB64,
	}, nil
}
