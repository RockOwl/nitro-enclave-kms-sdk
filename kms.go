package kms

import (
	"context"
	crypto2 "crypto"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/crypto"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/models"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/nitro"
	_ "github.com/brodyxchen/nitro-enclave-kms-sdk/randseed"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/types"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	amzDateTimeFormat = "20060102T150405Z"
	amzDateFormat     = "20060102"

	DataKeySpecAes256 types.DataKeySpec = "AES_256"
	DataKeySpecAes128 types.DataKeySpec = "AES_128"
)

func NewClient() (*Client, error) {
	cli := &Client{}

	err := cli.init()
	if err != nil {
		return nil, err
	}
	cli.health()
	return cli, nil
}

type Client struct {
	region          string
	accessKeyId     string
	accessSecretKey string
	sessionToken    string

	rsaKey    crypto2.PrivateKey
	rsaPubKey []byte

	httpCli *http.Client
}

func (cli *Client) init() error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't connect to the proxy:", err)
		return err
	}

	dc := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})

	// setup a http client
	httpTransport := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransport, Timeout: time.Second * 180}
	// set our socks5 as the dialer
	httpTransport.DialContext = dc.DialContext

	cli.httpCli = httpClient

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

func (cli *Client) health() {
	go func() {
		for {
			rsp, err := cli.httpCli.Get("http://www.baidu.com")
			if err != nil {
				fmt.Println("get http://baidu.com err : ", err)
			} else {
				body, err := ioutil.ReadAll(rsp.Body)
				fmt.Printf("get http://baidu.com ok : rsp.body.len=%v, err=%v \n", len(body), err)
			}

			time.Sleep(time.Second * 15)

			rsp, err = cli.httpCli.Get("https://www.qq.com")
			if err != nil {
				fmt.Println("get https://qq.com err : ", err)
			} else {
				body, err := ioutil.ReadAll(rsp.Body)
				fmt.Printf("get https://qq.com ok : rsp.body.len=%v, err=%v \n", len(body), err)
			}

			time.Sleep(time.Second * 15)
		}

	}()

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
		Recipient:     *recipient,
	}

	var rsp models.GenerateRandomResponse
	err = cli.callKms(awsTarget, req, rsp)
	if err != nil {
		return nil, err
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
		Recipient:   *recipient,
	}

	var rsp models.GenerateDataKeyResponse
	err = cli.callKms(awsTarget, req, rsp)
	if err != nil {
		return nil, nil, err
	}

	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, nil, err
	}

	return plainBytes, rsp.CiphertextBlob, nil
}

func (cli *Client) Decrypt(ciphertextBlob []byte, kmsKeyId string) ([]byte, error) {
	awsTarget := "TrentService.Decrypt"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, err
	}
	req := &models.DecryptRequest{
		CiphertextBlob: ciphertextBlob,
		//EncryptionAlgorithm: "",
		GrantTokens: []string{cli.sessionToken},
		KeyId:       kmsKeyId,
		Recipient:   *recipient,
	}

	var rsp models.DecryptResponse
	err = cli.callKms(awsTarget, req, rsp)
	if err != nil {
		return nil, err
	}

	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func (cli *Client) withRecipientInfo() (*models.RecipientInfo, error) {
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
