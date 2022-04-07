package kms

import (
	crypto2 "crypto"
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/crypto"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/models"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/nitro"
	_ "github.com/brodyxchen/nitro-enclave-kms-sdk/randseed"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/types"
	"net/http"
	"time"
)

const (
	amzDateTimeFormat = "20060102T150405Z"
	amzDateFormat     = "20060102"
)

func NewClient() (*Client, error) {
	cli := &Client{}

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
	rsaPubKey []byte

	httpCli *http.Client
}

func (cli *Client) init() error {
	cli.httpCli = &http.Client{
		Timeout: time.Second * 30,
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
