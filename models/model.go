package models

import (
	"github.com/brodyxchen/nitro-enclave-kms-sdk"
)

type ErrorResponse struct {
	ErrType    string `json:"__type"`
	ErrMessage string `json:"message"`
}

// RecipientInfo https://docs.aws.amazon.com/zh_cn/kms/latest/developerguide/services-nitro-enclaves.html
type RecipientInfo struct {
	AttestationDocument    string `json:"AttestationDocument"`
	KeyEncryptionAlgorithm string `json:"KeyEncryptionAlgorithm"` // 唯一有效值为 RSAES_OAEP_SHA_256
}

// 使用 AWS Nitro Enclaves 支持 AWS KMS Decrypt、GenerateDataKey 和 GenerateRandom 操作
// https://docs.aws.amazon.com/zh_cn/kms/latest/developerguide/services-nitro-enclaves.html

type GenerateRandomRequest struct {
	NumberOfBytes int `json:"NumberOfBytes"`

	Recipient RecipientInfo `json:"Recipient"`
}

type GenerateRandomResponse struct {
	Plaintext              []byte // enclave-kms中，此为null
	CiphertextForRecipient []byte // enclave-kms中，返回这个, Base64 编码的二进制数据对象
}

type GenerateDataKeyRequest struct {
	KeyId       string
	GrantTokens []string
	KeySpec     kms.DataKeySpec // AES_128  AES_256
	Recipient   RecipientInfo   `json:"Recipient"`
}
type GenerateDataKeyResponse struct {
	CiphertextBlob []byte
	KeyId          string

	Plaintext              []byte // enclave-kms中，此为null
	CiphertextForRecipient []byte // enclave-kms中，返回这个
}

type DecryptRequest struct {
	CiphertextBlob      []byte
	EncryptionAlgorithm kms.EncryptionAlgorithmSpec
	GrantTokens         []string
	KeyId               string
	Recipient           RecipientInfo `json:"Recipient"`
}
type DecryptResponse struct {
	EncryptionAlgorithm kms.EncryptionAlgorithmSpec
	KeyId               string

	Plaintext              []byte // enclave-kms中，此为null
	CiphertextForRecipient []byte // enclave-kms中，返回这个		// base64加密后的，需要解密
}
