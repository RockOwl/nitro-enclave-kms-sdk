package types

type DataKeySpec string

const (
	DataKeySpecAes256 DataKeySpec = "AES_256"
	DataKeySpecAes128 DataKeySpec = "AES_128"
)

type EncryptionAlgorithmSpec string

const (
	EncryptionAlgorithmSpecSymmetricDefault EncryptionAlgorithmSpec = "SYMMETRIC_DEFAULT"
	EncryptionAlgorithmSpecRsaesOaepSha1    EncryptionAlgorithmSpec = "RSAES_OAEP_SHA_1"
	EncryptionAlgorithmSpecRsaesOaepSha256  EncryptionAlgorithmSpec = "RSAES_OAEP_SHA_256"
)
