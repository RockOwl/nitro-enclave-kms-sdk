package main

import (
	"encoding/base64"
	"fmt"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/pkcs7"
)

func main() {

	envelopedRecipientB64 := "MIAGCSqGSIb3DQEHA6CAMIACAQIxggE8MIIBOAIBAoAg312y035Bz0YBpQvgnT0GGy3B72VZTVE5Bkwn3i0f8uUwDQYJKoZIhvcNAQEHMAAEggEAcyZh5fodhOrl+HtKtkrrAdtyeyiKfOG6eCunUoMXkMG9mOScg+0397B4woFMy/ihMGvuXVoVmcmG+1OO4P1ZljEa7Z6/JLYzNk7J8xcBaxRtP1KIDRPsEhHDTzPMHmw6D6PzJdSpg2ILdSA8JwPgPwxUJBnW3pjyWjG1aDTq/ZZBuWrjTpmd1wYG2cOq91Rfs6XRCwyoBA7eO+pqIu/mdKKQ9aUn7qjBlqiWODzGwgCuaatWlvzDzBaPtrEEMSggaE0TzlPvMbJmhzc+GkfduR6RF5hcMXyRtwMRYaJSiAlImjXjknd4cVurB7bdn0Om3b2PSnLPvQSt94UMKlilazCABgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCLX8NwQeuxv2K6kJHlYodloIAEMKrstZ65i3imsjpWkziBKUw13+c8OBOQ1Q0D9YNJ7ZkaOMwk6fjGPf7jXrlYgTuiGwAAAAAAAAAAAAA="

	envelopedRecipientBytes, _ := base64.StdEncoding.DecodeString(envelopedRecipientB64)
	_, err := pkcs7.Parse(envelopedRecipientBytes)
	if err != nil {
		fmt.Println(err)
	}

}
