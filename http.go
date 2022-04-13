package kms

import (
	"encoding/json"
	"fmt"
	crypto2 "github.com/brodyxchen/nitro-enclave-kms-sdk/crypto"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/log"
	"github.com/brodyxchen/nitro-enclave-kms-sdk/models"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4-create-canonical-request.html

func (cli *Client) callKms(target string, reqPtr interface{}, rspPtr interface{}) error {
	fmt.Println("kms.callKms target : ", target)
	url := fmt.Sprintf("https://kms.%s.amazonaws.com/", cli.region)

	reqData, err := json.Marshal(reqPtr)
	if err != nil {
		log.Error("callKms() json.Marshal err : ", err)
		return errors.WithStack(err)
	}

	headers := cli.withHeaders(target, reqData)

	// post
	rspData, err := cli.httpPost(url, reqData, headers)
	if err != nil {
		return err
	}

	fmt.Println("rspBody : ", rspData)

	err = json.Unmarshal(rspData, rspPtr)
	if err != nil {
		log.Error("callKms() json.Unmarshal err : ", err)
		return errors.WithStack(err)
	}
	return nil
}

func (cli *Client) withHeaders(target string, reqData []byte) map[string]string {
	reqHash := crypto2.HexEncodeToString(crypto2.Sha256(reqData))

	awsService := "kms"
	host := fmt.Sprintf("kms.%s.amazonaws.com", cli.region)
	contentType := "application/x-amz-json-1.1" //todo 这里末尾多了一个'

	nowUtc := time.Now().UTC()                      //todo 这里必须是utc
	amzDateTime := nowUtc.Format(amzDateTimeFormat) // %Y%m%dT%H%M%SZ

	// 创建规范请求
	httpMethod := "POST"
	canonicalURI := "/"
	CanonicalQueryString := ""

	var sb strings.Builder
	sb.WriteString("content-type:" + contentType + "\n")
	sb.WriteString("host:" + host + "\n")
	sb.WriteString("x-amz-date:" + amzDateTime + "\n")
	sb.WriteString("x-amz-target:" + target + "\n")
	CanonicalHeaders := sb.String()

	signedHeaders := "content-type;host;x-amz-date;x-amz-target"

	// 规范的请求字符串
	var reqBuilder strings.Builder
	reqBuilder.WriteString(httpMethod + "\n")
	reqBuilder.WriteString(canonicalURI + "\n")
	reqBuilder.WriteString(CanonicalQueryString + "\n")
	reqBuilder.WriteString(CanonicalHeaders + "\n")
	reqBuilder.WriteString(signedHeaders + "\n")
	reqBuilder.WriteString(reqHash) // 最后没有\n

	CanonicalRequest := reqBuilder.String()
	dateStamp := nowUtc.Format(amzDateFormat)

	// 创建待签字符串
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := dateStamp + "/" + cli.region + "/" + awsService + "/" + "aws4_request"
	canonicalReqHash := crypto2.HexEncodeToString(crypto2.Sha256([]byte(CanonicalRequest)))

	var signBuilder strings.Builder
	signBuilder.WriteString(algorithm + "\n")
	signBuilder.WriteString(amzDateTime + "\n")
	signBuilder.WriteString(credentialScope + "\n")
	signBuilder.WriteString(canonicalReqHash)
	unsignedString := signBuilder.String()

	// 计算签名
	sign := cli.signatureKms(dateStamp, cli.region, awsService, unsignedString)

	// header-Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
	var authBuilder strings.Builder
	authBuilder.WriteString(algorithm + " ")
	authBuilder.WriteString("Credential=" + cli.accessKeyId + "/" + credentialScope + ", ")
	authBuilder.WriteString("SignedHeaders=" + signedHeaders + ", ")
	authBuilder.WriteString("Signature=" + sign)
	authHeader := authBuilder.String()

	headers := make(map[string]string, 0)
	headers["Content-Type"] = contentType
	headers["X-Amz-Date"] = amzDateTime
	headers["X-Amz-Target"] = target
	headers["Authorization"] = authHeader
	if len(cli.sessionToken) > 0 {
		headers["X-Amz-Security-Token"] = cli.sessionToken
	}

	return headers
}

func (cli *Client) httpPost(url string, reqBody []byte, headers map[string]string) ([]byte, error) {
	fmt.Printf("kmsCli.httpPost() url=%v\n", url)
	fmt.Printf("kmsCli.httpPost() req=%+v\n", string(reqBody))
	fmt.Printf("kmsCli.httpPost() headers=%+v\n", headers)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		log.Error("httpPost() NewRequest() err : ", err)
		return nil, errors.WithStack(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rsp, err := cli.httpCli.Do(req)
	if err != nil {
		log.Error("httpPost() httpCli.Do() err : ", err)
		return nil, errors.WithStack(err)
	}
	defer rsp.Body.Close()

	log.Info("httpPost() httpCli.Do StatusCode : ", rsp.StatusCode)

	if rsp.StatusCode != 200 {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Error("httpPost() ioutil.ReadAll err : ", err)
			return nil, errors.WithStack(err)
		}
		var errRsp models.ErrorResponse
		err = json.Unmarshal(body, &errRsp)
		if err != nil {
			log.Error("httpPost() json.Unmarshal err : ", err)
			return nil, errors.WithStack(err)
		}

		log.Errorf("code: %v err_type: %v err_msg: %v", rsp.StatusCode, errRsp.ErrType, errRsp.ErrMessage)

		return nil, fmt.Errorf("code: %v err_type: %v err_msg: %v", rsp.StatusCode, errRsp.ErrType, errRsp.ErrMessage)
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		log.Error("httpPost() ioutil.ReadAll : ", err)
		return nil, errors.WithStack(err)
	}

	return body, nil
}

func (cli *Client) signatureKms(dateStamp, region, service string, unsignedString string) string {
	key := cli.accessSecretKey

	dateHash := crypto2.HMacSha256([]byte("AWS4"+key), dateStamp)
	regionHash := crypto2.HMacSha256(dateHash, region)
	serviceHash := crypto2.HMacSha256(regionHash, service)
	signing := crypto2.HMacSha256(serviceHash, "aws4_request")

	sign := crypto2.HMacSha256(signing, unsignedString)
	return crypto2.HexEncodeToString(sign)
}
