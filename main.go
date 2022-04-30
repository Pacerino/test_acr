package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

const (
	key    = ""
	secret = ""
	host   = ""
)

type Recognizer struct {
	Host         string
	AccessKey    string
	AccessSecret string
}

func main() {
	recognizer := Recognizer{Host: host, AccessKey: key, AccessSecret: secret}
	body, err := recognizer.RecognizeByFile("./test.mp3")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(body)
}

func (recog *Recognizer) RecognizeByFile(filePath string) (string, error) {
	fileBuff, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	string_to_sign := fmt.Sprintf("POST\n/v1/identify\n%v\naudio\n1\n%v", recog.AccessKey, timestamp)
	signature := recog.GetSign(string_to_sign, recog.AccessSecret)

	field_params := map[string]string{
		"access_key":        recog.AccessKey,
		"sample_bytes":      strconv.Itoa(len(fileBuff)),
		"timestamp":         timestamp,
		"signature":         signature,
		"data_type":         "audio",
		"signature_version": "1",
	}

	file_params := map[string][]byte{
		"sample": fileBuff,
	}

	body, err := recog.Post(field_params, file_params)
	if err != nil {
		return "", err
	}
	return body, nil
}

func (recog *Recognizer) Post(fieldParams map[string]string, fileParams map[string][]byte) (ret string, err error) {
	var remoteURL = fmt.Sprintf("%v/v1/identify", recog.Host)

	postDataBuffer := bytes.Buffer{}
	mpWriter := multipart.NewWriter(&postDataBuffer)

	for key, val := range fieldParams {
		_ = mpWriter.WriteField(key, val)
	}

	for key, val := range fileParams {
		fw, err := mpWriter.CreateFormFile(key, key)
		if err != nil {
			mpWriter.Close()
			return "", fmt.Errorf("create form file errror: %v", err)
		}
		fw.Write(val)
	}

	mpWriter.Close()

	hClient := &http.Client{}

	req, err := http.NewRequest("POST", remoteURL, &postDataBuffer)
	if err != nil {
		return "", fmt.Errorf("NewRequest Error: %v", err)
	}
	req.Header.Set("Content-Type", mpWriter.FormDataContentType())
	response, err := hClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http client do error: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http response code is not %d: %d", http.StatusOK, response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read from http response error: %v", err)
	}

	return string(body), nil
}

func (recog *Recognizer) GetSign(str string, key string) string {
	hmacHandler := hmac.New(sha1.New, []byte(key))
	hmacHandler.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(hmacHandler.Sum(nil))
}
