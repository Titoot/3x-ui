package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// type Client struct {
// 	session *http.Client
// }

// func NewYourStruct() *Client {
// 	return &Client{
// 		session: setupRequests(),
// 	}
// }

// func setupRequests() *http.Client {
// 	return &http.Client{}
// }

/*type WE struct {
	QuotaData string
	QuotaJson string
}*/

type UserInfo struct {
	data map[string]interface{}
}

func NewUserInfo(data map[string]interface{}) *UserInfo {
	return &UserInfo{data: data}
}

func (u *UserInfo) Msisdn() string {
	return u.data["header"].(map[string]interface{})["msisdn"].(string)
}

func (u *UserInfo) CustomerID() string {
	return u.data["header"].(map[string]interface{})["customerId"].(string)
}

func (u *UserInfo) JWT() string {
	return u.data["body"].(map[string]interface{})["jwt"].(string)
}

func (u *UserInfo) CustomerName() string {
	return u.data["body"].(map[string]interface{})["customerName"].(string)
}

type RequestHeader struct {
	Msisdn            string `json:"msisdn"`
	NumberServiceType string `json:"numberServiceType"`
	Timestamp         string `json:"timestamp"`
	Locale            string `json:"locale"`
}

type RequestBody struct {
	Password string `json:"password"`
}

type JsonRequest struct {
	Header RequestHeader `json:"header"`
	Body   RequestBody   `json:"body"`
}

var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

func InitWE(number string, password string) (*UserInfo, error) {
	userInfo := UserInfo{}
	login, err := userInfo.Login(number, password)
	return login, err

}

func (u UserInfo) Login(number string, password string) (*UserInfo, error) {
	requestHeader := RequestHeader{
		Msisdn:            number,
		NumberServiceType: "FBB",
		Timestamp:         "1778486658",
		Locale:            "en",
	}

	requestBody := RequestBody{
		Password: aesEncrypt(password),
	}

	jsonData := JsonRequest{
		Header: requestHeader,
		Body:   requestBody,
	}

	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	token, err := generateToken()
	if err != nil {
		fmt.Println("Error getting JWT Token:", err)
	}

	request, err := http.NewRequest("POST", "https://api-my.te.eg/api/user/login?channelId=WEB_APP", bytes.NewBuffer(jsonBytes))
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Jwt", token)

	//client := &http.Client{}
	resp, err := httpClient.Do(request)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	var loginJson map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&loginJson)
	if err != nil {
		fmt.Println("Error decoding JSON response:", err)
		return nil, err
	}
	fmt.Printf("Login Response: %v\n", loginJson)
	userInfo := NewUserInfo(loginJson)
	return userInfo, nil
}

func generateToken() (string, error) {
	url := "https://api-my.te.eg/api/user/generatetoken?channelId=WEB_APP"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()

	var jsonResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return "", err
	}

	jwt, ok := jsonResponse["body"].(map[string]interface{})["jwt"].(string)
	if !ok {
		return "", errors.New("JWT not found in response")
	}
	fmt.Printf("JWT TOKEN: %s", jwt)
	return jwt, nil
}

func pad(s string) string {
	blockSize := aes.BlockSize
	padSize := blockSize - (len(s) % blockSize)
	padding := strings.Repeat(string(byte(padSize)), padSize)
	return s + padding
}

func aesEncrypt(password string) string {
	key, _ := hex.DecodeString("0f0e0d0c0b0a09080706050403020100")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	rawPassword := pad(password)

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(rawPassword))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, []byte(rawPassword))

	return base64.StdEncoding.EncodeToString(ciphertext)
}
