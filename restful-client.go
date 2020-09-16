// Copyright 2018 Digital Transaction Limited.
// All Rights Reserved.
//

package parallelcore_restful_client_sdk

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

//Client to hold connection information
type Client struct {
	conn     *http.Client
	endpoint string
	certPath string
	token    string
}

//ClientData to hold data about a client
type ClientData struct {
	ID         string `json:"clientId"`
	Credential string `json:"clientCredential"`
	Roles      string `json:"clientRoles"`
	DomainName string `json:"clientDomainName"`
}

//ClientDomainData
type ClientDomainData struct {
	ID         string `json:"clientId"`
	DomainName string `json:"clientDomainName"`
}

//ClientAccessData to hold information about a clients access details
type ClientAccessData struct {
	ID                string `json:"clientId"`
	SmartContractName string `json:"scName"`
	DomainName        string `json:domainName"`
}

//SmartContractData for parsing JSON
type SmartContractData struct {
	Name        string `json:"scName"`
	FileContent []byte `json:"file-content"`
	DomainName  string `json:"domainName"`
	InitArgs    string `json:"init-args"`
}

var (
	clients = []http.Client{
		http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 200,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
		http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 200,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
		http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 200,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
		http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 200,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
		http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 200,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
	}
)

func Open(endpoint, clientId, clientCredential, certPath string) (*Client, error) {
	if certPath == "" {
		return openClient(endpoint, clientId, clientCredential)
	} else {
		return openClientWithCert(endpoint, clientId, clientCredential, certPath)
	}
}

func openClient(endpoint, clientId, clientCredential string) (*Client, error) {
	httpclient := &clients[rand.Intn(len(clients))]
	return authenticate(httpclient, endpoint, clientId, clientCredential)
}

func openClientWithCert(endpoint, clientId, clientCredential, certPath string) (*Client, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certs, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to append %q to RootCAs", certPath)
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, errors.New("No certs appended, using system certs only")
	}
	// insecure := flag.Bool("insecure-ssl", false, "Accept/Ignore all server SSL certificates")
	// flag.Parse()

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	httpclient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:     config,
		},
		Timeout: 60 * time.Second,
	}

	return authenticate(httpclient, endpoint, clientId, clientCredential)
}

func authenticate(httpclient *http.Client, endpoint, clientId, clientCredential string) (*Client, error) {
	data := url.Values{}
	data.Set("ClientId", clientId)
	data.Set("ClientCredential", clientCredential)
	request, err := http.NewRequest("POST", endpoint+"/auth", strings.NewReader(data.Encode()))

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to new request with clientId=%s, clientCredential=%s", clientId, clientCredential)
	} else {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Close = true

		res, err := httpclient.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to send request with clientId=%s, clientCredential=%s", clientId, clientCredential)
		} else {
			body, err := ioutil.ReadAll(res.Body)
			defer res.Body.Close()
			if res.StatusCode == 200 {
				return &Client{httpclient, endpoint, "", string(body)}, err
			} else {
				return nil, fmt.Errorf("Failed with StatusCode=%s, response=%s", res.StatusCode, string(body))
			}

			return nil, errors.Wrapf(err, "Failed to get response.")
		}
	}
}

func (client *Client) GetToken() string {
	return client.token
}

func (client *Client) Invoke(scName, opts string) ([]byte, string, error) {
	token := client.token
	request, err := http.NewRequest("POST", client.endpoint+"/invoke/"+scName, bytes.NewBuffer([]byte(opts)))
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Header.Set("parallelcore-return-txid", "true")
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, "", errors.Wrapf(err, "Failed with token=%s, opts=%s", token, opts)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		txId := res.Header.Get("parallelcore-txid")
		return body, txId, err
	}

	return nil, "", errors.Wrapf(err, "Failed with token=%s, opts=%s", token, opts)
}

func (client *Client) GetSmartContractTransactionJson(txId string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/transaction/json/"+txId, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, txId=%s", token, txId)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, txId=%s", token, txId)
}

func (client *Client) ListInvokableSC() ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/smartcontracts/invokable", nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s", token)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s", token)
}

func (client *Client) GetBlockchainSummary() ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/blockchain/summary", nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s", token)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s", token)
}

func (client *Client) GetBlockStatus(chainId, blockId string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/block/details/"+chainId+"/"+blockId, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, chainId=%s, blockId=%s", token, chainId, blockId)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, chainId=%s, blockId=%s", token, chainId, blockId)
}

func (client *Client) GetTransactionMetadata(txId string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/transaction/metadata/"+txId, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, txId=%s", token, txId)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, txId=%s", token, txId)
}

func (client *Client) GetLatestTxids(count string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/transactions/latest/"+count, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, count=%s", token, count)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, count=%s", token, count)
}

func (client *Client) CalculateBlockHash(chainId, blockId string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/block/hash/calculate/"+chainId+"/"+blockId, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, chainId=%s, blockId=%s", token, chainId, blockId)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, chainId=%s, blockId=%s", token, chainId, blockId)
}

//CreateClient Function to create a new client
func (client *Client) CreateClient(clientID, clientCredential, clientRoles string) ([]byte, error) {
	token := client.token
	jsonData := ClientData{
		ID:         clientID,
		Credential: clientCredential,
		Roles:      clientRoles,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", client.endpoint+"/client/"+clientID, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, clientCredential=%s, clientRoles=%s", token, clientID, clientCredential, clientRoles)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, clientCredential=%s, clientRoles=%s", token, clientID, clientCredential, clientRoles)
}

//UpdateClient Function to create a new client
func (client *Client) UpdateClient(clientID, clientCredential, clientRoles string) ([]byte, error) {
	token := client.token
	jsonData := ClientData{
		ID:         clientID,
		Credential: clientCredential,
		Roles:      clientRoles,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("PATCH", client.endpoint+"/client/"+clientID, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, clientCredential=%s, clientRoles=%s", token, clientID, clientCredential, clientRoles)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, clientCredential=%s, clientRoles=%s", token, clientID, clientCredential, clientRoles)
}

//RemoveClient Function to delete a client
func (client *Client) RemoveClient(clientID string) ([]byte, error) {
	token := client.token
	jsonData := ClientDomainData{
		ID: clientID,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("DELETE", client.endpoint+"/client/"+clientID, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s", token, clientID)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s", token, clientID)
}

//ListClient Function to list a single client
func (client *Client) ListClient(clientID string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/client/"+clientID, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s", token, clientID)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s", token, clientID)
}

//ListClients Function to list all clients
func (client *Client) ListClients() ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/clients", nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s", token)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s", token)
}

//GrantAccess function to grant a client access to a smartcontract
func (client *Client) GrantAccess(clientID, scName string) ([]byte, error) {
	token := client.token
	jsonData := ClientAccessData{
		ID:                clientID,
		SmartContractName: scName,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", client.endpoint+"/client/"+clientID+"/access/"+scName, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, smartcontract=%s", token, clientID, scName)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, smartcontract=%s", token, clientID, scName)
}

//RevokeAccess function to revoke access to a client from a smartcontract
func (client *Client) RevokeAccess(clientID, scName string) ([]byte, error) {
	token := client.token
	jsonData := ClientAccessData{
		ID:                clientID,
		SmartContractName: scName,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("DELETE", client.endpoint+"/client/"+clientID+"/access/"+scName, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, smartcontract=%s", token, clientID, scName)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, clientId=%s, smartcontract=%s", token, clientID, scName)
}

//RegisterSmartContract function to register a new smartcontract
func (client *Client) RegisterSmartContract(scName, initArgs string, fileContent []byte) ([]byte, error) {
	token := client.token
	jsonData := SmartContractData{
		Name:        scName,
		FileContent: fileContent,
		InitArgs:    initArgs,
	}
	opts, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", client.endpoint+"/smartcontract/"+scName, bytes.NewBuffer(opts))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, scName=%s, file-content=%s, init-args=%s", token, scName, fileContent, initArgs)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, scName=%s, file-content=%s, init-args=%s", token, scName, fileContent, initArgs)
}

//ListSmartContract Function to list a single smartcontract
func (client *Client) ListSmartContract(scName string) ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/smartcontract/"+scName, nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s, scName=%s", token, scName)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s, scName=%s", token, scName)
}

//ListSmartContracts Function to list all smartcontracts
func (client *Client) ListSmartContracts() ([]byte, error) {
	token := client.token
	request, err := http.NewRequest("GET", client.endpoint+"/smartcontracts", nil)
	if err == nil {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authentication", "Bearer "+token)
		request.Close = true

		res, err := client.conn.Do(request)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed with token=%s", token)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		return body, err
	}

	return nil, errors.Wrapf(err, "Failed with token=%s", token)
}
