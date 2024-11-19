package moneta

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Service struct {
	config *Config
}

const (
	createDynamicQRInvoice = "/services"
)

func New(config *Config) *Service {
	return &Service{
		config: config,
	}
}

func (s *Service) CreateDynamicQRInvoice(request *CreateDynamicQRInvoiceReq) (*CreateDynamicQRInvoiceResp, []byte, error) {
	var err error
	defer func() {
		if err != nil {
			err = fmt.Errorf("CreateDynamicQRInvoiceReq: %w", err)
		}
	}()

	// validation
	if request == nil {
		return nil, nil, fmt.Errorf("validation! request struct is nil")
	}

	if request.Amount == "" {
		return nil, nil, fmt.Errorf("validation! amount is empty")
	}

	if request.TransactionId == "" {
		return nil, nil, fmt.Errorf("validation! transaction len is empty")
	}

	reqData := &Request{
		Envelope: Envelope{
			Header: Header{Security: Security{UsernameToken: UsernameToken{
				Username: s.config.Username,
				Password: s.config.Password,
			}}},
			Body: Body{
				InvoiceRequest{
					Version:           s.config.Version,
					Payee:             s.config.Payee,
					Payer:             s.config.SbpPayer,
					Amount:            request.Amount,
					ClientTransaction: request.TransactionId,
					Description:       request.Description,
					OperationInfo: OperationInfo{
						Attributes: []Attribute{{
							Key:   "CUSTOMFIELD:QRTTL",
							Value: "11",
						}},
					},
				}},
		},
	}

	if len(request.Attributes) > 0 {
		for _, attribute := range request.Attributes {
			reqData.Body.InvoiceRequest.OperationInfo.Attributes = append(reqData.Body.InvoiceRequest.OperationInfo.Attributes, attribute)
		}
	}

	body := new(bytes.Buffer)
	if err = json.NewEncoder(body).Encode(reqData); err != nil {
		return nil, nil, fmt.Errorf("can't encode request: %s", err)
	}

	resp := new(Response)
	inputs := SendParams{
		Path:       createDynamicQRInvoice,
		HttpMethod: http.MethodPost,
		Response:   &resp,
		Body:       body,
	}

	var respBody []byte
	if respBody, err = sendRequest(s.config, &inputs); err != nil {
		return nil, respBody, fmt.Errorf("sendRequest: %w", err)
	}

	response := new(CreateDynamicQRInvoiceResp)

	if inputs.HttpCode != http.StatusOK {
		response.Error = Error{
			HasError: true,
			Code:     resp.Envelope.Body.Fault.FaultCode,
			Message:  resp.Envelope.Body.Fault.FaultStr,
			Detail:   resp.Envelope.Body.Fault.Detail.FaultDetail,
		}
	}

	response.Attributes = make(map[string]string)
	for _, attribute := range resp.Envelope.Body.InvoiceResponse.OperationInfo.Attributes {
		response.Attributes[attribute.Key] = attribute.Value
	}

	response.Status = resp.Envelope.Body.InvoiceResponse.Status
	response.OrderID = resp.Envelope.Body.InvoiceResponse.Transaction

	return response, respBody, nil
}

func sendRequest(config *Config, inputs *SendParams) (respBody []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("moneta! SendRequest: %v", err)
		}
	}()

	baseURL, err := url.Parse(config.Url)
	if err != nil {
		return respBody, fmt.Errorf("can't parse URI from config: %w", err)
	}

	baseURL.Path += inputs.Path

	query := baseURL.Query()
	for key, value := range inputs.QueryParams {
		query.Set(key, value)
	}

	baseURL.RawQuery = query.Encode()

	finalUrl := baseURL.String()

	req, err := http.NewRequest(inputs.HttpMethod, finalUrl, inputs.Body)
	if err != nil {
		return respBody, fmt.Errorf("can't create request! Err: %s", err)
	}

	req.Header.Add("Content-Type", "application/json")

	httpClient := http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: time.Second * time.Duration(config.IdleConnTimeoutSec),
		},
		Timeout: time.Second * time.Duration(config.RequestTimeoutSec),
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return respBody, fmt.Errorf("can't do request! Err: %s", err)
	}
	defer resp.Body.Close()

	inputs.HttpCode = resp.StatusCode

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return respBody, fmt.Errorf("can't read response body! Err: %w", err)
	}

	if resp.StatusCode == http.StatusInternalServerError {
		return respBody, fmt.Errorf("error: %v", string(respBody))
	}

	if err = json.Unmarshal(respBody, &inputs.Response); err != nil {
		return respBody, fmt.Errorf("can't unmarshall response: '%v'. Err: %w", string(respBody), err)
	}

	return
}

type SignatureData struct {
	MntID             string
	MntTransactionID  string
	MntOperationID    string
	MntAmount         string
	MntCurrencyCode   string
	MntSubscriberID   string
	MntTestMode       string
	ReceivedSignature string
}

func (s *Service) VerifySignature(data SignatureData) bool {
	signatureString := fmt.Sprintf("%s%s%s%s%s%s%s%s",
		data.MntID,
		data.MntTransactionID,
		data.MntOperationID,
		data.MntAmount,
		data.MntCurrencyCode,
		data.MntSubscriberID,
		data.MntTestMode,
		s.config.SignatureVerificationCode,
	)

	hash := md5.Sum([]byte(signatureString))
	calculatedSignature := hex.EncodeToString(hash[:])

	return calculatedSignature == data.ReceivedSignature
}
