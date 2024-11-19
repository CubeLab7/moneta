package moneta

import (
	"bytes"
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

func (s *Service) CreateDynamicQRInvoice(request *CreateDynamicQRInvoiceReq) (*InvoiceResponse, []byte, error) {
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

	if inputs.HttpCode != http.StatusOK {
		resp.Envelope.Body.InvoiceResponse.Error = Error{
			HasError: true,
			Code:     resp.Envelope.Body.Fault.FaultCode,
			Message:  resp.Envelope.Body.Fault.FaultStr,
			Detail:   resp.Envelope.Body.Fault.Detail.FaultDetail,
		}
	}

	return &resp.Envelope.Body.InvoiceResponse, respBody, nil
}

func sendRequest(config *Config, inputs *SendParams) (respBody []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("robokassa! SendRequest: %v", err)
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
