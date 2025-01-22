package moneta

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

func (s *Service) QrPayment(request *QrPaymentReq) (*QrPaymentResp, []byte, error) {
	var err error
	defer func() {
		if err != nil {
			err = fmt.Errorf("QrPayment: %w", err)
		}
	}()

	// validation
	err = s.validateRequest(request)
	if err != nil {
		return nil, nil, fmt.Errorf("validateRequest: %v", err)
	}

	reqData := &Request{
		Envelope: Envelope{
			Header: Header{Security: Security{UsernameToken: UsernameToken{
				Username: s.config.Login,
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

	response := new(QrPaymentResp)

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
	response.OrderID = resp.Envelope.Body.InvoiceResponse.OperationInfo.ID

	return response, respBody, nil
}

func (s *Service) MakeQrPayment(request *QrPaymentReq) (*QrPaymentResp, []byte, error) {
	var err error
	defer func() {
		if err != nil {
			err = fmt.Errorf("MakeQrPayment: %w", err)
		}
	}()

	// validation
	err = s.validateRequest(request)
	if err != nil {
		return nil, nil, fmt.Errorf("validateRequest: %v", err)
	}

	reqData := MakeQrPayment{
		MakeQrPaymentEnvelope{
			Header: Header{Security: Security{UsernameToken: UsernameToken{
				Username: s.config.Login,
				Password: s.config.Password,
			}}},
			Body: MakeQrPaymentBody{
				PaymentRequest{
					Version:           s.config.Version,
					Payee:             s.config.Payee,
					Payer:             s.config.SbpPayer,
					Amount:            request.Amount,
					ClientTransaction: request.TransactionId,
					Description:       request.Description,
				}},
		},
	}

	if len(request.Attributes) > 0 {
		for _, attribute := range request.Attributes {
			reqData.Body.PaymentRequest.OperationInfo.Attributes = append(reqData.Body.PaymentRequest.OperationInfo.Attributes, attribute)
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

	response := new(QrPaymentResp)

	if inputs.HttpCode != http.StatusOK {
		response.Error = Error{
			HasError: true,
			Code:     resp.Envelope.Body.Fault.FaultCode,
			Message:  resp.Envelope.Body.Fault.FaultStr,
			Detail:   resp.Envelope.Body.Fault.Detail.FaultDetail,
		}
	}

	response.Attributes = make(map[string]string)
	for _, attribute := range resp.Envelope.Body.PaymentResponse.OperationInfo.Attributes {
		response.Attributes[attribute.Key] = attribute.Value
	}

	response.Status = resp.Envelope.Body.PaymentResponse.Status
	response.OrderID = resp.Envelope.Body.PaymentResponse.OperationInfo.ID

	return response, respBody, nil
}

func (s *Service) GetPaymentStatusByOperationId(operationId string) (*QrPaymentResp, []byte, error) {
	var err error
	defer func() {
		if err != nil {
			err = fmt.Errorf("GetPaymentStatusByOperationId: %w", err)
		}
	}()

	id, err := strconv.ParseInt(operationId, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse to int: %v", err)
	}

	type Request struct {
		Envelope struct {
			Header struct {
				Security struct {
					UsernameToken struct {
						Username string `json:"Username"`
						Password string `json:"Password"`
					} `json:"UsernameToken"`
				} `json:"Security"`
			} `json:"Header"`
			Body struct {
				GetOperationDetailsByIdRequest int64 `json:"GetOperationDetailsByIdRequest"`
			} `json:"Body"`
		} `json:"Envelope"`
	}

	request := Request{}
	request.Envelope.Header.Security.UsernameToken.Username = s.config.Login
	request.Envelope.Header.Security.UsernameToken.Password = s.config.Password
	request.Envelope.Body.GetOperationDetailsByIdRequest = id

	body := new(bytes.Buffer)
	if err = json.NewEncoder(body).Encode(request); err != nil {
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

	response := new(QrPaymentResp)

	if inputs.HttpCode != http.StatusOK {
		response.Error = Error{
			HasError: true,
			Code:     resp.Envelope.Body.Fault.FaultCode,
			Message:  resp.Envelope.Body.Fault.FaultStr,
			Detail:   resp.Envelope.Body.Fault.Detail.FaultDetail,
		}

		return response, respBody, nil
	}

	response.Attributes = make(map[string]string)
	for _, attribute := range resp.Envelope.Body.GetOperationDetailsByIdResponse.Operation.Attributes {
		response.Attributes[attribute.Key] = attribute.Value
	}

	return response, respBody, nil
}

func (s *Service) VerifySignature(fields []string, receivedSignature string) bool {
	signatureString := strings.Join(fields, "")
	signatureString += s.config.SecretKey

	hash := md5.Sum([]byte(signatureString))
	calculatedSignature := hex.EncodeToString(hash[:])

	log.Println("Calculated signature: ", calculatedSignature)
	log.Println("Received signature: ", receivedSignature)

	return calculatedSignature == receivedSignature
}

func (s *Service) validateRequest(request *QrPaymentReq) error {
	if request == nil {
		return fmt.Errorf("request struct is nil")
	}

	if request.Amount == "" {
		return fmt.Errorf("amount is empty")
	}

	if request.TransactionId == "" {
		return fmt.Errorf("transaction len is empty")
	}

	return nil
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
