package moneta

import (
	"io"
)

type Config struct {
	IdleConnTimeoutSec int
	RequestTimeoutSec  int
	Username           string
	Password           string
	Url                string
	Payee              string
	SbpPayer           string
	Version            string
}

type SendParams struct {
	HttpCode    int
	Path        string
	HttpMethod  string
	Body        io.Reader
	QueryParams map[string]string
	Response    interface{}
}

type Request struct {
	Envelope `json:"Envelope"`
}

type Response struct {
	Envelope struct {
		Header Header `json:"Header"`
		Body   struct {
			InvoiceResponse InvoiceResponse `json:"InvoiceResponse,omitempty"`
			Fault           Fault           `json:"fault,omitempty"`
		} `json:"Body"`
	} `json:"Envelope"`
}

type Envelope struct {
	Header Header `json:"Header"`
	Body   Body   `json:"Body"`
}

type Header struct {
	Security Security `json:"Security"`
}

type Security struct {
	UsernameToken UsernameToken `json:"UsernameToken"`
}

type UsernameToken struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

type Body struct {
	InvoiceRequest InvoiceRequest `json:"InvoiceRequest,omitempty"`
}

type InvoiceReqBody struct {
	InvoiceRequest *InvoiceRequest `json:"InvoiceRequest,omitempty"`
}

type InvoiceRequest struct {
	Version           string        `json:"version"`
	Payer             string        `json:"payer"`
	Payee             string        `json:"payee"`
	Amount            string        `json:"amount"`
	ClientTransaction string        `json:"clientTransaction"`
	Description       string        `json:"description"`
	OperationInfo     OperationInfo `json:"operationInfo"`
}

type InvoiceResponse struct {
	DateTime          string        `json:"dateTime"`
	OperationInfo     OperationInfo `json:"operationInfo"`
	ClientTransaction string        `json:"clientTransaction"`
	Transaction       int           `json:"transaction"`
	Status            string        `json:"status"`
	Error             Error         `json:"error"`
}

type Error struct {
	HasError bool   `json:"has_error"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Detail   string `json:"detail"`
}

type OperationInfo struct {
	Attributes []Attribute `json:"attribute"`
}

type Attribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Fault struct {
	FaultCode string `json:"faultcode"`
	FaultStr  string `json:"faultstring"`
	Detail    Detail `json:"detail"`
}

type Detail struct {
	FaultDetail string `json:"faultDetail"`
}

type CreateDynamicQRInvoiceReq struct {
	Amount        string `json:"amount"`
	TransactionId string `json:"transaction_id"`
	Description   string `json:"description"`
	Attributes    []Attribute
}
