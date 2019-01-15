package baifu

import (
	"crypto/rsa"
	"io"

	"github.com/ideazxy/iso8583"
)

//ActivateRequest ....
type ActivateRequest struct {
	Op         string
	TradeNo    string
	PosSN      string
	ActiveCode string
	Random     []byte
	MacAddr    []byte
	PublicKey  *rsa.PublicKey
}

//WriteTo ....
func (r *ActivateRequest) WriteTo(w io.Writer) error {
	m := Message{}
	m.MTI = "0800"
	m.TPDU = "6000040000"
	m.AppClass = "60"
	m.MajorVersion = "32"
	m.Status = "0"
	m.ProcessFlag = "0"
	m.MinorVersion = "321704"
	m.VendorNo = "118"
	m.MerchantNo = "000000000000000"
	m.TerminalNo = "00000000000000000000"
	m.EncryptedFlag = "0"
	m.ChannelNo = "0001"
	m.D3 = iso8583.NewNumeric("300000")
	m.D11 = iso8583.NewNumeric("000078")
	m.D46 = iso8583.NewLllvar([]byte("QR66"))
	acode, err := DesEncrypt([]byte(r.ActiveCode), r.Random[0:8], ModeCBC, PaddingNone)
	if err != nil {
		return err
	}
	m.D55 = iso8583.NewLllvar(acode)
	key, err := RSAEncrypt(r.Random, r.PublicKey)
	m.D59 = iso8583.NewLllvar(key)
	m.D63 = iso8583.NewLllvar(r.MacAddr)
	return WriteMessage(w, &m)
}

//ActivateResponse ....
type ActivateResponse struct {
	Op           string
	TradeNo      string
	Time         string
	Date         string
	ReturnCode   string
	PosCode      string
	MerchantNo   string
	MerchantName string
	ErrorMessage string
	StoreInfo    string
	MainKey      string
}

//CheckInRequest ....
type CheckInRequest struct {
	Op           string
	TradeNo      string
	PosCode      string
	MerchantNo   string
	TradeType    string
	TradeBatchNo string
	AppInfo      string
}

//CheckInResponse ....
type CheckInResponse struct {
	Op           string
	TradeNo      string
	Time         string
	Date         string
	ReturnCode   string
	PosCode      string
	MerchantNo   string
	ErrorMessage string
	TradeType    string
	TradeBatchNo string
	PlatformInfo string
	WorkKey      string
}

//LoginRequest ....
type LoginRequest struct {
	Op               string
	TradeNo          string
	PosCode          string
	MerchantNo       string
	OperatorPassword string
	TradeType        string
	TradeBatchNo     string
	Custom1          string
	OperatorNo       string
}

//LoginResponse ....
type LoginResponse struct {
	Op           string
	TradeNo      string
	Time         string
	Date         string
	ReturnCode   string
	PosCode      string
	MerchantNo   string
	ErrorMessage string
	TradeType    string
	TradeBatchNo string
	Custom1      string
	OperatorNo   string
}

//SigninRequest ....
type SigninRequest struct {
	Op               string
	TradeNo          string
	PosCode          string
	MerchantNo       string
	OperatorPassword string
	TradeType        string
	TradeBatchNo     string
	Custom1          string
	OperatorNo       string
}

//SignoutResponse ....
type SignoutResponse struct {
	Op           string
	TradeNo      string
	Time         string
	Date         string
	ReturnCode   string
	PosCode      string
	MerchantNo   string
	ErrorMessage string
	TradeType    string
	TradeBatchNo string
	Custom1      string
	OperatorNo   string
}
