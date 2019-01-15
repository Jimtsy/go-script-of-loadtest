package baifu

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hemayun/mix"
	"io/ioutil"
	"path"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	//"github.com/go-xweb/log"

	"github.com/ideazxy/iso8583"
	"errors"
	"time"
	"net"
	"os"
	"strings"
	"github.com/jacexh/ultron"
	"go.uber.org/zap"
	"github.com/axgle/mahonia"
)

//LoadSimulator 从文件中加载一个终端模拟器
func LoadSimulator(deviceID string) (*Simulator, error) {
	b, err := ioutil.ReadFile(path.Join(conf, "devices", deviceID+".sim"))
	if err != nil {
		return nil, err
	}
	//log.Println(string(b))
	var sim Simulator
	err = json.Unmarshal(b, &sim)
	if err != nil {
		return nil, err
	}

	return &sim, nil
}

//NewSimulator 创建一个终端模拟器
func NewSimulator(posSN string, ch string) (*Simulator, error) {
	pkf := path.Join(conf, "devices", posSN+".pem")
	if !mix.Exist(pkf) {
		pkf = path.Join(conf, "publicKey.pem")
	}
	b, err := ioutil.ReadFile(pkf)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Simulator{
		Addr:         serverAddr,
		AppClass:     "60",
		MajorVersion: "32",
		MinorVersion: "321704",
		VendorNo:     "118",
		ChannelNo:    ch,
		PosSN:        posSN,
		MacAddr:      []byte{0, 0, 0, 0, 0, 0},
		PublicKey:    rsaPublicKey.(*rsa.PublicKey),
		TradeParams:  map[string]string{},
		MerchantNo:   "21680002798969",
		TerminalNo:   "2100216340002215865",
	}, nil
}

//Simulator ....
type Simulator struct {
	AppClass     string
	MajorVersion string
	MinorVersion string
	VendorNo     string
	MerchantNo   string
	TerminalNo   string
	// EncryptedFlag string
	ChannelNo    string
	MacAddr      []byte
	PosSN        string
	PublicKey    *rsa.PublicKey `json:"-"`
	Seq          int
	MerchantName string
	AdverName    string
	StoreName    string
	StoreID      string
	TerminalName string
	MainKey      []byte
	Addr         string
	Batch        string
	TradeParams  map[string]string
	WorkKey      []byte
	TDK          []byte
	TAK          []byte
	Operator     string
}

//Sequence ....
func (s *Simulator) Sequence() string {
	s.Seq++
	seq := fmt.Sprintf("%06d", s.Seq)
	if s.Seq >= 999999 {
		s.Seq = 0
	}
	return seq
}

// //BatchNo ....
// func (s *Simulator) BatchNo() []byte {
// 	// 	——	数据元长度	     N3
// 	//  ——	60.1  消息类型码 N2
// 	//      60.2  批次号    N6
// 	s.Batch++
// 	batch := fmt.Sprintf("%06d", s.Batch)
// 	if s.Batch >= 999999 {
// 		s.Batch = 0
// 	}
// 	log.Println("BatchNo", batch)
// 	// mt := append(bcd([]byte("00")), bcd([]byte(batch))...)
// 	// l := rbcd([]byte(fmt.Sprintf("%d", len(mt))))

// 	return lbcd([]byte("00")) //append(l, mt...)
// }

//Login ....
func (s *Simulator) Login(operator string) error {
	s.Operator = operator
	m := Message{}
	m.MTI = "0800"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	m.MerchantNo = s.MerchantNo
	m.TerminalNo = s.TerminalNo
	m.EncryptedFlag = "1"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	m.Sign = true
	m.TDK = s.TDK
	m.TAK = s.TAK
	m.D3 = iso8583.NewNumeric("330000")
	m.D11 = iso8583.NewNumeric(s.Sequence())
	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
	m.D60 = iso8583.NewLllnumeric("00")
	//m.D60 = iso8583.NewLllnumeric("00")
	m.D63 = iso8583.NewLllvar([]byte(operator))
	mm, err := Post(s.Addr, &m)
	if err != nil {
		return err
	}
	mahonia.NewDecoder("gbk").ConvertString(string(mm.D55.Value))
	if mm.D39.Value != "00" {
		return fmt.Errorf("%v %s", mm.D39.Value, GbkToUtf8(mm.D55.Value))
	}
	s.Batch = mm.D60.Value[2:]
	log.Infof("批次号 %d %s\n", len(mm.D60.Value), mm.D60.Value)
	b, _ := json.Marshal(s)
	log.Infof(string(b))
	err = ioutil.WriteFile(path.Join(conf, "devices", s.PosSN+".sim"), b, os.ModePerm)
	log.Infof("POS序号:%v 终端号: %v 主密钥: %X  TAK: %X TDK: %X %s登陆%v 批次号 %s %v\n", s.PosSN, s.TerminalNo, s.MainKey, s.TAK, s.TDK, operator, string(mm.D55.Value), s.Batch, err)
	return nil
}


//Activate ....
func (s *Simulator) Activate(code string) error {
	 //if len(s.MainKey) > 0 {
		//fmt.Println("终端已激活，忽略激活操作，POS序号:%v 终端号: %v 主密钥: %X\n", s.PosSN, s.TerminalNo, s.MainKey)
		//return nil
	 //}
	m := Message{}
	m.MTI = "0800"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	// m.MerchantNo = strings.Repeat(" ", 15)
	// m.TerminalNo = strings.Repeat(" ", 20)
	m.EncryptedFlag = "0"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	m.D3 = iso8583.NewNumeric("300000")
	m.D11 = iso8583.NewNumeric(s.Sequence())
	m.D46 = iso8583.NewLllvar([]byte(s.PosSN))
	random := genKey(8)                      //产生8字节安全随机密钥
	tk := []byte(hex.EncodeToString(random)) //把8字节随机数编码成16进制字符串，得到16字节字符串数组
	//fmt.Println("传输密钥: ", tk)
	acode, err := DesEncrypt([]byte(code), tk, ModeECB, PaddingNone)
	if err != nil {
		//ultron.Logger.Warn("", zap.Any("error", err))
		return err
	}
	m.D55 = iso8583.NewLllvar(acode)
	key, err := RSAEncrypt(tk, s.PublicKey)
	m.D59 = iso8583.NewLllvar(key)
	m.D63 = iso8583.NewLllvar(s.MacAddr)
	mm, err := Post(s.Addr, &m)
	if err != nil {
		ultron.Logger.Warn("", zap.Any("error", err))
		return err
	}
	if mm.D39.Value != "00" {
		//ultron.Logger.Warn("",
		//	zap.Any("mm.D39.Value", mm.D39.Value),
		//	zap.Any("D55", string(GbkToUtf8(mm.D55.Value))))
		//if mm.D39.Value != "96" {
		//	return fmt.Errorf("%v %v", mm.D39.Value, GbkToUtf8(mm.D55.Value))
		//}
		return errors.New("D39: " + mm.D39.Value + ", D55:"+ string(mm.D55.Value))
	}

	s.TerminalNo = strings.TrimSpace(mm.D41.Value)
	s.MerchantNo = strings.TrimSpace(mm.D42.Value)
	s.MerchantName = string(Utf8ToGbk(mm.D46.Value))
	var store = map[string]interface{}{}

	err = json.Unmarshal(GbkToUtf8(mm.D62.Value), &store)
	if err != nil {
		ultron.Logger.Warn("", zap.Any("error", err))
		return err
	}
	if v, has := store["storename"]; has {
		s.StoreName = v.(string)
	}
	if v, has := store["storeid"]; has {
		s.StoreID = v.(string)
	}
	if v, has := store["advername"]; has {
		s.AdverName = v.(string)
	}
	if v, has := store["termname"]; has {
		s.TerminalName = v.(string)
	}

	//fmt.Println("主密钥密文：", mm.D63.Value[0:16])
	b, _ := hex.DecodeString(string(mm.D63.Value[0:16]))
	mk, err := DesDecrypt(b, random, ModeECB, PaddingNone)
	if err != nil {
		ultron.Logger.Warn("", zap.Any("error", err))
		return err
	}
	s.MainKey = mk
	//fmt.Println("主密钥明文：", mk)
	checkMK, err := DesEncrypt(make([]byte, 8), mk, ModeECB, PaddingNone)
	if bytes.Compare(mm.D63.Value[16:], checkMK[0:4]) != 0 {
		ultron.Logger.Warn("", zap.Any(" mm.D63.Value[16:]",  mm.D63.Value[16:]),
			zap.Any("checkMK[0:4]", checkMK[0:4]))

		return fmt.Errorf("主密钥校验值：%X 主密钥校验值：%X 校验失败", mm.D63.Value[16:], checkMK[0:4])

	}
	//	checkMk, err := DesEncrypt(ivKey, mk, ModeECB, PaddingNone)
	//log.Printf("主密钥校验值：%X 主密钥校验值：%X 校验结果 %v\n", mm.D63.Value[16:], checkMK[0:4], bytes.Compare(mm.D63.Value[16:], checkMK[0:4]) == 0)
	b, _ = json.Marshal(s)
	//log.Println(string(b))
	err = ioutil.WriteFile(path.Join(conf, "devices", s.PosSN+".sim"), b, os.ModePerm)
	//log.Infof("POS序号:%v 终端号: %v 主密钥: %X 激活 %v %v\n", s.PosSN, s.TerminalNo, mk, string(mm.D55.Value), err)
	return nil
}

//activate ....
func (s *Simulator) activate(code string) (*Message, error) {
	// if len(s.MainKey) > 0 {
	// 	log.Infof("终端已激活，忽略激活操作，POS序号:%v 终端号: %v 主密钥: %X\n", s.PosSN, s.TerminalNo, s.MainKey)
	// 	return nil
	// }
	m := &Message{}
	m.MTI = "0800"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	// m.MerchantNo = strings.Repeat(" ", 15)
	// m.TerminalNo = strings.Repeat(" ", 20)
	m.EncryptedFlag = "0"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	m.D3 = iso8583.NewNumeric("300000")
	m.D11 = iso8583.NewNumeric(s.Sequence())
	m.D46 = iso8583.NewLllvar([]byte(s.PosSN))
	random := genKey(8)                      //产生8字节安全随机密钥
	tk := []byte(hex.EncodeToString(random)) //把8字节随机数编码成16进制字符串，得到16字节字符串数组
	//log.Printf("传输密钥 %X\n", tk)
	acode, err := DesEncrypt([]byte(code), tk, ModeECB, PaddingNone) // 激活码
	if err != nil {
		return m, err
	}
	m.D55 = iso8583.NewLllvar(acode)
	key, err := RSAEncrypt(tk, s.PublicKey)
	m.D59 = iso8583.NewLllvar(key)
	m.D63 = iso8583.NewLllvar(s.MacAddr)
	return doPost(m)
}


//Post ....
func Post(addr string, msg *Message) (*Message, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	err = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		return nil, err
	}
	err = WriteMessage(conn, msg)
	if err != nil {
		return nil, err
	}
	err = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		return nil, err
	}
	rmsg := &Message{}
	rmsg.TAK = msg.TAK
	rmsg.TDK = msg.TDK
	err = ReadMessage(conn, rmsg)
	if err != nil {
		return nil, err
	}
	return rmsg, nil
}

// SignIn ....
func (s *Simulator) SignIn() error {
	// if len(s.WorkKey) > 0 {
	// 	log.Infof("终端已签到，忽略签到操作，POS序号:%v 终端号: %v 主密钥: %X  TAK: %X TDK: %X\n", s.PosSN, s.TerminalNo, s.MainKey, s.TAK, s.TDK)
	// 	return nil
	// }
	m := Message{}
	m.MTI = "0800"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	m.MerchantNo = s.MerchantNo
	m.TerminalNo = s.TerminalNo
	m.EncryptedFlag = "0"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	// m.Sign = true
	// m.WorkKey = s.MainKey
	m.D3 = iso8583.NewNumeric("320000")
	m.D11 = iso8583.NewNumeric(s.Sequence())
	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
	m.D60 = iso8583.NewLllnumeric("00201804230002")
	//m.D60 = iso8583.NewLllnumeric(string(bcdl2Ascii([]byte("00"), 2)))
	appInfo := map[string]interface{}{
		"part_serial":      "n1,sn1;n2,sn2;n3,sn3;",    //配件列表
		"app_list":         "app1,v1;app2,v2;app3,v3;", //应用列表
		"SystemVersion":    "12321312",                 //系统版本号
		"BootVersion":      "12321312",                 //BOOT版本号
		"DriverVersion":    "12321312",                 //驱动版本号
		"flag":             "1",                        //防切机标识
		"MacAddress":       "12321312",                 //MAC地址
		"LBS":              "12321312",                 //
		"GPS":              "12321312",
		"WIFI":             "12321312",
		"GPRSVersion":      "12321312",
		"ConnSignalIntens": "wifi", //通讯方式+信号强度
	}
	b, _ := json.Marshal(appInfo)
	//log.Println(len(b))
	//m.D62 = iso8583.NewLllvar([]byte(mahonia.NewEncoder("gbk").ConvertString(string(b))))
	m.D62 = iso8583.NewLllvar(b)
	//m.D64 = &iso8583.Binary{Value: make([]byte, 0), FixLen: 0}
	mm, err := Post(s.Addr, &m)
	if err != nil {
		return err
	}
	if mm.D39.Value != "00" {
		return fmt.Errorf("%v %v", mm.D39.Value, GbkToUtf8(mm.D55.Value))
	}
	if len(mm.D62.Value) > 0 {
		var info = map[string]string{}
		err = json.Unmarshal(GbkToUtf8(mm.D62.Value), &info)
		if err != nil {
			return err
		}
		s.TradeParams = info
	}
	// wk, err := DesDecrypt(mm.D63.Value, s.MainKey, ModeECB, PaddingZero) //DesCBCDecrypt(mm.D63.Value, s.MainKey)
	// log.Printf("工作密钥密文: %X 主密钥: %X\n", mm.D63.Value, s.MainKey)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("工作密钥明文: %X\n", wk)
	s.WorkKey = mm.D63.Value

	key1, err := DesDecrypt(mm.D63.Value[0:8], s.MainKey, ModeECB, PaddingZero) //DesCBCDecrypt(mm.D63.Value, s.MainKey)
	//fmt.Println("Key1密文: ", mm.D63.Value[0:8], "主密钥: ", s.MainKey)
	if err != nil {
		//panic(err)
		return err
	}
	//fmt.Println("Key1明文: ", key1)
	checkKey1, err := DesEncrypt(ivKey, key1, ModeECB, PaddingNone)


	if bytes.Compare(mm.D63.Value[16:20], checkKey1[0:4]) != 0 {
		//fmt.Println("TAK校验失败：%X %X", mm.D63.Value[16:20], checkKey1[0:4])

	}
	s.TAK = key1

	key2, err := DesDecrypt(mm.D63.Value[20:28], s.MainKey, ModeECB, PaddingZero) //DesCBCDecrypt(mm.D63.Value, s.MainKey)
	//log.Printf("Key2密文: %X 主密钥: %X\n", mm.D63.Value[20:28], s.MainKey)
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("Key2明文: %X\n", key2)
	checkKey2, err := DesEncrypt(ivKey, key2, ModeECB, PaddingNone)
	//log.Printf("Key2校验：%X %X %v\n", mm.D63.Value[36:], checkKey2[0:4], bytes.Compare(mm.D63.Value[36:], checkKey2[0:4]))
	if bytes.Compare(mm.D63.Value[36:], checkKey2[0:4]) != 0 {
		return fmt.Errorf("TDK校验失败：%X %X", mm.D63.Value[36:], checkKey2[0:4])
	}
	s.TDK = key2

	b, _ = json.Marshal(s)
	//log.Println(string(b))
	err = ioutil.WriteFile(path.Join(conf, "devices", s.PosSN+".sim"), b, os.ModePerm)
	//fmt.Println("POS序号:%v 终端号: %v 主密钥: %X  TAK: %X TDK: %X 签到%v %v\n", s.PosSN, s.TerminalNo, s.MainKey, s.TAK, s.TDK, string(mm.D55.Value), err)
	return nil
}

////signIn ....
//func (s *Simulator) signIn() (*Message, error) {
//	// if len(s.WorkKey) > 0 {
//	// 	log.Infof("终端已签到，忽略签到操作，POS序号:%v 终端号: %v 主密钥: %X  TAK: %X TDK: %X\n", s.PosSN, s.TerminalNo, s.MainKey, s.TAK, s.TDK)
//	// 	return nil
//	// }
//	m := &Message{}
//	m.MTI = "0800"
//	m.TPDU = "6000040000"
//	m.Status = "0"
//	m.ProcessFlag = "0"
//	m.MerchantNo = s.MerchantNo
//	m.TerminalNo = s.TerminalNo
//	m.EncryptedFlag = "0"
//	m.AppClass = s.AppClass
//	m.MajorVersion = s.MajorVersion
//	m.MinorVersion = s.MinorVersion
//	m.VendorNo = s.VendorNo
//	m.ChannelNo = s.ChannelNo
//	// m.Sign = true
//	// m.WorkKey = s.MainKey
//	m.D3 = iso8583.NewNumeric("320000")
//	m.D11 = iso8583.NewNumeric(s.Sequence())
//	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
//	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
//	m.D60 = iso8583.NewLllnumeric("00201804230002")
//	//m.D60 = iso8583.NewLllnumeric(string(bcdl2Ascii([]byte("00"), 2)))
//	appInfo := map[string]interface{}{
//		"part_serial":      "n1,sn1;n2,sn2;n3,sn3;",    //配件列表
//		"app_list":         "app1,v1;app2,v2;app3,v3;", //应用列表
//		"SystemVersion":    "12321312",                 //系统版本号
//		"BootVersion":      "12321312",                 //BOOT版本号
//		"DriverVersion":    "12321312",                 //驱动版本号
//		"flag":             "1",                        //防切机标识
//		"MacAddress":       "12321312",                 //MAC地址
//		"LBS":              "12321312",                 //
//		"GPS":              "12321312",
//		"WIFI":             "12321312",
//		"GPRSVersion":      "12321312",
//		"ConnSignalIntens": "wifi", //通讯方式+信号强度
//	}
//	b, _ := json.Marshal(appInfo)
//	//log.Println(len(b))
//	//m.D62 = iso8583.NewLllvar([]byte(mahonia.NewEncoder("gbk").ConvertString(string(b))))
//	m.D62 = iso8583.NewLllvar(b)
//	//m.D64 = &iso8583.Binary{Value: make([]byte, 0), FixLen: 0}
//	return doPost(m)
//}

////login ....
//func (s *Simulator) login(operator string) (*Message, error) {
//	s.Operator = operator
//	m := &Message{}
//	m.MTI = "0800"
//	m.TPDU = "6000040000"
//	m.Status = "0"
//	m.ProcessFlag = "0"
//	m.MerchantNo = s.MerchantNo
//	m.TerminalNo = s.TerminalNo
//	m.EncryptedFlag = "1"
//	m.AppClass = s.AppClass
//	m.MajorVersion = s.MajorVersion
//	m.MinorVersion = s.MinorVersion
//	m.VendorNo = s.VendorNo
//	m.ChannelNo = s.ChannelNo
//	m.Sign = true
//	m.TDK = s.TDK
//	m.TAK = s.TAK
//	m.D3 = iso8583.NewNumeric("330000")
//	m.D11 = iso8583.NewNumeric(s.Sequence())
//	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
//	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
//	m.D60 = iso8583.NewLllnumeric("00")
//	//m.D60 = iso8583.NewLllnumeric("00")
//	m.D63 = iso8583.NewLllvar([]byte(operator))
//	return doPost(m)
//}
//
////logout ....
//func (s *Simulator) logout() (*Message, error) {
//	m := &Message{}
//	m.MTI = "0800"
//	m.TPDU = "6000040000"
//	m.Status = "0"
//	m.ProcessFlag = "0"
//	m.MerchantNo = s.MerchantNo
//	m.TerminalNo = s.TerminalNo
//	m.EncryptedFlag = "1"
//	m.AppClass = s.AppClass
//	m.MajorVersion = s.MajorVersion
//	m.MinorVersion = s.MinorVersion
//	m.VendorNo = s.VendorNo
//	m.ChannelNo = s.ChannelNo
//	m.Sign = true
//	m.TDK = s.TDK
//	m.TAK = s.TAK
//	m.D3 = iso8583.NewNumeric("340000")
//	m.D11 = iso8583.NewNumeric(s.Sequence())
//	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
//	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
//	m.D60 = iso8583.NewLllnumeric("00" + s.Batch)
//	m.D63 = iso8583.NewLllvar([]byte(s.Operator))
//	return doPost(m)
//}

//pay ....
func (s *Simulator) pay(barCode string) (*Message, error) {

	if len(s.TAK) == 0 {
		return nil, errors.New("设备未激活")
	}
	if "" == s.Operator {
		return nil, errors.New("收银员未登陆")

	}

	m := &Message{}
	m.MTI = "0200"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	m.MerchantNo = s.MerchantNo
	m.TerminalNo = s.TerminalNo
	m.EncryptedFlag = "1"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	m.Sign = true
	m.TDK = s.TDK
	m.TAK = s.TAK
	m.D3 = iso8583.NewNumeric("010900")
	m.D4 = iso8583.NewNumeric("1")
	m.D11 = iso8583.NewNumeric(s.Sequence())
	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
	m.D46 = iso8583.NewLllvar([]byte(barCode))
	m.D49 = iso8583.NewAlphanumeric("CNY")
	m.D60 = iso8583.NewLllnumeric("00" + s.Batch)
	if strings.HasPrefix(barCode, prefixBarCodeWX) {
		m.D59 = iso8583.NewLllvar([]byte("微信"))
	}else if strings.HasPrefix(barCode, prefixBarCodeAL) {
		m.D59 = iso8583.NewLllvar([]byte("支付宝"))
	}else {
		ultron.Logger.Error("invalid barcode: " + barCode)
	}
	m.D63 = iso8583.NewLllvar([]byte(s.Operator))

	return doPost(m)
}


// Query ....
func (s *Simulator) query() (*Message, error)  {
	m := Message{}
	m.MTI = "0200"
	m.TPDU = "6000040000"
	m.Status = "0"
	m.ProcessFlag = "0"
	m.MerchantNo = s.MerchantNo
	m.TerminalNo = s.TerminalNo
	m.EncryptedFlag = "1"
	m.AppClass = s.AppClass
	m.MajorVersion = s.MajorVersion
	m.MinorVersion = s.MinorVersion
	m.VendorNo = s.VendorNo
	m.ChannelNo = s.ChannelNo
	m.Sign = true
	m.TDK = s.TDK
	m.TAK = s.TAK
	m.D3 = iso8583.NewNumeric("110000")
	m.D11 = iso8583.NewNumeric(s.Sequence()) // 交易流水号
	m.D41 = iso8583.NewAlphanumeric(s.TerminalNo)
	m.D42 = iso8583.NewAlphanumeric(s.MerchantNo)
	m.D46 = iso8583.NewLllvar([]byte("1002259244527965")) // 订单号
	m.D49 = iso8583.NewAlphanumeric("CNY")
	m.D60 = iso8583.NewLllnumeric("00" + s.Batch)

	p := map[string]interface{}{
		"trade_no":      "4200000233201901047618451331",
	}

	b, _ := json.Marshal(p)
	m.D62 = iso8583.NewLllvar(b)

	m.D63 = iso8583.NewLllvar([]byte(s.Operator))

	//if err != nil {
	//	ultron.Logger.Error("query", zap.Any("response", err))
	//	return err
	//}
	//if mm.D39.Value != "00" {
	//	ultron.Logger.Info("query",
	//		zap.String("D39", string(mm.D39.Value)),
	//		zap.String("D55", string(GbkToUtf8(mm.D55.Value))))
	//}

	return Post(s.Addr, &m)
}


func GbkToUtf8(s []byte) []byte {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil
	}
	return d
}

func Utf8ToGbk(s []byte) []byte {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewEncoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil
	}
	return d
}
