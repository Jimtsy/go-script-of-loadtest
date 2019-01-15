package baifu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"strings"
	//"github.com/go-xweb/log"
	"github.com/ideazxy/iso8583"
)

var iparser = &iso8583.Parser{MtiEncode: iso8583.BCD}

func init() {

	iparser.Register("0800", &Message{})
	iparser.Register("0810", &Message{})
	iparser.Register("0200", &Message{})
	iparser.Register("0210", &Message{})
	iparser.Register("0220", &Message{})
	iparser.Register("0230", &Message{})
}

//ReadMessage ....
func ReadMessage(r io.Reader, msg *Message) error {
	var l uint16
	err := binary.Read(r, binary.BigEndian, &l)
	if err != nil {
		return err
	}
	if l == 0 {
		return io.EOF
	}
	//log.Println("read length", l)
	b := make([]byte, l)
	i, err := io.ReadFull(r, b)
	if err != nil {
		return err
	}
	if l != uint16(i) {
		return fmt.Errorf("数据包错误 %v/%v", l, i)
	}
	//log.Printf("<<<< %d/%d %#X\n", l, i, b)

	err = Unmarshal(b, msg)
	//log.Printf("Response %v %v\n", msg, err)
	return err
}

//WriteMessage ....
func WriteMessage(w io.Writer, msg *Message) error {
	b, err := Marshal(msg)
	//log.Printf("Request %v %v\n", msg, err)
	if err != nil {
		return err
	}
	l := uint16(len(b))
	err = binary.Write(w, binary.BigEndian, &l)
	if err != nil {
		return err
	}
	_, err = w.Write(b)

	//log.Printf(">>>> %d/%d %#X %v\n", i, l, b, err)
	return err
}

func lbcd(data []byte) []byte {
	if len(data)%2 != 0 {
		return bcd(append(data, "0"...))
	}
	return bcd(data)
}

func rbcd(data []byte) []byte {
	if len(data)%2 != 0 {
		return bcd(append([]byte("0"), data...))
	}
	return bcd(data)
}

// Encode numeric in ascii into bsd (be sure len(data) % 2 == 0)
func bcd(data []byte) []byte {
	out := make([]byte, len(data)/2+1)
	n, err := hex.Decode(out, data)
	if err != nil {
		panic(err.Error())
	}
	return out[:n]
}

func bcdl2Ascii(data []byte, length int) []byte {
	return bcd2Ascii(data)[:length]
}

func bcdr2Ascii(data []byte, length int) []byte {
	out := bcd2Ascii(data)
	return out[len(out)-length:]
}

func bcd2Ascii(data []byte) []byte {
	out := make([]byte, len(data)*2)
	n := hex.Encode(out, data)
	return out[:n]
}

//Message ...
type Message struct {
	TPDU          string //10n
	AppClass      string //2n
	MajorVersion  string //2n
	Status        string //1n
	ProcessFlag   string //1n
	MinorVersion  string //6n
	VendorNo      string //3n
	MerchantNo    string //15n
	TerminalNo    string //20n
	EncryptedFlag string //1n
	ChannelNo     string //4n

	TDK  []byte
	TAK  []byte
	Sign bool
	MTI  string
	D3   *iso8583.Numeric      `field:"3" length:"6" encode:"bcd"`          //交易处理码
	D4   *iso8583.Numeric      `field:"4" length:"12" encode:"bcd"`         //交易金额
	D6   *iso8583.Numeric      `field:"6" length:"12" encode:"bcd"`         //实付金额
	D11  *iso8583.Numeric      `field:"11" length:"6" encode:"bcd"`         //受卡方系统跟踪号
	D12  *iso8583.Numeric      `field:"12" length:"6" encode:"bcd"`         //受卡方所在地时间
	D13  *iso8583.Numeric      `field:"13" length:"4" encode:"bcd"`         //受卡方所在地日期
	D22  *iso8583.Numeric      `field:"22" length:"3" encode:"bcd"`         //服务点输入方式码
	D25  *iso8583.Numeric      `field:"25" length:"2" encode:"bcd"`         //服务点条件码
	D39  *iso8583.Alphanumeric `field:"39" length:"2"`                      //应答码
	D41  *iso8583.Alphanumeric `field:"41" length:"20"`                     //受卡机终端标识码
	D42  *iso8583.Alphanumeric `field:"42" length:"15"`                     //受卡方的标识码，即商户代码
	D46  *iso8583.Lllvar       `field:"46" length:"512" encode:"bcd,ascii"` //自定义域
	D48  *iso8583.Llvar        `field:"48" length:"322" encode:"bcd,ascii"` //自定义域
	D49  *iso8583.Alphanumeric `field:"49" length:"3"`                      //交易货币代码
	D55  *iso8583.Lllvar       `field:"55" length:"255" encode:"bcd,ascii"` //自定义域
	D59  *iso8583.Lllvar       `field:"59" length:"999" encode:"bcd,ascii"` //自定义域
	D60  *iso8583.Lllnumeric   `field:"60" length:"17" encode:"bcd,lbcd"`   //自定义域
	//D601  *iso8583.Alphanumeric   `field:"60.1" length:"17" encode:"bcd,lbcd"`   //交易类型码
	//D602  *iso8583.Alphanumeric   `field:"60.2" length:"17" encode:"bcd,lbcd"`   //批次号
	D61  *iso8583.Lllnumeric   `field:"61" length:"29" encode:"bcd,lbcd"`   //自定义域
	D62  *iso8583.Lllvar       `field:"62" length:"999" encode:"bcd,ascii"` //自定义域
	D63  *iso8583.Lllvar       `field:"63" length:"163" encode:"bcd,ascii"` //自定义域
	D64  *iso8583.Binary       `field:"64" length:"8"`                      //报文鉴别码
}

func (m *Message) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

//Unmarshal ....
func Unmarshal(b []byte, m *Message) error {

	var idx = 0
	m.TPDU = fmt.Sprintf("%X", b[0:idx+5])
	idx += 5
	head := fmt.Sprintf("%X", b[0:idx+6])
	idx += 6
	m.AppClass = head[0:2]
	m.MajorVersion = head[2 : 2+2]
	m.Status = head[2+2 : 2+2+1]
	m.ProcessFlag = head[2+2+1 : 2+2+1+1]
	m.MinorVersion = head[2+2+1+1 : 2+2+1+1+6]
	m.VendorNo = string(b[idx : idx+3])
	idx += 3
	m.MerchantNo = strings.TrimSpace(string(b[idx : idx+15]))
	idx += 15
	m.TerminalNo = strings.TrimSpace(string(b[idx : idx+20]))
	idx += 20
	m.EncryptedFlag = string(b[idx : idx+1])
	idx++
	m.ChannelNo = string(b[idx : idx+4])
	idx += 4
	var body = b[56:]
	var err error
	if m.EncryptedFlag == "1" {
		//log.Printf("密文长度：%X %d\n", b[54:56], binary.BigEndian.Uint16(b[54:56]))
		body, err = DesDecrypt(b[56:], m.TDK, ModeECB, PaddingZero)
		if err != nil {
			return err
		}
	}
	//log.Printf("%X\n", body)
	msg, err := iparser.Parse(body)
	if err != nil {
		return err
	}
	mm := msg.Data.(*Message)
	//log.Println("8583", m)
	m.MTI = msg.Mti
	m.Sign = !mm.D64.IsEmpty()
	m.D3 = mm.D3
	m.D4 = mm.D4
	m.D6 = mm.D6
	m.D11 = mm.D11
	m.D12 = mm.D12
	m.D13 = mm.D13
	m.D22 = mm.D22
	m.D25 = mm.D25
	m.D39 = mm.D39
	m.D41 = mm.D41
	m.D42 = mm.D42
	m.D46 = mm.D46
	m.D48 = mm.D48
	m.D55 = mm.D55
	m.D59 = mm.D59
	m.D60 = mm.D60
	m.D61 = mm.D61
	m.D62 = mm.D62
	m.D63 = mm.D63
	m.D64 = mm.D64
	return nil
}

//Marshal ....
func Marshal(m *Message) ([]byte, error) {
	if m.Sign {
		msg := iso8583.NewMessage(m.MTI, m)
		msg.MtiEncode = iso8583.BCD
		b, err := msg.Bytes()
		if err != nil {
			return nil, err
		}
		b[9] = b[9] | 0x01 //把64域置为1
		sign, err := genMac(b, m.TAK)
		if err != nil {
			return nil, err
		}
		m.D64 = iso8583.NewBinary(sign)
		//log.Printf("签名密钥 %X 签名包 %d %X 签名值 %d %s\n", m.TAK, len(b), b, len(sign), sign)
	}
	msg := iso8583.NewMessage(m.MTI, m)
	msg.MtiEncode = iso8583.BCD
	b, err := msg.Bytes()
	if err != nil {
		return nil, err
	}
	l := uint16(len(b))
	if m.EncryptedFlag == "1" {
		//log.Printf("明文：%d %X\n", len(b), b)
		b, err = DesEncrypt(b, m.TDK, ModeECB, PaddingZero)
		//b = encryptMsg(b, m.WorkKey)
		//log.Printf("密文：%d %X %v\n", len(b), b, err)
		if err != nil {
			return nil, err
		}
		//l = uint16(len(b))
	}
	bb := strings.Builder{}
	bb.WriteString(m.TPDU)
	bb.WriteString(m.AppClass)
	bb.WriteString(m.MajorVersion)
	bb.WriteString(m.Status)
	bb.WriteString(m.ProcessFlag)
	bb.WriteString(m.MinorVersion)
	buf := bytes.NewBuffer(bcd([]byte(bb.String())))
	buf.Write([]byte(m.VendorNo))
	buf.Write([]byte(fmt.Sprintf("%- 15s", m.MerchantNo)))
	buf.Write([]byte(fmt.Sprintf("%- 20s", m.TerminalNo)))
	buf.Write([]byte(m.EncryptedFlag))
	buf.Write([]byte(m.ChannelNo))
	binary.Write(buf, binary.BigEndian, l)
	//buf.Write([]byte(fmt.Sprintf("%04X", len(b))))
	buf.Write(b)
	return buf.Bytes(), nil
}
