package baifu

import (
	"time"
	"flag"
	"net"
	"github.com/jacexh/ultron"

	//"github.com/jacexh/ultron-helper"
	"github.com/op/go-logging"
	"math/rand"
	"sync"
	"github.com/pkg/errors"
)

// 用设备SN激活 可以拿到tmk
// 设备签到可以拿到tdk和tak


// Attacker 百富云压测
type BF3Attacker struct {
	name string
	sim *Simulator
	mu  sync.RWMutex
}



var (
	snPrefix = "QR88"
    conf = "conf"
	log = logging.MustGetLogger("cronosin")
)


const (
	dbSource = ""
	requestPay    = "pay"
	requestQuery  = "query"
	stateAlipay   = "stateAlipay"
	stateWechat   = "stateWechat"
	prefixBarCodeWX = "13"
	prefixBarCodeAL = "28"
	statusNotActive = 0
	statusNotSignIn = 2
	deviceTypeBaifu = 30
)


const (
	// TimeoutConnect 百富连接超时时长
	TimeoutConnect = time.Second * 3
	// TimeoutWrite 百富客户端与服务器没有写超时时间
	TimeoutWrite = time.Second * 60
	// TimeoutRead 百富读超时
	TimeoutRead = time.Second * 45

)

var (
	concurrency  int
	duration     time.Duration
	minWait      time.Duration
	maxWait      time.Duration
	serverAddr   string
	hatchRate    int

	simulatorsCount   int
	weightOfPay       int
	weightOfQuery      int
	weightOfWechatPay int
	weightOfAlipay    int
	sourceWeightMap   map[string]int
	//isDebug           bool
)

func init() {
	flag.IntVar(&weightOfPay, "wpay", 20, "交易请求权重")
	flag.IntVar(&weightOfQuery, "wquery", 1, "查询请求权重")
	flag.IntVar(&weightOfAlipay, "wali", 1, "支付宝在交易请求中的交易权重")
	flag.IntVar(&weightOfWechatPay, "wwx", 2, "微信交易在交易请求中的权重")
	flag.IntVar(&simulatorsCount, "simulators", 1, "模拟机个数")


	flag.IntVar(&concurrency, "concurrency", 1, "压测并发数")
	flag.IntVar(&hatchRate, "hatchRate", 500, "每秒产生多少个虚拟用户")
	flag.DurationVar(&duration, "duration", 20, "压测时长")
	flag.DurationVar(&minWait, "minWait", 1, "最小思考时间")
	flag.DurationVar(&maxWait, "maxWait", 2, "最大思考时间")
	flag.StringVar(&serverAddr, "addrAndPort", "", "IP Address")
	//flag.BoolVar(&isDebug, "debug", true, "是否开启调试")
	flag.Parse()

	sourceWeightMap = map[string]int{
		stateAlipay: weightOfAlipay,
		stateWechat: weightOfWechatPay,
	}

}

// 随机返回一个激活码
func randomChooseActiveCode() string {
	codes := Pre.ListActiveCodes()
	c := codes[rand.Intn(len(codes))]
	return c
}

// 根据微信、支付宝交易权重随机返回一个支付条形码
func pickUpBarcode() string {
	total := 0
	validState := []string{}
	for state, weight := range sourceWeightMap {
		if weight >= 0 {
			validState = append(validState, state)
		}
		total += weight
	}

	upto := 0
	index := rand.Intn(total)

	for _, state := range validState {
		weight := sourceWeightMap[state]
		upto += weight
		if index < upto {
			if state == stateAlipay {
				return prefixBarCodeAL + genRandomStr(17, "digit")
			}else if state == stateWechat {
				return prefixBarCodeWX + genRandomStr(17, "digit")
			}else {
				panic("invalid state: " + state)
			}
		}
	}
	panic("unreachable code")

}

func genRandomStr(length int, strType string) string {
	str := ""
	switch strType {
	case "digit":
		str = "0123456789"
	default:
		str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}

	bytes := []byte(str)
	var rs []byte
	for start := 0; start < length; start++ {
		rs = append(rs, bytes[rand.Intn(len(bytes))])
	}
	return string(rs)
}


func newSimulator(endpoint int) (*Simulator, error) {
	//sn := snPrefix + strconv.Itoa(endpoint)
	sn := "QR68"
	ch := "0001"
	sim, err := NewSimulator(sn, ch)
	return sim, err
}


// newBF3Attacker
func newBF3Attacker(name string) *BF3Attacker {
	return &BF3Attacker{
		name: name,
	}
}

// doPost
func doPost(msg *Message) (*Message, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, TimeoutConnect)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	//conn.SetWriteDeadline(time.Now().Add(TimeoutWrite))
	err = WriteMessage(conn, msg)
	if err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(TimeoutRead))
	resp := &Message{}
	resp.TAK = msg.TAK
	resp.TDK = msg.TDK
	err = ReadMessage(conn, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// randChooseSimulator
func (b *BF3Attacker) randChooseSimulator() *Simulator {
	b.mu.RLock()
	defer b.mu.RUnlock()

	simulators := Pre.ListSimulators()
	index := rand.Intn(len(simulators))
	return simulators[index]
}


// implement Fire()
func (b *BF3Attacker) Fire() error {
	
	// 每次请求随机获取一个模拟器终端
	s := b.randChooseSimulator()
	
	var resp *Message
	var err error
	switch b.name {
	case requestPay:
		bc := pickUpBarcode()
		resp, err = s.pay(bc)
	case requestQuery:
		resp, err = s.query()
	}

	if err != nil {
		return err
	}

	//ultron.Logger.Info("resp", zap.Any("message", resp))

	if resp.D39.Value != "00" {
		if string(GbkToUtf8(resp.D55.Value)) == "WAITTING_PAY" {
			ultron.Logger.Warn(b.name + "::" + s.PosSN + "::" + s.TerminalNo + "::" + "WAITTING_PAY")
			return nil
		}else if string(GbkToUtf8(resp.D55.Value)) == "交易未完成，等待顾客输入密码[EP104]" {
			ultron.Logger.Warn(b.name + "::" + s.PosSN + "::" + s.TerminalNo + "::" + "交易未完成，等待顾客输入密码[EP104]")
			return nil
		}
		return errors.New(b.name + "::" + s.PosSN + "::" + s.TerminalNo + "::" + string(GbkToUtf8(resp.D55.Value)))
	}

	result := string(resp.D55.Value)

	if result != "SUCCESS" {
		return errors.New(b.name + "::" + s.PosSN + "::" + s.TerminalNo + "::" + result)
	}//else {
	//	ultron.Logger.Info("SUCCESS",
	//		zap.String("POS", s.PosSN),
	//		zap.String("terminalSN", s.TerminalNo),
	//		zap.String("OrderSN", string(resp.D46.Value)))
	//}

	return nil


}

// implement Name()
func (b *BF3Attacker) Name() string {
	return b.name
}

func main() {
	taskSet := ultron.NewTask()


	attackerPay := newBF3Attacker(requestPay)
	attackerQuery := newBF3Attacker(requestQuery)

	taskSet.Add(attackerPay, weightOfPay)
	taskSet.Add(attackerQuery, weightOfQuery)


	//conf := helper.NewInfluxDBHelperConfig()
	//conf.URL = "http://influxdb.qa.shouqianba.com"
	//conf.Database = "ultron"
	//
	//inf, err := helper.NewInfluxDBHelper(conf)
	//if err != nil {
	//	panic(err)
	//}

	//ultron.LocalEventHook.AddReportHandleFunc(inf.HandleReport())
	//ultron.LocalEventHook.AddResultHandleFunc(inf.HandleResult())

	ultron.LocalRunner.Config = &ultron.RunnerConfig{
		Concurrence: concurrency,
		Duration: duration * time.Minute,
		HatchRate: hatchRate,
		MinWait: minWait * time.Second,
		MaxWait: maxWait * time.Second,
	}

	ultron.LocalRunner.WithTask(taskSet)
	//ultron.LocalRunner.Start()
}