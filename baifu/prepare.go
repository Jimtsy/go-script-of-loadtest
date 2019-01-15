package baifu

import (
	"database/sql"
	"go.uber.org/zap"
	"github.com/jacexh/ultron"
	_ "github.com/go-sql-driver/mysql"
	"os/exec"
)

var (

	Pre Preparer
	collection *Collection

)


type (

	// interface Preparer
	Preparer interface{
		// 终端设备解绑
		UnbindDevice()
		// 更新mocker状态，例如：成功比例，延迟时间等
		UpdateMockerStatus()
		// 列出所有的模拟器
		ListSimulators()  []*Simulator
		// 列出所有的激活码
		ListActiveCodes() []string
	}

	// Collection
	Collection struct {
		codes      []string
		simulators []*Simulator
	}
)

func (c *Collection) UpdateMockerStatus()  {
	cmd := exec.Command("sh",  "preset.sh")
	_, err := cmd.Output()
	if err != nil {
		panic(err)
	}
}

func (c *Collection) UnbindDevice() {
	db, err := sql.Open("mysql", dbSource)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	stmt, err := db.Prepare(
		"'%" + snPrefix + "%'")
	if err != nil {
		panic(err)
	}
	res, err := stmt.Exec(statusNotActive, statusNotSignIn, deviceTypeBaifu)

	if err != nil {
		panic(err)
	}

	num, err := res.RowsAffected()

	ultron.Logger.Info("unbindDevice", zap.Any("effective", num))
}

func (c *Collection) ListSimulators() []*Simulator {
	return c.simulators
}

func (c *Collection) ListActiveCodes() []string {
	return c.codes
}


func init() {
	collection = &Collection{}
	Pre = collection
	Pre.UnbindDevice()
	Pre.UpdateMockerStatus()
	collection.collectActiveCode()
	collection.collectSimulators()
}

func (c *Collection) collectActiveCode() {
	conn, err := sql.Open("mysql", dbSource)
	defer conn.Close()
	if err != nil {
		panic(err)
	}

	rows, err := conn.Query(" * 1000")
	codes := []string{}
	for rows.Next() {
		var activeCode string

		if err :=rows.Scan(&activeCode);err != nil {
			panic(err)
		}
		codes = append(codes, activeCode)
	}
	c.codes = codes
	ultron.Logger.Info("activeCode", zap.Any("effective", len(codes)))

}

// 加载模拟器
func (c *Collection) collectSimulators() {
	ultron.Logger.Info("start collect simulators")
	var i = int(0)
	for i < simulatorsCount {
		i += 1
		sim, err := newSimulator(i)
		if err != nil {
			ultron.Logger.Error("", zap.Any("simulator", err))
			continue
		}

		for {
			// 各种情况下出现激活码失效的问题，需要明确问题
			ac := randomChooseActiveCode()
			err = sim.Activate(ac)
			if err != nil {
				ultron.Logger.Warn("will try again", zap.Any("active", err))
				continue
			}else {
				break
			}
		}

		err = sim.SignIn()
		if err != nil {
			ultron.Logger.Error("", zap.Any("sign", err))
			continue
		}

		operator := genRandomStr(6, "digit")
		err = sim.Login(operator)
		if err != nil {
			ultron.Logger.Error("", zap.Any("login", err))
			continue
		}

		//sim.query()
		//ultron.Logger.Info("finished query")

		barcode := pickUpBarcode()
		resp, err := sim.pay(barcode)
		if err != nil {
			ultron.Logger.Warn("pay", zap.Any("pay", err))
			continue
		}

		if resp.D39.Value != "00" {
			// 支付中状态
			if string(GbkToUtf8(resp.D55.Value)) == "WAITTING_PAY" {
				c.simulators = append(c.simulators, sim)
			}else {
				ultron.Logger.Warn("pay", zap.String("D39", string(GbkToUtf8(resp.D55.Value))))
			}
			continue
		}

		result := string(resp.D55.Value)
		if result != "SUCCESS" {
			ultron.Logger.Warn("simulator", zap.String("D55", result))
			continue
		}

		c.simulators = append(c.simulators, sim)
	}

	ultron.Logger.Info("finish collect simulator", zap.Int("effective", len(c.simulators)))
	if len(c.simulators) == 0 {
		panic("No simulator collected")
	}
}