package fingerprint

// 上报类型常量。
const (
	ReportTypeStartup   = "startup"
	ReportTypeHeartbeat = "heartbeat"
)

// Report 是上报到 SLS 的单条日志结构，全部字段明文。
type Report struct {
	Ts             int64  `json:"ts"`
	Type           string `json:"type"` // "startup" | "heartbeat"
	PublicIP       string `json:"public_ip"`
	BuildVersion   string `json:"build_version"`
	BuildTag       string `json:"build_tag"`
	HardwareSerial string `json:"hardware_serial"`
	MachineID      string `json:"machine_id"`
	LanIP          string `json:"lan_ip"`
	Mac            string `json:"mac"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	IsVM           bool   `json:"is_vm"`
	StartedAt      int64  `json:"started_at"`
	V              string `json:"v"` // 协议版本，固定 "1"
}

// BuildReport 把 Fingerprint 映射成 Report，reportType 取 ReportTypeStartup /
// ReportTypeHeartbeat。它做的是纯字段映射：Report 的每个字段一一取自
// Fingerprint 对应字段；Ts 取 fp.StartedAt；V 固定为 "1"。
func BuildReport(fp Fingerprint, reportType string) Report {
	return Report{
		Ts:             fp.StartedAt,
		Type:           reportType,
		PublicIP:       fp.PublicIP,
		BuildVersion:   fp.BuildVersion,
		BuildTag:       fp.BuildTag,
		HardwareSerial: fp.HardwareSerial,
		MachineID:      fp.MachineID,
		LanIP:          fp.LanIP,
		Mac:            fp.Mac,
		Hostname:       fp.Hostname,
		OS:             fp.OS,
		Arch:           fp.Arch,
		IsVM:           fp.IsVM,
		StartedAt:      fp.StartedAt,
		V:              "1",
	}
}
