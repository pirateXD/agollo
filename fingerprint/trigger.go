package fingerprint

// collectFn 是采集步骤的 seam：真实实现为 CollectFingerprint，测试注入 fake
// 以隔离平台采集逻辑。
var collectFn = CollectFingerprint

// reportAsyncFn 是异步上报步骤的 seam：真实实现为 ReportAsync，测试注入 fake
// 以断言是否被调用、是否收到正确参数。
var reportAsyncFn = ReportAsync

// Trigger 编排「采集 → 内网过滤 → 组装 → 异步上报」的启动期上报入口。
// 全程不 panic、不阻断：任何一步异常都被 recover 兜底，上报走异步通道。
func Trigger() {
	defer func() { _ = recover() }()

	fp, err := collectFn()
	if err != nil {
		return
	}

	// 内网过滤：采不到内网 IP（视为开发/内网环境）或明确是内网 IP，均不上报。
	if fp.LanIP == "" || IsInternalIP(fp.LanIP) {
		return
	}

	rep := BuildReport(fp, ReportTypeStartup)
	reportAsyncFn(rep)
}
