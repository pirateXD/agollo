package fingerprint

import (
	"errors"
	"testing"
	"time"
)

// slsTestEnv 保存并恢复 SLS 上报相关的包级占位变量与 seam，避免测试之间相互污染。
type slsTestEnv struct {
	putLogsFn   func(string, string, Report) error
	addrEncoded string
	ak          string
	logstore    string
	sleep       func(time.Duration)
}

func saveSLSEnv() slsTestEnv {
	return slsTestEnv{
		putLogsFn:   putLogsFn,
		addrEncoded: reportAddrEncoded,
		ak:          reportAK,
		logstore:    reportLogstore,
		sleep:       sleepFn,
	}
}

func (e slsTestEnv) restore() {
	putLogsFn = e.putLogsFn
	reportAddrEncoded = e.addrEncoded
	reportAK = e.ak
	reportLogstore = e.logstore
	sleepFn = e.sleep
}

// setupSLSEnv 把上报环境设置成可用于测试的值：有效 endpoint、AK、logstore、无操作 sleep。
func setupSLSEnv(t *testing.T) {
	reportAddrEncoded = EncodeAddr("https://sls.example.com")
	reportAK = "testAKID:testSecret"
	reportLogstore = "test-logstore"
	sleepFn = func(time.Duration) {}
}

func TestReportToSLS_CallsPutLogs(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	setupSLSEnv(t)

	var gotEndpoint, gotAK string
	called := false
	putLogsFn = func(endpoint, ak string, rep Report) error {
		called = true
		gotEndpoint = endpoint
		gotAK = ak
		return nil
	}

	if err := ReportToSLS(Report{Type: ReportTypeStartup}); err != nil {
		t.Fatalf("ReportToSLS returned error: %v", err)
	}
	if !called {
		t.Fatalf("putLogsFn was not called")
	}
	if gotEndpoint == "" {
		t.Fatalf("endpoint passed to putLogsFn is empty")
	}
	if gotEndpoint != "https://sls.example.com" {
		t.Fatalf("endpoint = %q, want %q", gotEndpoint, "https://sls.example.com")
	}
	if gotAK != "testAKID:testSecret" {
		t.Fatalf("ak = %q, want %q", gotAK, "testAKID:testSecret")
	}
}

func TestReportToSLS_PropagatesError(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	setupSLSEnv(t)

	expected := errors.New("sls boom")
	putLogsFn = func(endpoint, ak string, rep Report) error { return expected }

	if err := ReportToSLS(Report{}); err != expected {
		t.Fatalf("err = %v, want %v", err, expected)
	}
}

func TestReportToSLS_MissingEndpoint(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	// 不设置 endpoint（reportAddrEncoded 保持默认空串）。
	reportAK = "testAKID:testSecret"

	called := false
	putLogsFn = func(endpoint, ak string, rep Report) error {
		called = true
		return nil
	}

	if err := ReportToSLS(Report{}); err == nil {
		t.Fatalf("ReportToSLS expected error when no address configured, got nil")
	}
	if called {
		t.Fatalf("putLogsFn should not be called when no address is configured")
	}
}

func TestReportToSLS_InvalidAK(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	reportAddrEncoded = EncodeAddr("https://sls.example.com")
	reportAK = "missing-colon" // 无 ":" 分隔符，格式非法

	if err := ReportToSLS(Report{}); err == nil {
		t.Fatalf("ReportToSLS expected error for malformed reportAK, got nil")
	}
}

func TestReportAsync_SwallowsPanic(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	setupSLSEnv(t)

	putLogsFn = func(endpoint, ak string, rep Report) error {
		panic("fake network panic")
	}

	// 直接调用不应把 panic 传播到调用方；若传播则本测试失败。
	ReportAsync(Report{})
}

func TestSignRequest_Deterministic(t *testing.T) {
	env := saveSLSEnv()
	defer env.restore()
	reportAK = "testAKID:testSecret"

	headers := map[string]string{
		"Content-MD5":           "",
		"Content-Type":          "application/json",
		"Date":                  "Mon, 01 Jan 2024 00:00:00 GMT",
		"x-log-apiversion":      "0.6.0",
		"x-log-signaturemethod": "hmac-sha1",
		"x-log-bodyrawsize":     "0",
	}
	resource := "/logstores/test-logstore/shards/lock"

	first := signRequest("PUT", headers, resource)
	if first == "" {
		t.Fatalf("signRequest returned empty signature")
	}
	second := signRequest("PUT", headers, resource)
	if second != first {
		t.Fatalf("signRequest not deterministic: %q vs %q", first, second)
	}

	// 资源参与签名：不同 resource 应得到不同签名。
	if other := signRequest("PUT", headers, "/logstores/other/shards/lock"); other == first {
		t.Fatalf("signature should depend on resource")
	}

	// 日期参与签名：不同 Date 应得到不同签名。
	alt := map[string]string{
		"Content-MD5":           "",
		"Content-Type":          "application/json",
		"Date":                  "Tue, 02 Jan 2024 00:00:00 GMT",
		"x-log-apiversion":      "0.6.0",
		"x-log-signaturemethod": "hmac-sha1",
		"x-log-bodyrawsize":     "0",
	}
	if other := signRequest("PUT", alt, resource); other == first {
		t.Fatalf("signature should depend on the Date header")
	}
}
