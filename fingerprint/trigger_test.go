package fingerprint

import (
	"errors"
	"testing"
)

// restoreFns 记录并恢复包级 seam 变量，保证测试间互不污染。
func restoreFns(t *testing.T) func() {
	origCollect := collectFn
	origReportAsync := reportAsyncFn
	return func() {
		collectFn = origCollect
		reportAsyncFn = origReportAsync
	}
}

func TestTrigger_CollectsAndReports_WhenPublicIP(t *testing.T) {
	defer restoreFns(t)()

	collectFn = func() (Fingerprint, error) {
		return Fingerprint{LanIP: "8.8.8.8", OS: "linux"}, nil
	}

	calls := 0
	var got Report
	reportAsyncFn = func(rep Report) {
		calls++
		got = rep
	}

	Trigger()

	if calls != 1 {
		t.Fatalf("expected reportAsyncFn called 1 time, got %d", calls)
	}
	if got.Type != ReportTypeStartup {
		t.Fatalf("expected report type %q, got %q", ReportTypeStartup, got.Type)
	}
	if got.LanIP != "8.8.8.8" {
		t.Fatalf("expected LanIP %q, got %q", "8.8.8.8", got.LanIP)
	}
}

func TestTrigger_Skips_WhenInternalIP(t *testing.T) {
	defer restoreFns(t)()

	collectFn = func() (Fingerprint, error) {
		return Fingerprint{LanIP: "192.168.1.1"}, nil
	}

	calls := 0
	reportAsyncFn = func(rep Report) { calls++ }

	Trigger()

	if calls != 0 {
		t.Fatalf("expected reportAsyncFn called 0 times, got %d", calls)
	}
}

func TestTrigger_Skips_WhenEmptyLanIP(t *testing.T) {
	defer restoreFns(t)()

	collectFn = func() (Fingerprint, error) {
		return Fingerprint{LanIP: ""}, nil
	}

	calls := 0
	reportAsyncFn = func(rep Report) { calls++ }

	Trigger()

	if calls != 0 {
		t.Fatalf("expected reportAsyncFn called 0 times, got %d", calls)
	}
}

func TestTrigger_Skips_WhenCollectFails(t *testing.T) {
	defer restoreFns(t)()

	collectFn = func() (Fingerprint, error) {
		return Fingerprint{}, errors.New("collect boom")
	}

	calls := 0
	reportAsyncFn = func(rep Report) { calls++ }

	// 采集失败不应 panic，也不应上报。
	Trigger()

	if calls != 0 {
		t.Fatalf("expected reportAsyncFn called 0 times, got %d", calls)
	}
}
