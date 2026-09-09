package fingerprint

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestIsInternalIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		got := IsInternalIP(c.ip)
		if got != c.want {
			t.Fatalf("IsInternalIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCollectFingerprint_MachineID_FromInjectedReader(t *testing.T) {
	origReadFile := readFileFn
	origNow := now
	defer func() {
		readFileFn = origReadFile
		now = origNow
	}()

	fixed := time.Unix(1700000000, 0)
	readFileFn = func(string) ([]byte, error) {
		return []byte("test-machine-id"), nil
	}
	now = func() time.Time { return fixed }

	fp, err := CollectFingerprint()
	if err != nil {
		t.Fatalf("CollectFingerprint() returned error: %v", err)
	}
	if fp.MachineID != "test-machine-id" {
		t.Fatalf("MachineID = %q, want %q", fp.MachineID, "test-machine-id")
	}
	if fp.OS != runtime.GOOS {
		t.Fatalf("OS = %q, want %q", fp.OS, runtime.GOOS)
	}
	if fp.Arch != runtime.GOARCH {
		t.Fatalf("Arch = %q, want %q", fp.Arch, runtime.GOARCH)
	}
	if fp.StartedAt != fixed.Unix() {
		t.Fatalf("StartedAt = %d, want %d", fp.StartedAt, fixed.Unix())
	}
}

func TestCollectFingerprint_NoError_WhenFilesMissing(t *testing.T) {
	origReadFile := readFileFn
	defer func() { readFileFn = origReadFile }()

	readFileFn = func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	}

	if _, err := CollectFingerprint(); err != nil {
		t.Fatalf("CollectFingerprint() returned error when files missing: %v", err)
	}
}
