package fingerprint

import "testing"

// fullFingerprint returns a Fingerprint whose every field is set to a distinct,
// non-zero value so that BuildReport's field-by-field mapping can be verified
// without any ambiguity.
func fullFingerprint() Fingerprint {
	return Fingerprint{
		HardwareSerial: "HS-1234",
		MachineID:      "MID-5678",
		BuildVersion:   "1.2.3",
		BuildTag:       "tag-abc",
		PublicIP:       "8.8.8.8",
		LanIP:          "192.168.1.10",
		Mac:            "aa:bb:cc:dd:ee:ff",
		Hostname:       "build-node-1",
		OS:             "linux",
		Arch:           "amd64",
		IsVM:           true,
		StartedAt:      1700000000,
	}
}

func TestBuildReport_FieldsMapped(t *testing.T) {
	fp := fullFingerprint()
	got := BuildReport(fp, ReportTypeStartup)

	if got.Ts != fp.StartedAt {
		t.Fatalf("Ts = %d, want %d (fp.StartedAt)", got.Ts, fp.StartedAt)
	}
	if got.Type != ReportTypeStartup {
		t.Fatalf("Type = %q, want %q", got.Type, ReportTypeStartup)
	}
	if got.PublicIP != fp.PublicIP {
		t.Fatalf("PublicIP = %q, want %q", got.PublicIP, fp.PublicIP)
	}
	if got.BuildVersion != fp.BuildVersion {
		t.Fatalf("BuildVersion = %q, want %q", got.BuildVersion, fp.BuildVersion)
	}
	if got.BuildTag != fp.BuildTag {
		t.Fatalf("BuildTag = %q, want %q", got.BuildTag, fp.BuildTag)
	}
	if got.HardwareSerial != fp.HardwareSerial {
		t.Fatalf("HardwareSerial = %q, want %q", got.HardwareSerial, fp.HardwareSerial)
	}
	if got.MachineID != fp.MachineID {
		t.Fatalf("MachineID = %q, want %q", got.MachineID, fp.MachineID)
	}
	if got.LanIP != fp.LanIP {
		t.Fatalf("LanIP = %q, want %q", got.LanIP, fp.LanIP)
	}
	if got.Mac != fp.Mac {
		t.Fatalf("Mac = %q, want %q", got.Mac, fp.Mac)
	}
	if got.Hostname != fp.Hostname {
		t.Fatalf("Hostname = %q, want %q", got.Hostname, fp.Hostname)
	}
	if got.OS != fp.OS {
		t.Fatalf("OS = %q, want %q", got.OS, fp.OS)
	}
	if got.Arch != fp.Arch {
		t.Fatalf("Arch = %q, want %q", got.Arch, fp.Arch)
	}
	if got.IsVM != fp.IsVM {
		t.Fatalf("IsVM = %v, want %v", got.IsVM, fp.IsVM)
	}
	if got.StartedAt != fp.StartedAt {
		t.Fatalf("StartedAt = %d, want %d", got.StartedAt, fp.StartedAt)
	}
	if got.V != "1" {
		t.Fatalf("V = %q, want %q", got.V, "1")
	}
}

func TestBuildReport_HeartbeatType(t *testing.T) {
	fp := fullFingerprint()
	got := BuildReport(fp, ReportTypeHeartbeat)

	if got.Type != ReportTypeHeartbeat {
		t.Fatalf("Type = %q, want %q", got.Type, ReportTypeHeartbeat)
	}
	// Heartbeat reports still carry the same fingerprint payload.
	if got.Ts != fp.StartedAt {
		t.Fatalf("Ts = %d, want %d", got.Ts, fp.StartedAt)
	}
	if got.V != "1" {
		t.Fatalf("V = %q, want %q", got.V, "1")
	}
}
