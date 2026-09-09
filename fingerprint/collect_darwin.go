//go:build darwin

package fingerprint

import (
	"os/exec"
	"regexp"
	"strings"
)

// machineIDDarwinSeam is the sentinel path passed to readFileFn as the
// testability seam for the machine-id on macOS.
const machineIDDarwinSeam = "IOPlatformUUID"

var ioPlatformUUIDRe = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// platformMachineID returns the macOS IOPlatformUUID. The readFileFn seam is
// consulted first; otherwise the value is read via the ioreg command.
func platformMachineID() string {
	if b, err := readFileFn(machineIDDarwinSeam); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	if m := ioPlatformUUIDRe.FindSubmatch(out); len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

// platformHardwareSerial is not implemented on macOS; the field is left empty.
func platformHardwareSerial() string {
	return ""
}

// platformIsVM is not implemented on macOS; defaults to false.
func platformIsVM() bool {
	return false
}
