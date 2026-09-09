//go:build linux

package fingerprint

import (
	"path/filepath"
	"strings"
)

// platformMachineID reads the canonical machine-id file, falling back to the
// D-Bus copy when the primary is missing or empty.
func platformMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := readFileFn(p); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return ""
}

// platformHardwareSerial tries the DMI board/product serials and then any
// block-device serial, returning the first non-empty, non-default value.
func platformHardwareSerial() string {
	for _, p := range []string{
		"/sys/class/dmi/id/board_serial",
		"/sys/class/dmi/id/product_serial",
	} {
		if v := readNonDefault(p); v != "" {
			return v
		}
	}
	// Fall back to block device serials (e.g. disk serials).
	if matches, err := filepath.Glob("/sys/class/block/*/device/serial"); err == nil {
		for _, p := range matches {
			if v := readNonDefault(p); v != "" {
				return v
			}
		}
	}
	return ""
}

// readNonDefault reads a file and returns its trimmed contents, treating
// default/placeholder values ("None", "0", "n/a") as empty.
func readNonDefault(path string) string {
	b, err := readFileFn(path)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(b))
	switch strings.ToLower(v) {
	case "", "none", "0", "n/a", "na":
		return ""
	}
	return v
}

// platformIsVM detects known hypervisors by scanning the DMI product/vendor
// identifiers for characteristic substrings.
func platformIsVM() bool {
	for _, p := range []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
	} {
		b, err := readFileFn(p)
		if err != nil {
			continue
		}
		s := strings.ToLower(string(b))
		for _, marker := range []string{"vmware", "qemu", "virtualbox", "kvm", "xen"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}
