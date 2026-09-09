//go:build windows

package fingerprint

import (
	"strings"
	"syscall"
	"unsafe"
)

// machineIDRegistryKey is the HKLM subkey holding the MachineGuid value.
const machineIDRegistryKey = `SOFTWARE\Microsoft\Cryptography`

// platformMachineID returns the Windows MachineGuid. The readFileFn seam is
// consulted first so tests can inject a known value; otherwise the real
// registry value is read via the standard-library syscall package.
func platformMachineID() string {
	if b, err := readFileFn(machineIDRegistryKey); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return windowsMachineGuid()
}

// windowsMachineGuid reads the MachineGuid value under
// HKLM\SOFTWARE\Microsoft\Cryptography. Any failure yields "".
func windowsMachineGuid() string {
	subkey, err := syscall.UTF16PtrFromString(machineIDRegistryKey)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_READ, &h); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)

	name, err := syscall.UTF16PtrFromString("MachineGuid")
	if err != nil {
		return ""
	}
	var typ uint32
	var buf [256]uint16
	n := uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf[:n/2]))
}

// platformHardwareSerial is not implemented on Windows; the field is left
// empty (may be enriched later).
func platformHardwareSerial() string {
	return ""
}

// platformIsVM is not implemented on Windows; defaults to false.
func platformIsVM() bool {
	return false
}
