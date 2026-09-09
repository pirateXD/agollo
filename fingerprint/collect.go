// Package fingerprint collects a stable, best-effort machine fingerprint for
// device identification.
//
// All collectors degrade gracefully: when a value cannot be read (missing
// file, no permission, unsupported platform, empty registry) the corresponding
// field is simply left empty rather than failing the whole collection. This
// makes CollectFingerprint safe to call unconditionally at startup.
package fingerprint

import (
	"net"
	"os"
	"runtime"
	"time"
)

// Fingerprint is a snapshot of identifying attributes of the current machine.
// Strong anchors (hardware serial, machine-id) come first; network and
// auxiliary attributes are weaker and may change over time.
type Fingerprint struct {
	HardwareSerial string  // 强锚点 #1：CPU/主板/磁盘 首个可得序列号
	MachineID      string  // 强锚点 #2：machine-id
	BuildVersion   string  // 强锚点 #3a：编译期注入，本 task 可留空
	BuildTag       string  // 强锚点 #3b：编译期注入，本 task 可留空
	PublicIP       string  // 定位 #4：本 task 置空
	LanIP          string  // 定位 #5a：内网 IP
	Mac            string  // 定位 #5b：MAC
	Hostname       string  // 辅助 #6
	OS             string  // 辅助 #7a：runtime.GOOS
	Arch           string  // 辅助 #7b：runtime.GOARCH
	IsVM           bool    // 辅助 #7c：VM 检测
	StartedAt      int64   // 辅助 #8：启动时间戳
}

// readFileFn is the filesystem-read seam used by the platform collectors.
// Tests override it to inject fake file contents.
var readFileFn = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// now is the clock seam. Tests override it for a deterministic StartedAt.
var now = time.Now

// CollectFingerprint gathers every available fingerprint attribute. It never
// fails: unreadable attributes are left empty and a nil error is returned.
func CollectFingerprint() (Fingerprint, error) {
	fp := Fingerprint{
		HardwareSerial: platformHardwareSerial(),
		MachineID:      platformMachineID(),
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		IsVM:           platformIsVM(),
		StartedAt:      now().Unix(),
	}
	fp.LanIP, fp.Mac = firstActiveLanIPAndMac()
	if h, err := os.Hostname(); err == nil {
		fp.Hostname = h
	}
	return fp, nil
}

// IsInternalIP reports whether ip is a private (RFC1918), loopback, or
// link-local (RFC3927) address rather than a public routable one.
func IsInternalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// IsPrivate covers 10/8, 172.16/12, 192.168/16. IsLoopback covers 127/8.
	// IsLinkLocalUnicast covers 169.254/16.
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// firstActiveLanIPAndMac returns the first IPv4 and the MAC of the first
// non-loopback, up interface. It swallows all errors and returns empty values
// when nothing is found, so the fingerprint collection never fails.
func firstActiveLanIPAndMac() (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		var mac string
		if len(ifc.HardwareAddr) > 0 {
			mac = ifc.HardwareAddr.String()
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				return ip4.String(), mac
			}
		}
	}
	return "", ""
}
