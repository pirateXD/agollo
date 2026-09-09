package fingerprint

import (
	"encoding/base64"
	"fmt"
)

// xorKey is the fixed 16-byte key used to obfuscate report addresses. It is a
// weak scheme by design: the goal is only to keep the plaintext domain out of
// binaries and logs, not to provide cryptographic secrecy.
var xorKey = []byte("t1fingerprint16b")

// reportAddrEncoded holds the obfuscated primary report address. It is a
// placeholder at the package level; the real value is injected at deploy time
// by the surrounding service.
var reportAddrEncoded = ""

// reportAddrBackupEncoded holds obfuscated backup report addresses. Same
// deploy-time injection contract as reportAddrEncoded.
var reportAddrBackupEncoded = []string{}

// xorBytes applies a cyclic XOR of key over data. data[i] is XORed with
// key[i%len(key)], so data need not be a multiple of the key length and never
// panics on short inputs.
func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// EncodeAddr obfuscates a plaintext address into a string that does not
// contain the plaintext domain: xorBytes then base64 standard encoding.
func EncodeAddr(plain string) string {
	return base64.StdEncoding.EncodeToString(xorBytes([]byte(plain), xorKey))
}

// DecodeAddr reverses EncodeAddr. It returns an error when the input is not
// valid base64.
func DecodeAddr(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("fingerprint: invalid obfuscated address %q: %w", encoded, err)
	}
	return string(xorBytes(raw, xorKey)), nil
}

// ResolveReportAddrs returns the primary report address followed by the backup
// addresses, all de-obfuscated at runtime. Entries that fail to decode are
// silently skipped. When every address is empty, it returns an empty slice.
func ResolveReportAddrs() []string {
	var out []string
	if reportAddrEncoded != "" {
		if addr, err := DecodeAddr(reportAddrEncoded); err == nil {
			out = append(out, addr)
		}
	}
	for _, enc := range reportAddrBackupEncoded {
		if enc == "" {
			continue
		}
		if addr, err := DecodeAddr(enc); err == nil {
			out = append(out, addr)
		}
	}
	return out
}
