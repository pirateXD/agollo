package fingerprint

import (
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	plain := "https://example.com/report"
	enc := EncodeAddr(plain)

	if strings.Contains(enc, "example.com") {
		t.Fatalf("EncodeAddr(%q) = %q, must not contain the plaintext domain", plain, enc)
	}

	got, err := DecodeAddr(enc)
	if err != nil {
		t.Fatalf("DecodeAddr(%q) returned error: %v", enc, err)
	}
	if got != plain {
		t.Fatalf("DecodeAddr(EncodeAddr(%q)) = %q, want %q", plain, got, plain)
	}
}

func TestDecodeAddr_InvalidBase64(t *testing.T) {
	if _, err := DecodeAddr("!!!not-base64!!!"); err == nil {
		t.Fatalf("DecodeAddr(%q) expected error, got nil", "!!!not-base64!!!")
	}
}

func TestResolveReportAddrs_SkipsBadEntries(t *testing.T) {
	origPrimary := reportAddrEncoded
	origBackups := reportAddrBackupEncoded
	defer func() {
		reportAddrEncoded = origPrimary
		reportAddrBackupEncoded = origBackups
	}()

	reportAddrEncoded = EncodeAddr("https://a.com")
	reportAddrBackupEncoded = []string{EncodeAddr("https://b.com"), "%%%bad%%%"}

	got := ResolveReportAddrs()
	want := []string{"https://a.com", "https://b.com"}
	if len(got) != len(want) {
		t.Fatalf("ResolveReportAddrs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ResolveReportAddrs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestEncodeDecodeShortPlain covers the case where the plaintext is shorter
// than the XOR key, exercising the data[i]^key[i%len(key)] indexing so the
// round-trip does not require the data length to be a multiple of the key.
func TestEncodeDecodeShortPlain(t *testing.T) {
	plain := "a"
	enc := EncodeAddr(plain)
	got, err := DecodeAddr(enc)
	if err != nil {
		t.Fatalf("DecodeAddr(%q) returned error: %v", enc, err)
	}
	if got != plain {
		t.Fatalf("DecodeAddr(EncodeAddr(%q)) = %q, want %q", plain, got, plain)
	}
}
