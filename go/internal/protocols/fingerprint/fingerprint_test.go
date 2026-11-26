package fingerprint

import "testing"

// Known answers computed by the Python reference (protocol_engine/fingerprints.py) for the same inputs.
func TestKnownAnswers(t *testing.T) {
	if got := JA3S(0x0303, 0xc02f, []int{65281, 11}); got != "303951d4c50efb2e991652225a6f02b1" {
		t.Fatalf("JA3S %s", got)
	}
	if got := JA4S(0x0304, 0x1301, []int{43, 51}, [][]byte{[]byte("h2")}, "t"); got != "t1302h2_1301_a56c5b993250" {
		t.Fatalf("JA4S %s", got)
	}
	if got := HASSH([]byte("curve25519-sha256"), []byte("aes128-ctr"), []byte("hmac-sha2-256"), []byte("none")); got != "e97d07603350d1111ec2b64bf25413c9" {
		t.Fatalf("HASSH %s", got)
	}
	if got := H2Settings([]Setting{{1, 4096}, {4, 65535}}); got != "1:4096;4:65535" {
		t.Fatalf("SETTINGS %s", got)
	}
}

func TestGREASEAndALPNCodes(t *testing.T) {
	for v := 0x0a0a; v <= 0xfafa; v += 0x1010 {
		if !IsGREASE(v) {
			t.Fatalf("%04x not GREASE", v)
		}
	}
	for _, v := range []int{0x0a0b, 0x1301, 0x0000, 0xfafb} {
		if IsGREASE(v) {
			t.Fatalf("%04x treated as GREASE", v)
		}
	}
	// Keys are wire bytes. A printable value that starts with "hex:" is text, never decoded as hex (SEC-FP-1).
	cases := map[string]string{"": "00", "h2": "h2", "http/1.1": "h1", "\x00\xff": "0f", "x-": "7d",
		"hex:zz": "hz", "hex:4": "h4", "hex:7a7a": "ha", "zz": "zz"}
	for in, want := range cases {
		alpn := [][]byte{[]byte(in)}
		if in == "" {
			alpn = nil
		}
		if got := alpnCode(alpn); got != want {
			t.Fatalf("ALPN %q: %s want %s", in, got, want)
		}
	}
	// A JA4 drops GREASE before counting and sorting, and a ClientHello without SNI is "i".
	info := &ClientHello{Version: 0x0303, Ciphers: []int{0x0a0a, 0x1301}, Extensions: []int{0x1a1a, 16, 13}, ALPNRaw: [][]byte{[]byte("h2")},
		SignatureAlgorithms: []int{0x0403}, SupportedVersions: []int{0x2a2a, 0x0304}}
	if got := JA4(info, "t"); got[:10] != "t13i0102h2" {
		t.Fatalf("JA4 %s", got)
	}
}
