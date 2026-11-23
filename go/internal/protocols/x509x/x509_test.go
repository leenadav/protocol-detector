package x509x

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Synthetic leaves (RSA 1024..3072, P-256/384/521, Ed25519/Ed448; SAN, EKU, CA, v1, CA-signed) and byte mutations,
// with the Python reference's leaf_profile outcome for each, and validity labels around the capture-clock bounds.
func TestLeafProfileMatchesTheReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/leaves.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Certs []struct {
			DER    string
			Fields [][2]string
			Error  *string
		}
		Validity []struct {
			NB, NA string
			At     *float64
			Label  *string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Certs) < 100 {
		t.Fatalf("testdata: %v (%d certificates)", err, len(doc.Certs))
	}
	for i, c := range doc.Certs {
		der, _ := hex.DecodeString(c.DER)
		fields, err := LeafProfile(der)
		got := ""
		if err != nil {
			got = "error: " + err.(*parsing.Error).Message
		} else {
			got = fmt.Sprint(fields)
		}
		want := ""
		if c.Error != nil {
			want = "error: " + *c.Error
		} else {
			var fs []Field
			for _, f := range c.Fields {
				fs = append(fs, Field{f[0], f[1]})
			}
			want = fmt.Sprint(fs)
		}
		if got != want {
			t.Fatalf("certificate %d\n got  %s\n want %s", i, got, want)
		}
	}
	for _, v := range doc.Validity {
		want := ""
		if v.Label != nil {
			want = *v.Label
		}
		if got := Validity(v.NB, v.NA, v.At); got != want {
			t.Fatalf("validity %s..%s at %v: %q want %q", v.NB, v.NA, v.At, got, want)
		}
	}
}

func TestWeakKey(t *testing.T) {
	for label, want := range map[string]bool{"rsa-1024": true, "rsa-2048": false, "ec-256": false, "ec-other": false, "ed25519": false, "other": false, "rsa-": false} {
		if WeakKey(label) != want {
			t.Fatalf("%s", label)
		}
	}
}

// Codex PRO-15: a four-octet DER length fits in an int on 32-bit platforms, but adding the content offset
// overflowed (and 0xffffffff read as -1), so the container guard passed and a negative end panicked at the slice.
// The reference (unbounded Python ints) refuses every one of these lengths as exceeding the container.
func TestFourOctetLengthNeverOverflowsTheContainerGuard(t *testing.T) {
	want := parsing.Malformed("DER element exceeds its container").Error()
	for _, length := range []string{"7fffffff", "7ffffffa", "80000000", "fffffff0", "ffffffff"} {
		inner, _ := hex.DecodeString("3084" + length)
		tbs := append([]byte{0x30, byte(len(inner))}, inner...)
		der := append([]byte{0x30, byte(len(tbs))}, tbs...)
		if _, _, _, err := element(der, 4, len(der)); err == nil || err.Error() != want {
			t.Errorf("length %s: element error %v, want %q", length, err, want)
		}
		if _, err := LeafProfile(der); err == nil || err.Error() != want {
			t.Errorf("length %s: LeafProfile error %v, want %q", length, err, want)
		}
	}
}

func FuzzLeafProfileStaysBounded(f *testing.F) {
	raw, _ := os.ReadFile("testdata/leaves.json")
	var doc struct{ Certs []struct{ DER string } }
	json.Unmarshal(raw, &doc)
	for _, c := range doc.Certs[:20] {
		der, _ := hex.DecodeString(c.DER)
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		fields, err := LeafProfile(der)
		if err == nil && len(fields) < 7 {
			t.Fatalf("a profile with %d fields", len(fields))
		}
	})
}

// SEC-X509-1: a four-octet DER length near the int32 maximum must be rejected by subtraction, not by an addition
// that wraps on 32-bit builds (GOARCH=386, arm) and lets a negative end reach a slice expression. Run this test with
// GOARCH=386 as well: on amd64 the old check also held, so only a 32-bit run reproduces the panic.
func TestHugeDERLengthIsRejectedWithoutWrap(t *testing.T) {
	for _, header := range [][]byte{
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xfa},
		{0x30, 0x83, 0xff, 0xff, 0xff},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	} {
		for _, lead := range []int{0, 1, 7} {
			data := append(make([]byte, lead), header...)
			data = append(data, make([]byte, 16)...)
			if _, _, _, err := element(data, lead, len(data)); err == nil {
				t.Fatalf("% x at %d: accepted", header, lead)
			} else if e, ok := err.(*parsing.Error); !ok || e.Kind != "malformed" {
				t.Fatalf("% x at %d: %v is not malformed", header, lead, err)
			}
		}
	}

	// The reported path: a leaf whose issuer Name starts with 30 84 7f ff ff ff, through LeafProfile.
	tlv := func(tag byte, body ...[]byte) []byte {
		var inner []byte
		for _, b := range body {
			inner = append(inner, b...)
		}
		n := len(inner)
		if n < 0x80 {
			return append([]byte{tag, byte(n)}, inner...)
		}
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, inner...)
	}
	version := tlv(0xa0, tlv(0x02, []byte{0x02}))
	serial := tlv(0x02, []byte{0x01})
	sigAlg := tlv(0x30, tlv(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}), []byte{0x05, 0x00})
	issuer := append([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, make([]byte, 200)...)
	der := tlv(0x30, tlv(0x30, version, serial, sigAlg, issuer))
	if _, err := LeafProfile(der); err == nil {
		t.Fatal("hostile issuer length accepted")
	} else if e, ok := err.(*parsing.Error); !ok || e.Kind != "malformed" {
		t.Fatalf("hostile issuer length: %v is not malformed", err)
	}
}
