package x509x

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

func derTLV(tag byte, content []byte) []byte {
	n := len(content)
	switch {
	case n < 128:
		return append([]byte{tag, byte(n)}, content...)
	case n < 256:
		return append([]byte{tag, 0x81, byte(n)}, content...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, content...)
	}
}

// derSplit returns the elements of a DER content (definite short or long lengths only).
func derSplit(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(data) > 0 {
		size, head := int(data[1]), 2
		if size&0x80 != 0 {
			width := size & 0x7f
			size = 0
			for i := 0; i < width; i++ {
				size = size<<8 | int(data[2+i])
			}
			head = 2 + width
		}
		out = append(out, data[:head+size])
		data = data[head+size:]
	}
	return out
}

func derBody(element []byte) []byte {
	size, head := int(element[1]), 2
	if size&0x80 != 0 {
		head = 2 + size&0x7f
	}
	return element[head:]
}

// securityLeaf is the first committed reference leaf that profiles cleanly and carries an extensions block.
func securityLeaf(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/leaves.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Certs []struct {
			DER   string
			Error *string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Certs {
		der, _ := hex.DecodeString(c.DER)
		if c.Error == nil && bytes.Contains(der, []byte{0x06, 0x03, 0x55, 0x1d, 0x13}) {
			return der
		}
	}
	t.Fatal("no reference leaf with basic constraints")
	return nil
}

// withExtensions rebuilds the leaf with its extensions block replaced by exts (signature left as it was).
func withExtensions(t *testing.T, leaf []byte, exts ...[]byte) []byte {
	t.Helper()
	parts := derSplit(t, derBody(leaf))
	tbs := derSplit(t, derBody(parts[0]))
	for i, e := range tbs {
		if e[0] == 0xa3 {
			tbs[i] = derTLV(0xa3, derTLV(0x30, bytes.Join(exts, nil)))
		}
	}
	parts[0] = derTLV(0x30, bytes.Join(tbs, nil))
	return derTLV(0x30, bytes.Join(parts, nil))
}

func extension(oidHex string, critical []byte, value []byte) []byte {
	o, _ := hex.DecodeString(oidHex)
	return derTLV(0x30, bytes.Join([][]byte{derTLV(0x06, o), critical, derTLV(0x04, value)}, nil))
}

func profileOf(t *testing.T, der []byte) (map[string]string, string) {
	t.Helper()
	fields, err := LeafProfile(der)
	if err != nil {
		return nil, err.(*parsing.Error).Message
	}
	out := map[string]string{}
	for _, f := range fields {
		out[f.Name] = f.Value
	}
	return out, ""
}

// SR-55: the leaf certificate's extendedKeyUsage (at most 16 purposes) and subjectAltName (at most 256
// GeneralNames, each in its DER form with its inner framing) are interpreted under DER rules: a repeated extension,
// an encoded critical FALSE or an iPAddress other than 4 or 16 octets is refused, and neither the alternative
// names nor the purpose OIDs are emitted, only closed labels.
func TestSecurityCertificateExtensionBudgetsAndDER(t *testing.T) {
	leaf := securityLeaf(t)
	ca := extension("551d13", nil, derTLV(0x30, []byte{0x01, 0x01, 0xff}))
	serverAuth := derTLV(0x06, []byte{0x2b, 6, 1, 5, 5, 7, 3, 1})
	eku := func(n int) []byte { return extension("551d25", nil, derTLV(0x30, bytes.Repeat(serverAuth, n))) }
	dns := derTLV(0x82, []byte("secret-name.example"))
	san := func(entries ...[]byte) []byte {
		return extension("551d11", nil, derTLV(0x30, bytes.Join(entries, nil)))
	}
	repeat := func(entry []byte, n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = entry
		}
		return out
	}
	good, msg := profileOf(t, withExtensions(t, leaf, ca, eku(16), san(repeat(dns, 256)...)))
	if msg != "" || good["tls_certificate_ca"] != "yes" || good["tls_certificate_san"] != "present" || good["tls_certificate_eku"] == "" || good["tls_certificate_eku"] == "absent" {
		t.Fatalf("16 purposes and 256 names: %v %q", good, msg)
	}
	rendered := fmt.Sprint(good)
	for _, forbidden := range []string{"secret-name", "1.3.6.1.5.5.7.3.1", "2b06010505070301"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("%q emitted: %s", forbidden, rendered)
		}
	}
	if _, msg := profileOf(t, withExtensions(t, leaf, san(derTLV(0x87, []byte{192, 0, 2, 1}), derTLV(0x87, make([]byte, 16))))); msg != "" {
		t.Fatalf("4- and 16-octet iPAddresses: %q", msg)
	}
	for name, c := range map[string]struct {
		der  []byte
		want string
	}{
		"17 purposes":        {withExtensions(t, leaf, ca, eku(17)), "Extended key usage exceeds the purpose budget"},
		"257 names":          {withExtensions(t, leaf, ca, san(repeat(dns, 257)...)), "Subject alternative name exceeds the entry budget"},
		"repeated extension": {withExtensions(t, leaf, ca, ca), "Certificate repeats an extension"},
		"critical FALSE":     {withExtensions(t, leaf, extension("551d13", []byte{0x01, 0x01, 0x00}, derTLV(0x30, []byte{0x01, 0x01, 0xff}))), "Extension critical flag must be absent or a DER TRUE"},
		"5-octet iPAddress":  {withExtensions(t, leaf, san(derTLV(0x87, []byte{192, 0, 2, 1, 9}))), "Subject alternative name iPAddress must be 4 or 16 octets"},
		"empty dNSName":      {withExtensions(t, leaf, san(derTLV(0x82, nil))), "Subject alternative name text entry must be a non-empty IA5String"},
	} {
		if _, msg := profileOf(t, c.der); msg != c.want {
			t.Fatalf("%s: %q, want %q", name, msg, c.want)
		}
	}
}

// SR-55: certificate validity is judged only against a capture time the host supplies, never the analysis
// clock: no capture time, or one before 2000, gives no label; within the window the label is day-granular.
func TestSecurityValidityNeedsACaptureClock(t *testing.T) {
	at := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		at   *float64
		want string
	}{
		{nil, ""}, {at(0), ""}, {at(946684799), ""}, {at(946684800), "not-yet-valid"},
		{at(1795046400), "current"},       // 2026-11-19T00:00:00Z
		{at(1795132799), "current"},       // 2026-11-19T23:59:59Z, the last day
		{at(1795132800), "expired"},       // 2026-11-20
		{at(1794873600), "not-yet-valid"}, // 2026-11-17
	} {
		if got := Validity("2026-11-18", "2026-11-19", c.at); got != c.want {
			t.Fatalf("validity at %v: %q, want %q", c.at, got, c.want)
		}
	}
}
