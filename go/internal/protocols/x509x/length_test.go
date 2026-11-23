package x509x

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// SEC-X509-1: on a 32-bit int (GOARCH=386, arm) content start plus a four-octet DER length wrapped negative, so the
// container check passed and a later slice panicked. Every long-form length past the container, the largest ones
// included, must return the reference's error ("DER element exceeds its container") on every architecture.
var exceeds = fail("DER element exceeds its container").Error()

func TestElementRejectsHugeLongFormLengths(t *testing.T) {
	for _, header := range []string{"847fffffff", "8480000000", "84ffffffff", "84fffffffa", "8401000000", "83ffffff", "82ffff"} {
		data, _ := hex.DecodeString("30" + header + "00000000")
		_, start, end, err := element(data, 0, len(data))
		if err == nil || err.Error() != exceeds {
			t.Errorf("header %s: start %d end %d err %v, want the container error", header, start, end, err)
		}
	}
}

func TestElementKeepsLongFormLengthsThatFit(t *testing.T) {
	data := make([]byte, 4+0x80)
	copy(data, []byte{0x30, 0x81, 0x80})
	if _, start, end, err := element(data, 0, 3+0x80); err != nil || start != 3 || end != 3+0x80 {
		t.Fatalf("start %d end %d err %v", start, end, err)
	}
	if _, _, _, err := element(data, 0, 2+0x80); err == nil || err.Error() != exceeds {
		t.Fatalf("one byte short: %v", err)
	}
}

// The finding's input: a real leaf whose issuer Name header is replaced by 30 84 7f ff ff ff.
func TestLeafProfileRejectsAWrappingIssuerLength(t *testing.T) {
	raw, err := os.ReadFile("testdata/leaves.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Certs []struct{ DER string } }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	der, _ := hex.DecodeString(doc.Certs[0].DER)
	if der[1] != 0x82 || der[5] != 0x82 {
		t.Fatal("fixture no longer has two-octet outer lengths")
	}
	_, tbsStart, tbsEnd, _ := element(der, 4, len(der))
	cursor := tbsStart
	for i := 0; i < 3; i++ { // version, serial, signature algorithm
		_, _, end, err := element(der, cursor, tbsEnd)
		if err != nil {
			t.Fatal(err)
		}
		cursor = end
	}
	if der[cursor] != tagSequence || der[cursor+1] >= 0x80 {
		t.Fatalf("issuer header % x is not a short-form SEQUENCE", der[cursor:cursor+2])
	}
	hostile := append(append(append([]byte{}, der[:cursor]...), 0x30, 0x84, 0x7f, 0xff, 0xff, 0xff), der[cursor+2:]...)
	for _, at := range []int{2, 6} { // the Certificate and TBSCertificate lengths grow by the four added octets
		n := int(hostile[at])<<8 | int(hostile[at+1]) + 4
		hostile[at], hostile[at+1] = byte(n>>8), byte(n)
	}
	fields, err := LeafProfile(hostile)
	if err == nil || err.Error() != exceeds {
		t.Fatalf("fields %v err %v, want the container error", fields, err)
	}
}
