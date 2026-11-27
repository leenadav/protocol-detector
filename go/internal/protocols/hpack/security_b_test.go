package hpack

import (
	"strings"
	"testing"
)

// SR-48: an HPACK integer is read in at most four continuation bytes, whatever value it encodes.
func TestSecurityIntegerContinuationIsBoundedToFourBytes(t *testing.T) {
	// 127 with four continuation bytes (redundant zero groups) is within the limit.
	if v, pos, err := decodeInteger([]byte{0x7f, 0x80, 0x80, 0x80, 0x00}, 0, 7); err != nil || v != 127 || pos != 5 {
		t.Fatalf("four continuation bytes: %d %d %v", v, pos, err)
	}
	// The same value with a fifth continuation byte is refused before it is read.
	if _, _, err := decodeInteger([]byte{0x7f, 0x80, 0x80, 0x80, 0x80, 0x00}, 0, 7); err == nil ||
		!strings.Contains(err.Error(), "HPACK integer exceeds the decoder limit") {
		t.Fatalf("five continuation bytes: %v", err)
	}
}

// SR-48: the dynamic table never exceeds the default 4096 octets, whatever the header block inserts, and a size
// update above the acknowledged maximum is refused.
func TestSecurityDynamicTableNeverExceedsTheDefaultSize(t *testing.T) {
	d := NewDecoder(DefaultTableSize, 4096, 4096, 1<<20)
	value := strings.Repeat("v", 1000)
	block := []byte{}
	for i := 0; i < 12; i++ {
		block = append(block, 0x40, 0x01, byte('a'+i), 0x7f, 0xe9, 0x06) // literal, new name, 1000-octet value
		block = append(block, value...)
	}
	if _, err := d.Decode(block); err != nil {
		t.Fatal(err)
	}
	if d.used > DefaultTableSize || len(d.table) > 4 {
		t.Fatalf("dynamic table %d octets in %d entries", d.used, len(d.table))
	}
	if _, err := NewDecoder(DefaultTableSize, 8, 8, 4096).Decode([]byte{0x3f, 0xe2, 0x1f}); err == nil {
		t.Fatal("size update to 4097 accepted")
	}
}
