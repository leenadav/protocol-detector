package hpack

import (
	"encoding/hex"
	"strings"
	"testing"
)

// SR-48: an HPACK integer has at most four continuation bytes (values stay below 2^28); the reference's answers at
// python-final for the same bytes.
func TestIntegerContinuationBytesAreAtMostFour(t *testing.T) {
	for text, want := range map[string]int{"ffffffff0f": 33554686, "ff8080807f": 266338559, "ff00": 255, "fe": 254} {
		data, _ := hex.DecodeString(text)
		value, next, err := decodeInteger(data, 0, 8)
		if err != nil || value != want || next != len(data) {
			t.Errorf("%s: %d at %d (%v), want %d", text, value, next, err, want)
		}
	}
	for _, text := range []string{"ffffffffff0f", "ff8080808001"} {
		data, _ := hex.DecodeString(text)
		if _, _, err := decodeInteger(data, 0, 8); err == nil || !strings.HasSuffix(err.Error(), "HPACK integer exceeds the decoder limit") {
			t.Errorf("%s: error %v, want the decoder limit", text, err)
		}
	}
}
