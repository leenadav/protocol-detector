package framed

import (
	"errors"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// PRO-503: fields above 2^31 must keep their meaning on a 32-bit int (GOARCH=386, make go-check-386), where
// be/le of four bytes yields the int32 bit pattern and strconv.Atoi clamps at MaxInt32.

func TestRPCLastFragmentBitOn32BitInt(t *testing.T) {
	size, err := NewRPC(4096).spec.size([]byte{0x80, 0, 0, 0x18})
	if err != nil || size != 4+0x18 {
		t.Fatalf("last-fragment record: size %d, err %v; want 28, nil", size, err)
	}
	if _, err := NewRPC(4096).spec.size([]byte{0x00, 0, 0, 0x18}); err == nil {
		t.Fatal("record without the last-fragment bit was accepted")
	}
}

func TestSMBMoreProcessingStatusOn32BitInt(t *testing.T) {
	status := le([]byte{0x16, 0x00, 0x00, 0xC0}, 0, 4)
	if uint32(status) != statusMoreProcessing {
		t.Fatalf("STATUS_MORE_PROCESSING_REQUIRED read as %#x", uint32(status))
	}
}

func TestRESPLengthAbove32BitIntIsBudget(t *testing.T) {
	for _, digits := range []string{"2147483648", "9999999999", "999999999999999999", "9999999999999999999"} {
		p := NewRESP(4096)
		_, err := p.Feed([]byte("*2\r\n$4\r\nPING\r\n$" + digits + "\r\n"))
		var pe *parsing.Error
		if !errors.As(err, &pe) || pe.Kind != "budget" {
			t.Fatalf("bulk length %s: err %v; want a budget error", digits, err)
		}
	}
}
