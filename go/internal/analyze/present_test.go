package analyze

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

func classicCapture(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, frame := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(frame)))
		out = append(append(out, header...), frame...)
	}
	return out
}

func TestPresentRefusalsAndMeta(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	zero := func() float64 { return 0 }
	refusal := func(data []byte, limits Limits, kind, message string) {
		t.Helper()
		_, err := Present(data, pack, limits, zero)
		refused, ok := err.(*PresentError)
		if !ok || refused.Type != kind || refused.Message != message {
			t.Fatalf("got %#v, want %s %q", err, kind, message)
		}
	}
	refusal(classicCapture(), DefaultLimits, "ValueError", "The capture contains no frames.")
	refusal([]byte("not a pcap"), DefaultLimits, "CaptureError", "Incomplete or failed PCAP stream")
	junk := make([]byte, 60) // not IPv4: counted as skipped, never an error
	refusal(classicCapture(junk), Limits{Frames: 0, Sessions: 500, Events: 4000}, "ValueError",
		"Frame limit reached. Use a capture with at most 20,000 frames.")
	truncated := classicCapture(junk)
	binary.LittleEndian.PutUint32(truncated[24+12:], 61)
	refusal(truncated, DefaultLimits, "CaptureError", "Truncated capture record. No results published; use a complete capture.")

	text, err := Present(classicCapture(junk, junk), pack, DefaultLimits, func() float64 { return 1.005 })
	if err != nil {
		t.Fatal(err)
	}
	want := `{"sessions": [], "meta": {"frames": 2, "skipped": 2, "wire_bytes": 120, "processing_ms": 1.0, "events": 0, "identified": 0, ` +
		`"timeline": [[1700000000, 1], [1700000001, 1]], "sha256": "`
	if !strings.HasPrefix(text, want) || !strings.HasSuffix(text, `"}}`) {
		t.Fatalf("meta layout:\n%s", text)
	}
}
