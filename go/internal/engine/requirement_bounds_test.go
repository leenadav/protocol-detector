package engine

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Bounds a security requirement names that no frozen or recorded case sits on (a mutation of the bound survived
// them, PRO-403). Each answer is the reference's at python-final for the same bytes (migration/parity/cases.py
// run_stream), so these stay checks of the documented profile, not of the Go code's own constants.
func TestRequirementBoundsMatchTheReference(t *testing.T) {
	le32 := func(v int) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, uint32(v)); return b }
	// SR-51: a SPICE client link message carries at most 32 common and 32 channel capabilities, each sized exactly.
	spice := func(common, channel int) []byte {
		body := append([]byte{0, 0, 0, 0, 1, 0}, le32(common)...)
		body = append(append(append(body, le32(channel)...), le32(18)...), make([]byte, 4*(common+channel))...)
		return append(append(append(append([]byte("REDQ"), le32(2)...), le32(2)...), le32(len(body))...), body...)
	}
	// SR-48: the initial SETTINGS payload is at most 16384 bytes (a multiple of six).
	settings := func(n int) []byte {
		frame := []byte{byte(n >> 16), byte(n >> 8), byte(n), 4, 0, 0, 0, 0, 0}
		frame = append(frame, bytes.Repeat([]byte{0, 3, 0, 0, 0, 0x64}, n/6)...)
		return append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), frame...)
	}
	// SR-50: a syslog TCP message is read within min(max_line, 8192) bytes, whatever larger max_line is configured.
	syslog := func(n int, counted bool) []byte {
		msg := []byte("<34>1 2003-10-11T22:14:15.003Z host app - - - ")
		msg = append(msg, bytes.Repeat([]byte("x"), n-len(msg))...)
		if counted {
			return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
		}
		return append(msg, '\n')
	}
	for _, c := range []struct {
		name    string
		data    []byte
		maxLine int
		status  contracts.Status
		reason  string
	}{
		{"spice 32 common capabilities", spice(32, 0), 0, contracts.Identified, "SPICE link message validated; connection id and capabilities not emitted"},
		{"spice 32+32 capabilities", spice(32, 32), 0, contracts.Identified, "SPICE link message validated; connection id and capabilities not emitted"},
		{"spice 33 common capabilities", spice(33, 0), 0, contracts.Malformed, "SPICE link message fields outside the profile"},
		{"spice 33 channel capabilities", spice(0, 33), 0, contracts.Malformed, "SPICE link message fields outside the profile"},
		{"spice 32+33 capabilities", spice(32, 33), 0, contracts.Malformed, "SPICE link message fields outside the profile"},
		{"settings 16380 bytes", settings(16380), 0, contracts.Identified, "HTTP/2 client preface and initial SETTINGS validated; no HEADERS frame decoded yet"},
		{"settings 16386 bytes", settings(16386), 0, contracts.Malformed, "Invalid initial SETTINGS payload length"},
		{"syslog octet count 8192", syslog(8192, true), 65536, contracts.Identified,
			"RFC5424 header and NIL structured-data framing validated; log content unverified; TCP octet-counting framing"},
		{"syslog octet count 8193", syslog(8193, true), 65536, contracts.BudgetExhausted, "Syslog octet count exceeds the line budget"},
		{"syslog line of 8192", syslog(8192, false), 65536, contracts.BudgetExhausted, "Syslog message exceeds the line budget"},
	} {
		cfg := contracts.DefaultConfig()
		if c.maxLine != 0 {
			cfg.MaxLine = c.maxLine
		}
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		in.Feed(c.data)
		if in.Observation.Status != c.status || in.Observation.Reason != c.reason {
			t.Errorf("%s: %s %q, want %s %q", c.name, in.Observation.Status, in.Observation.Reason, c.status, c.reason)
		}
	}
}
