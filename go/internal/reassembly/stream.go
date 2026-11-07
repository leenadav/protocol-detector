// Package reassembly keeps one direction's bounded initial window and hands out each contiguous byte
// exactly once, mirroring protocol_adapters/sessions.py Stream (stage 3 / A03, D02).
//
// A Stream is transport-only: it knows sequence numbers, the retained window and what has been
// delivered. It does not own an inspector; the owner feeds the returned deltas to whatever consumes
// the direction, so one reassembler serves the engine and any second consumer (TLS decoding) from the
// same delivery. A conflicting overlap is detected before any byte of the offending segment is admitted
// and makes the stream unusable (Feed keeps returning the error); a wholly identical duplicate delivers
// nothing. Sequence arithmetic is modulo 2^32.
package reassembly

import (
	"bytes"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// Modulus is the TCP sequence space.
const Modulus = 1 << 32

// Reason sentences shared with the Python reference (compared verbatim by the harness).
const (
	ReasonOutsideWindow = "Data lies outside the bounded initial stream window"
	ReasonConflict      = "Conflicting overlapping bytes; classification invalidated"
)

// Stream is one direction's retained initial window.
type Stream struct {
	first      uint32
	limit      int
	prefixOnly bool
	buf        []byte // grows on demand up to limit (A07)
	present    []bool
	contiguous int
	stored     int
	highestEnd int
	delivered  int
	err        error
}

// New creates a stream whose first payload byte has sequence number first (normally SYN + 1).
// limit is the per-direction byte window (1..65536); prefixOnly clips instead of failing beyond it
// (the live observer's mode).
func New(first uint32, limit int, prefixOnly bool) (*Stream, error) {
	if limit < 1 || limit > 65536 {
		return nil, errs.New(errs.Invalid, errs.ScopeDirection, "stream window must be 1..65536 bytes")
	}
	return &Stream{first: first, limit: limit, prefixOnly: prefixOnly}, nil
}

// Counters as the Python reference exposes them.
func (s *Stream) First() uint32   { return s.first }
func (s *Stream) Limit() int      { return s.limit }
func (s *Stream) Contiguous() int { return s.contiguous }
func (s *Stream) Stored() int     { return s.stored }
func (s *Stream) HighestEnd() int { return s.highestEnd }
func (s *Stream) Delivered() int  { return s.delivered }
func (s *Stream) Pending() int    { return s.stored - s.contiguous }
func (s *Stream) Err() error      { return s.err }

// NextSequence is the sequence number of the first byte not yet contiguous.
func (s *Stream) NextSequence() uint32 {
	return uint32((uint64(s.first) + uint64(s.contiguous)) % Modulus)
}

// Allocated is the memory the window currently holds (A07 accounting; never above 2 * limit).
func (s *Stream) Allocated() int { return len(s.buf) + len(s.present) }

// Prefix returns a transient view of the contiguous prefix (valid until the next Feed).
func (s *Stream) Prefix() []byte { return s.buf[:s.contiguous] }

func (s *Stream) reserve(end int) {
	if end > len(s.buf) {
		grow := end - len(s.buf)
		s.buf = append(s.buf, make([]byte, grow)...)
		s.present = append(s.present, make([]bool, grow)...)
	}
}

func (s *Stream) fail(reason string) error {
	s.err = errs.New(errs.Malformed, errs.ScopeDirection, reason)
	return s.err
}

// Feed admits one segment. It returns the bytes that became contiguous by this segment (a copy the
// caller owns; nil when nothing new became contiguous) or an error: the stream's permanent failure
// (ReasonConflict, ReasonOutsideWindow) as an errs.Malformed error. The caller keeps ownership of
// payload (ADR 0001).
func (s *Stream) Feed(sequence uint32, payload []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if len(payload) == 0 {
		return nil, nil
	}
	offset := int((uint64(sequence) + Modulus - uint64(s.first)) % Modulus)
	if s.prefixOnly && offset >= Modulus/2 {
		leading := Modulus - offset
		if leading >= len(payload) {
			return nil, nil
		}
		payload = payload[leading:]
		offset = 0
	}
	if offset+len(payload) > s.limit {
		if !s.prefixOnly {
			return nil, s.fail(ReasonOutsideWindow)
		}
		if offset >= s.limit {
			return nil, nil
		}
		payload = payload[:s.limit-offset]
	}
	end := offset + len(payload)
	// Common in-order case.
	if offset == s.contiguous && s.stored == s.contiguous {
		s.reserve(end)
		copy(s.buf[offset:end], payload)
		for i := offset; i < end; i++ {
			s.present[i] = true
		}
		s.stored, s.contiguous, s.highestEnd = end, end, end
		return s.deliver(), nil
	}
	allocated := len(s.present)
	missing := 0
	for i := offset; i < end; i++ {
		if i >= allocated || !s.present[i] {
			missing++
		}
	}
	conflict := false
	switch {
	case missing == 0:
		conflict = !bytes.Equal(s.buf[offset:end], payload)
	case missing == len(payload):
		conflict = false
	default:
		// Check every occupied byte BEFORE writing anything: a late conflict must not admit earlier
		// new bytes or deliver them.
		for i := offset; i < end && i < allocated; i++ {
			if s.present[i] && s.buf[i] != payload[i-offset] {
				conflict = true
				break
			}
		}
	}
	if conflict {
		return nil, s.fail(ReasonConflict)
	}
	if missing == 0 {
		return nil, nil // identical duplicate: never delivered twice
	}
	s.reserve(end)
	copy(s.buf[offset:end], payload)
	for i := offset; i < end; i++ {
		s.present[i] = true
	}
	s.stored += missing
	if end > s.highestEnd {
		s.highestEnd = end
	}
	old := s.contiguous
	if offset <= old && old < end {
		gap := -1
		for i := old; i < s.highestEnd; i++ {
			if !s.present[i] {
				gap = i
				break
			}
		}
		if gap == -1 {
			s.contiguous = s.highestEnd
		} else {
			s.contiguous = gap
		}
	}
	if s.contiguous == old {
		return nil, nil
	}
	return s.deliver(), nil
}

// deliver copies the not-yet-delivered contiguous bytes; every byte leaves exactly once.
func (s *Stream) deliver() []byte {
	if s.delivered >= s.contiguous {
		return nil
	}
	out := make([]byte, s.contiguous-s.delivered)
	copy(out, s.buf[s.delivered:s.contiguous])
	s.delivered = s.contiguous
	return out
}

// Release zeroes and drops the window.
func (s *Stream) Release() {
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.buf, s.present = nil, nil
}
