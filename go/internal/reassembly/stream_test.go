package reassembly

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// recorder is the trivial inspector of M3: it only records what it was delivered.
type recorder struct{ got []byte }

func (r *recorder) feed(delta []byte) { r.got = append(r.got, delta...) }

func mustNew(t *testing.T, first uint32, limit int) *Stream {
	t.Helper()
	s, err := New(first, limit, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func drive(t *testing.T, s *Stream, sink *recorder, seq uint32, payload []byte) error {
	t.Helper()
	delta, err := s.Feed(seq, payload)
	if err != nil {
		return err
	}
	sink.feed(delta)
	if s.Delivered() != s.Contiguous() {
		t.Fatalf("delivered %d != contiguous %d", s.Delivered(), s.Contiguous())
	}
	return nil
}

var message = []byte("GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: x\r\n\r\n")

func TestInOrderDeliversOnce(t *testing.T) {
	s, sink := mustNew(t, 1000, 65536), &recorder{}
	drive(t, s, sink, 1000, message[:10])
	drive(t, s, sink, 1010, message[10:])
	if !bytes.Equal(sink.got, message) || s.Stored() != len(message) || s.Pending() != 0 {
		t.Fatalf("got %q", sink.got)
	}
	if s.NextSequence() != uint32(1000+len(message)) {
		t.Fatal("next sequence")
	}
}

func TestEverySplitPointDeliversTheSameBytesOnce(t *testing.T) {
	for cut := 1; cut < len(message); cut++ {
		for _, reversed := range []bool{false, true} {
			s, sink := mustNew(t, 5000, 1024), &recorder{}
			parts := [][2]interface{}{{uint32(5000), message[:cut]}, {uint32(5000 + cut), message[cut:]}}
			if reversed {
				parts[0], parts[1] = parts[1], parts[0]
			}
			for _, p := range parts {
				if err := drive(t, s, sink, p[0].(uint32), p[1].([]byte)); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(sink.got, message) {
				t.Fatalf("cut %d reversed %v: %q", cut, reversed, sink.got)
			}
		}
	}
}

func TestGapThenFillAndDuplicates(t *testing.T) {
	s, sink := mustNew(t, 0, 1024), &recorder{}
	drive(t, s, sink, 20, message[20:30])
	if len(sink.got) != 0 || s.Pending() != 10 || s.HighestEnd() != 30 {
		t.Fatal("gap delivered early")
	}
	drive(t, s, sink, 0, message[:20])
	if !bytes.Equal(sink.got, message[:30]) {
		t.Fatalf("after fill %q", sink.got)
	}
	drive(t, s, sink, 0, message[:30])  // identical retransmission
	drive(t, s, sink, 5, message[5:12]) // identical inner overlap
	if !bytes.Equal(sink.got, message[:30]) || s.Stored() != 30 {
		t.Fatal("duplicate delivered twice")
	}
	drive(t, s, sink, 25, message[25:40]) // consistent overlap extending the prefix
	if !bytes.Equal(sink.got, message[:40]) {
		t.Fatalf("overlap extension %q", sink.got)
	}
}

func TestConflictingOverlapIsRejectedBeforeAdmittingAnything(t *testing.T) {
	s, sink := mustNew(t, 0, 1024), &recorder{}
	drive(t, s, sink, 0, message[:16])
	changed := append([]byte{}, message[8:32]...)
	changed[3] ^= 0xff
	err := drive(t, s, sink, 8, changed)
	if !errors.Is(err, errs.Malformed.Err()) || err.Error() != "malformed: "+ReasonConflict+" (direction)" {
		t.Fatalf("conflict error %v", err)
	}
	if !bytes.Equal(sink.got, message[:16]) || s.Stored() != 16 || s.HighestEnd() != 16 {
		t.Fatal("bytes of the conflicting segment were admitted")
	}
	if _, err := s.Feed(16, message[16:]); !errors.Is(err, errs.Malformed.Err()) {
		t.Fatal("stream usable after conflict")
	}
	// A conflict against a retained byte beyond a gap is caught the same way (mixed overlap).
	s2, sink2 := mustNew(t, 0, 1024), &recorder{}
	drive(t, s2, sink2, 10, message[10:20])
	bad := append([]byte{}, message[:15]...)
	bad[12] ^= 1
	if err := drive(t, s2, sink2, 0, bad); err == nil || len(sink2.got) != 0 {
		t.Fatal("mixed overlap conflict admitted bytes")
	}
}

func TestSequenceWraparound(t *testing.T) {
	first := uint32(0xffffffff - 5)
	s, sink := mustNew(t, first, 1024), &recorder{}
	drive(t, s, sink, first, message[:6])
	drive(t, s, sink, 0, message[6:20]) // wrapped past 2^32
	if !bytes.Equal(sink.got, message[:20]) || s.NextSequence() != 14 {
		t.Fatalf("wraparound %q next %d", sink.got, s.NextSequence())
	}
}

func TestWindowLimit(t *testing.T) {
	s, sink := mustNew(t, 0, 16), &recorder{}
	drive(t, s, sink, 0, message[:16])
	err := drive(t, s, sink, 16, []byte("X"))
	if !errors.Is(err, errs.Malformed.Err()) || err.Error() != "malformed: "+ReasonOutsideWindow+" (direction)" {
		t.Fatalf("limit error %v", err)
	}
	if s.Allocated() > 2*16 {
		t.Fatal("allocation above 2*limit")
	}
	prefix, _ := New(0, 16, true)
	if d, err := prefix.Feed(0, message[:40]); err != nil || len(d) != 16 {
		t.Fatalf("prefix mode clip: %d %v", len(d), err)
	}
	if d, err := prefix.Feed(100, []byte("late")); err != nil || d != nil {
		t.Fatal("prefix mode beyond window")
	}
	if _, err := New(0, 0, false); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal("zero window accepted")
	}
}

func TestLazyAllocationAndRelease(t *testing.T) {
	s := mustNew(t, 0, 65536)
	if s.Allocated() != 0 {
		t.Fatal("allocated up front")
	}
	s.Feed(0, message)
	if s.Allocated() != 2*len(message) {
		t.Fatalf("allocated %d", s.Allocated())
	}
	s.Release()
	if s.Allocated() != 0 {
		t.Fatal("release kept memory")
	}
}

func TestInputBufferIsNotRetained(t *testing.T) {
	s := mustNew(t, 0, 1024)
	in := append([]byte{}, message[:20]...)
	delta, _ := s.Feed(0, in)
	for i := range in {
		in[i] = 'z'
	}
	if !bytes.Equal(delta, message[:20]) || !bytes.Equal(s.Prefix(), message[:20]) {
		t.Fatal("stream aliases the caller's buffer")
	}
}

// Metamorphic: any permutation of consistent segments delivers the same bytes exactly once and never
// a byte a conflicting segment would have changed.
func TestRandomPermutationsDeliverExactlyOnce(t *testing.T) {
	rng := rand.New(rand.NewSource(20261107))
	for round := 0; round < 300; round++ {
		n := 1 + rng.Intn(60)
		data := make([]byte, n)
		rng.Read(data)
		var segments [][2]int
		for start := 0; start < n; {
			end := start + 1 + rng.Intn(12)
			if end > n {
				end = n
			}
			segments = append(segments, [2]int{start, end})
			// sometimes also an overlapping consistent retransmit
			if rng.Intn(3) == 0 {
				segments = append(segments, [2]int{start / 2, end})
			}
			start = end
		}
		rng.Shuffle(len(segments), func(i, j int) { segments[i], segments[j] = segments[j], segments[i] })
		s, sink := mustNew(t, uint32(rng.Uint32()), 4096), &recorder{}
		first := s.First()
		for _, seg := range segments {
			if err := drive(t, s, sink, uint32((uint64(first)+uint64(seg[0]))%Modulus), data[seg[0]:seg[1]]); err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if !bytes.Equal(sink.got, data) || s.Stored() != n || s.Pending() != 0 {
			t.Fatalf("round %d: delivered %d of %d", round, len(sink.got), n)
		}
	}
}

func FuzzFeedInvariants(f *testing.F) {
	f.Add(uint32(0), []byte("abcdef"), uint32(2), []byte("cdefgh"))
	f.Fuzz(func(t *testing.T, first uint32, a []byte, off uint32, b []byte) {
		s, err := New(first, 256, false)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		for _, seg := range [][2]interface{}{{first, a}, {uint32((uint64(first) + uint64(off%300)) % Modulus), b}} {
			d, err := s.Feed(seg[0].(uint32), seg[1].([]byte))
			if err != nil {
				if !errors.Is(err, errs.Malformed.Err()) {
					t.Fatal(err)
				}
				break
			}
			got = append(got, d...)
		}
		if len(got) != s.Delivered() || s.Delivered() != s.Contiguous() || s.Contiguous() > s.Stored() || s.Stored() > s.HighestEnd() || s.HighestEnd() > 256 {
			t.Fatalf("invariants: got %d delivered %d contiguous %d stored %d highest %d", len(got), s.Delivered(), s.Contiguous(), s.Stored(), s.HighestEnd())
		}
		if !bytes.Equal(got, s.Prefix()) {
			t.Fatal("delivered bytes differ from the retained prefix")
		}
	})
}
