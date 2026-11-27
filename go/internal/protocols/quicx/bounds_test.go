package quicx

import "testing"

// SR-24: one connection's CRYPTO assembly holds at most 8 fragments and 16384 bytes; the ninth fragment, or a byte
// past 16384, ends the assembly as exhausted. The numbers are the documented budget (PROTOCOLS.md, quic
// MAX_FRAGMENTS and MAX_CRYPTO), written out so a changed constant fails here.
func TestCryptoAssemblyBudgetIsEightFragmentsAnd16KiB(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	a := NewAssembler(4, 10)
	for i := 0; i < 8; i++ {
		if s, _ := a.Add(dcid, []Fragment{{uint64(200 + i*2), []byte{byte(i)}}}, "A", V1, nil); s == Exhausted {
			t.Fatalf("fragment %d of 8 exhausted the assembly", i+1)
		}
	}
	if s, _ := a.Add(dcid, []Fragment{{400, []byte{1}}}, "A", V1, nil); s != Exhausted {
		t.Fatalf("the ninth fragment: %s, want %s", s, Exhausted)
	}
	b := NewAssembler(4, 10)
	if s, _ := b.Add(dcid, []Fragment{{100, make([]byte, 16384)}}, "B", V1, nil); s == Exhausted {
		t.Fatal("16384 CRYPTO bytes exhausted the assembly")
	}
	c := NewAssembler(4, 10)
	if s, _ := c.Add(dcid, []Fragment{{100, make([]byte, 16385)}}, "C", V1, nil); s != Exhausted {
		t.Fatalf("16385 CRYPTO bytes: %s, want %s", s, Exhausted)
	}
}
