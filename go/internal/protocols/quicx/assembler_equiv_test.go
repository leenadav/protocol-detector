package quicx

import (
	"bytes"
	"container/list"
	"fmt"
	"math/rand"
	"testing"
)

// naive is the assembler before SEC-QUIC-1, kept verbatim as the oracle: it scans every entry on each expiry and
// reset. The indexed Assembler must answer every operation sequence the same way.
type naive struct {
	MaxConnections int
	IdleSeconds    float64
	order          *list.List
	entries        map[key]*list.Element
	Counts         map[string]int
}

func newNaive(maxConnections int, idleSeconds float64) *naive {
	return &naive{MaxConnections: maxConnections, IdleSeconds: idleSeconds, order: list.New(), entries: map[key]*list.Element{},
		Counts: map[string]int{"conflicts": 0, "evictions": 0, "expired": 0, "exhausted": 0}}
}

func (a *naive) Len() int { return len(a.entries) }

func (a *naive) Clear() {
	a.order.Init()
	a.entries = map[key]*list.Element{}
}

func (a *naive) Reset(scope string) {
	for k, el := range a.entries {
		if k.scope == scope {
			a.order.Remove(el)
			delete(a.entries, k)
		}
	}
}

func (a *naive) expire(now float64) {
	for k, el := range a.entries {
		if now-el.Value.(*entry).last > a.IdleSeconds {
			a.order.Remove(el)
			delete(a.entries, k)
			a.Counts["expired"]++
		}
	}
}

func (a *naive) Conflicted(dcid []byte, scope string, version uint32, now *float64) bool {
	if now != nil {
		a.expire(*now)
	}
	el := a.entries[key{scope, version, string(dcid)}]
	if el == nil {
		return false
	}
	e := el.Value.(*entry)
	if !e.conflict {
		return false
	}
	if now != nil {
		e.last = *now
	}
	return true
}

func (a *naive) Add(dcid []byte, fragments []Fragment, scope string, version uint32, now *float64) (string, []byte) {
	if now != nil {
		a.expire(*now)
	}
	k := key{scope, version, string(dcid)}
	var e *entry
	if el := a.entries[k]; el != nil {
		e = el.Value.(*entry)
		a.order.Remove(el)
		delete(a.entries, k)
	} else {
		if len(a.entries) >= a.MaxConnections {
			oldest := a.order.Front()
			a.order.Remove(oldest)
			delete(a.entries, oldest.Value.(*entry).key)
			a.Counts["evictions"]++
		}
		e = &entry{key: k}
		if now != nil {
			e.last = *now
		}
	}
	if now != nil {
		e.last = *now
	}
	if e.conflict {
		a.entries[k] = a.order.PushBack(e)
		return Conflict, nil
	}
	merged := merge(e.fragments, fragments)
	if contradicts(merged) { // the contradiction outranks the budget (PRO-201)
		e.fragments, e.conflict = nil, true
		a.Counts["conflicts"]++
		a.entries[k] = a.order.PushBack(e)
		return Conflict, nil
	}
	total := 0
	for _, f := range merged {
		total += len(f.Data)
	}
	if len(merged) > MaxFragments || total > MaxCrypto {
		a.Counts["exhausted"]++
		return Exhausted, nil
	}
	status, data := Assemble(merged)
	if status == Conflict {
		e.fragments, e.conflict = nil, true
		a.Counts["conflicts"]++
	} else {
		e.fragments = merged
	}
	a.entries[k] = a.order.PushBack(e)
	return status, data
}

func (a *naive) keys() []string {
	var out []string
	for el := a.order.Front(); el != nil; el = el.Next() {
		k := el.Value.(*entry).key
		out = append(out, fmt.Sprintf("%s/%d/%x", k.scope, k.version, k.dcid))
	}
	return out
}

func (a *Assembler) keys() []string {
	var out []string
	for el := a.order.Front(); el != nil; el = el.Next() {
		k := el.Value.(*entry).key
		out = append(out, fmt.Sprintf("%s/%d/%x", k.scope, k.version, k.dcid))
	}
	return out
}

// consistent checks the indexes agree: every entry is in the LRU list, the heap (at its slot, heap-ordered) and its
// scope's index, and nothing else is.
func (a *Assembler) consistent(t *testing.T) {
	t.Helper()
	if a.order.Len() != len(a.entries) || len(a.idle) != len(a.entries) {
		t.Fatalf("index sizes: order %d, idle %d, entries %d", a.order.Len(), len(a.idle), len(a.entries))
	}
	scoped := 0
	for scope, members := range a.scopes {
		if len(members) == 0 {
			t.Fatalf("empty scope index %q kept", scope)
		}
		for k, e := range members {
			if a.entries[k] != e || k.scope != scope {
				t.Fatalf("scope index entry %v not in the store", k)
			}
			scoped++
		}
	}
	if scoped != len(a.entries) {
		t.Fatalf("scope index holds %d of %d entries", scoped, len(a.entries))
	}
	for i, e := range a.idle {
		if e.slot != i || a.entries[e.key] != e {
			t.Fatalf("heap slot %d holds a stale entry", i)
		}
		if i > 0 && a.idle[(i-1)/2].last > e.last {
			t.Fatalf("heap order broken at %d", i)
		}
	}
}

func randomFragments(r *rand.Rand) []Fragment {
	hello := append([]byte{1, 0, 0, byte(4 + r.Intn(40))}, make([]byte, 80)...)
	for i := 4; i < len(hello); i++ {
		hello[i] = byte(i)
	}
	if r.Intn(8) == 0 { // a contradicting retransmission
		hello[10] ^= 0xff
	}
	var out []Fragment
	for n := 1 + r.Intn(3); n > 0; n-- {
		a := r.Intn(len(hello) - 1)
		b := a + 1 + r.Intn(len(hello)-a-1)
		out = append(out, Fragment{uint64(a), append([]byte{}, hello[a:b]...)})
	}
	if r.Intn(20) == 0 { // over the fragment budget
		for i := 0; i < MaxFragments+1; i++ {
			out = append(out, Fragment{uint64(i * 2), []byte{hello[i*2]}})
		}
	}
	return out
}

// TestAssemblerMatchesTheScanningOracle (SEC-QUIC-1): the indexed assembler answers random operation sequences
// exactly like the scanning implementation it replaced: statuses, bytes, counts, size and LRU order after every
// operation, with time moving forwards, standing still, jumping and going backwards, and without time.
func TestAssemblerMatchesTheScanningOracle(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		r := rand.New(rand.NewSource(seed))
		capacity, idle := 1+r.Intn(12), float64(1+r.Intn(30))
		got, want := NewAssembler(capacity, idle), newNaive(capacity, idle)
		clock := 0.0
		for step := 0; step < 600; step++ {
			scope := fmt.Sprintf("s%d", r.Intn(5))
			dcid := []byte{byte(r.Intn(6))}
			version := uint32(1 + r.Intn(2))
			var now *float64
			if r.Intn(6) != 0 {
				switch r.Intn(10) {
				case 0:
					clock -= float64(r.Intn(10)) // capture time running backwards
				case 1:
					clock += idle + float64(r.Intn(20)) // a jump past the idle window
				default:
					clock += float64(r.Intn(4))
				}
				c := clock
				now = &c
			}
			where := fmt.Sprintf("seed %d step %d", seed, step)
			switch op := r.Intn(20); {
			case op < 12:
				fragments := randomFragments(r)
				gs, gd := got.Add(dcid, fragments, scope, version, now)
				ws, wd := want.Add(dcid, fragments, scope, version, now)
				if gs != ws || !bytes.Equal(gd, wd) {
					t.Fatalf("%s: Add = %s %x, oracle %s %x", where, gs, gd, ws, wd)
				}
			case op < 16:
				if g, w := got.Conflicted(dcid, scope, version, now), want.Conflicted(dcid, scope, version, now); g != w {
					t.Fatalf("%s: Conflicted = %v, oracle %v", where, g, w)
				}
			case op < 19:
				got.Reset(scope)
				want.Reset(scope)
			default:
				got.Clear()
				want.Clear()
			}
			if got.Len() != want.Len() || fmt.Sprint(got.Counts) != fmt.Sprint(want.Counts) {
				t.Fatalf("%s: Len %d counts %v, oracle %d %v", where, got.Len(), got.Counts, want.Len(), want.Counts)
			}
			g, w := got.keys(), want.keys()
			if fmt.Sprint(g) != fmt.Sprint(w) {
				t.Fatalf("%s: LRU order %v, oracle %v", where, g, w)
			}
			got.consistent(t)
		}
	}
}

// TestResetAndExpiryTouchOnlyTheirEntries: a reset of one scope leaves the others, and expiry removes exactly the
// entries idle for longer than the window, oldest first, whatever order they were added in.
func TestResetAndExpiryTouchOnlyTheirEntries(t *testing.T) {
	a := NewAssembler(4096, 10)
	at := func(v float64) *float64 { return &v }
	for i := 0; i < 1024; i++ { // last-seen times 991..1000, all inside one idle window, in no particular order
		a.Add([]byte{byte(i), byte(i >> 8)}, []Fragment{{0, []byte{1, 0}}}, fmt.Sprintf("scope%d", i%64), 1, at(float64(1000-(i*7)%10)))
	}
	if a.Len() != 1024 || a.Counts["expired"] != 0 {
		t.Fatalf("Len %d, expired %d", a.Len(), a.Counts["expired"])
	}
	a.Reset("scope7")
	if a.Len() != 1024-16 || a.scopes["scope7"] != nil {
		t.Fatalf("Reset left %d entries (scope7 index %v)", a.Len(), a.scopes["scope7"])
	}
	stale := 0
	for _, e := range a.entries {
		if 1005-e.last > 10 {
			stale++
		}
	}
	a.Conflicted([]byte{0xff}, "none", 1, at(1005)) // expiry runs: exactly the entries last seen before 995 go
	if stale == 0 || a.Counts["expired"] != stale || a.Len() != 1024-16-stale {
		t.Fatalf("expired %d of %d stale entries; %d left", a.Counts["expired"], stale, a.Len())
	}
	for _, e := range a.entries {
		if 1005-e.last > 10 {
			t.Fatalf("expiry kept an entry last seen at %v", e.last)
		}
	}
	a.consistent(t)
}

func benchmarkDatagrams(b *testing.B, held int) {
	a := NewAssembler(held+1, 60)
	now := 0.0
	for i := 0; i < held; i++ {
		a.Add([]byte{byte(i), byte(i >> 8)}, []Fragment{{0, []byte{1, 0}}}, fmt.Sprintf("flow%d", i), 1, &now)
	}
	dcid := []byte("probe")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Conflicted(dcid, "probe", 1, &now) // the per-datagram call every QUIC datagram makes
		a.Reset("nothing")                   // a flow end with no QUIC state
	}
}

// BenchmarkAssemblerDatagram measures the per-datagram expiry check and a flow-end reset with an empty store and
// with 1024 held connections; before SEC-QUIC-1 the second cost grew with the store (about 12 µs).
func BenchmarkAssemblerDatagram(b *testing.B) {
	b.Run("empty", func(b *testing.B) { benchmarkDatagrams(b, 0) })
	b.Run("held1024", func(b *testing.B) { benchmarkDatagrams(b, 1024) })
}
