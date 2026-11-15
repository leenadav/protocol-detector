package quicx

import (
	"bytes"
	"container/list"
	"sort"
)

// MaxCrypto and MaxFragments are quic.MAX_CRYPTO and quic.MAX_FRAGMENTS: the assembled ClientHello bytes and the
// CRYPTO fragments one connection may hold.
const (
	MaxCrypto    = 16384
	MaxFragments = 8
)

// Fragment is one CRYPTO frame's (offset, bytes).
type Fragment struct {
	Offset uint64
	Data   []byte
}

// Assembly outcomes (quic.assemble and QuicAssembler.add).
const (
	Complete  = "complete"
	Partial   = "partial"
	Conflict  = "conflict"
	Exhausted = "exhausted"
)

type key struct {
	scope   string
	version uint32
	dcid    string
}

type entry struct {
	key       key
	fragments []Fragment
	conflict  bool
	last      float64
}

// Assembler ports quic.QuicAssembler (contracts C5/C6, D01/D02): a bounded CRYPTO fragment store with one entry
// per connection, keyed by (scope, version, DCID). The scope is the host's flow identity for the datagram (the
// analyzer passes "source>destination", so direction is part of it; a bare datagram inspector passes ""). Entries
// from a different scope, version or DCID never meet. Every overlap is compared byte for byte; a contradiction
// turns the entry into a sticky conflict marker that answers "conflict" for every later datagram of that
// connection until the host resets the scope or the entry expires. Lifetime: LRU eviction at MaxConnections, idle
// expiry when the host supplies time, Reset(scope) when the host ends a flow.
type Assembler struct {
	MaxConnections int
	IdleSeconds    float64
	order          *list.List // least recently used at the front
	entries        map[key]*list.Element
	Counts         map[string]int
}

// NewAssembler validates the limits like the Python constructor.
func NewAssembler(maxConnections int, idleSeconds float64) *Assembler {
	if maxConnections < 1 || idleSeconds <= 0 {
		panic("quicx: invalid QUIC assembler limits")
	}
	return &Assembler{MaxConnections: maxConnections, IdleSeconds: idleSeconds, order: list.New(), entries: map[key]*list.Element{},
		Counts: map[string]int{"conflicts": 0, "evictions": 0, "expired": 0, "exhausted": 0}}
}

// Len is the number of connections held.
func (a *Assembler) Len() int { return len(a.entries) }

// Clear forgets every connection.
func (a *Assembler) Clear() {
	a.order.Init()
	a.entries = map[key]*list.Element{}
}

// Reset forgets every connection of one flow scope (the host ended or restarted the flow).
func (a *Assembler) Reset(scope string) {
	for k, el := range a.entries {
		if k.scope == scope {
			a.order.Remove(el)
			delete(a.entries, k)
		}
	}
}

func (a *Assembler) expire(now float64) {
	for k, el := range a.entries {
		if now-el.Value.(*entry).last > a.IdleSeconds {
			a.order.Remove(el)
			delete(a.entries, k)
			a.Counts["expired"]++
		}
	}
}

// Conflicted reports whether this connection carries a conflict marker; the marker binds every later datagram of
// the connection, CRYPTO or not, until reset or expiry. It refreshes the entry's idle time but not its LRU place.
func (a *Assembler) Conflicted(dcid []byte, scope string, version uint32, now *float64) bool {
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

// Add merges fragments for one connection and returns the status and, when complete, the handshake message.
func (a *Assembler) Add(dcid []byte, fragments []Fragment, scope string, version uint32, now *float64) (string, []byte) {
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
	total := 0
	for _, f := range merged {
		total += len(f.Data)
	}
	if len(merged) > MaxFragments || total > MaxCrypto {
		a.Counts["exhausted"]++
		return Exhausted, nil // over budget: this connection is forgotten
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

// merge is quic._merge: the union in (offset, length) order; an exact duplicate is kept once.
func merge(existing, fragments []Fragment) []Fragment {
	merged := append([]Fragment{}, existing...)
	for _, f := range fragments {
		duplicate := false
		for _, m := range merged {
			if m.Offset == f.Offset && bytes.Equal(m.Data, f.Data) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			merged = append(merged, Fragment{f.Offset, append([]byte{}, f.Data...)})
		}
	}
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Offset != merged[j].Offset {
			return merged[i].Offset < merged[j].Offset
		}
		return len(merged[i].Data) < len(merged[j].Data)
	})
	return merged
}

// Assemble is quic.assemble: every overlapping pair is compared byte for byte before anything is assembled;
// complete returns exactly one handshake message from offset zero.
func Assemble(fragments []Fragment) (string, []byte) {
	items := append([]Fragment{}, fragments...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Offset < items[j].Offset })
	for i, f := range items {
		end := f.Offset + uint64(len(f.Data))
		for _, other := range items[i+1:] {
			if other.Offset >= end {
				break
			}
			stop := end
			if o := other.Offset + uint64(len(other.Data)); o < stop {
				stop = o
			}
			if !bytes.Equal(f.Data[other.Offset-f.Offset:stop-f.Offset], other.Data[:stop-other.Offset]) {
				return Conflict, nil
			}
		}
	}
	var data []byte
	for _, f := range items {
		if f.Offset > uint64(len(data)) {
			return Partial, nil
		}
		if f.Offset+uint64(len(f.Data)) > uint64(len(data)) {
			data = append(data, f.Data[uint64(len(data))-f.Offset:]...)
		}
	}
	if len(data) < 4 || data[0] != 1 {
		return Partial, nil
	}
	size := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) >= 4+size {
		return Complete, data[:4+size]
	}
	return Partial, nil
}
