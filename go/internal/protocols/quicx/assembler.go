package quicx

import (
	"bytes"
	"container/heap"
	"container/list"
	"sort"
)

// MaxCrypto and MaxFragments are quic.MAX_CRYPTO and quic.MAX_FRAGMENTS: the assembled ClientHello bytes and the
// CRYPTO fragments one connection may hold.
const (
	MaxCrypto    = 16384
	MaxFragments = 8
	// MinClientDatagram is RFC 9000 section 14.1: a server discards a client Initial in a smaller UDP datagram.
	MinClientDatagram = 1200
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
	element   *list.Element // its place in the LRU order
	slot      int           // its index in the idle heap
}

// idleHeap orders entries by last-seen time (the oldest first), so expiry visits only the entries it removes.
type idleHeap []*entry

func (h idleHeap) Len() int           { return len(h) }
func (h idleHeap) Less(i, j int) bool { return h[i].last < h[j].last }
func (h idleHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].slot, h[j].slot = i, j
}
func (h *idleHeap) Push(x any) {
	e := x.(*entry)
	e.slot = len(*h)
	*h = append(*h, e)
}
func (h *idleHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

// Assembler ports quic.QuicAssembler (contracts C5/C6, D01/D02): a bounded CRYPTO fragment store with one entry
// per connection, keyed by (scope, version, DCID). The scope is the host's flow identity for the datagram (the
// analyzer passes "source>destination", so direction is part of it; a bare datagram inspector passes ""). Entries
// from a different scope, version or DCID never meet. Every overlap is compared byte for byte; a contradiction
// turns the entry into a sticky conflict marker that answers "conflict" for every later datagram of that
// connection until the host resets the scope or the entry expires. Lifetime: LRU eviction at MaxConnections, idle
// expiry when the host supplies time, Reset(scope) when the host ends a flow.
//
// SEC-QUIC-1 (PRO-47): the entries are indexed three ways so that no datagram or flow end scans the whole store,
// with the reference's semantics unchanged: the LRU list (eviction), an idle heap by last-seen time (expiry removes
// exactly the entries with now-last > IdleSeconds, whatever order time arrives in) and a per-scope index (Reset).
type Assembler struct {
	MaxConnections int
	IdleSeconds    float64
	order          *list.List // least recently used at the front; each element's Value is its *entry
	entries        map[key]*entry
	idle           idleHeap
	scopes         map[string]map[key]*entry
	// SEC-QUIC-3: each scope's first complete ClientHello server name ("" is none). Codex PRO-290 P2 (PRO-291):
	// a name lives as long as its flow, so only Reset(scope) and Clear forget it, never the loss of the scope's
	// last entry. MaxNames bounds the store (least recently used first) for hosts that do not reset their scopes.
	MaxNames  int
	names     map[string]*list.Element // each element's Value is a *serverName
	nameOrder *list.List               // least recently used at the front
	// NameEvictions counts names dropped at MaxNames; it stays out of Counts, which mirrors the reference's counters.
	NameEvictions int
	Counts        map[string]int
}

type serverName struct {
	scope, name string
}

// NewAssembler validates the limits like the Python constructor.
func NewAssembler(maxConnections int, idleSeconds float64) *Assembler {
	if maxConnections < 1 || idleSeconds <= 0 {
		panic("quicx: invalid QUIC assembler limits")
	}
	return &Assembler{MaxConnections: maxConnections, IdleSeconds: idleSeconds, order: list.New(), entries: map[key]*entry{},
		scopes: map[string]map[key]*entry{}, MaxNames: 2 * maxConnections, names: map[string]*list.Element{}, nameOrder: list.New(),
		Counts: map[string]int{"conflicts": 0, "evictions": 0, "expired": 0, "exhausted": 0}}
}

// insert stores a new entry: at the back of the LRU order, in the idle heap and in its scope's index.
func (a *Assembler) insert(e *entry) {
	e.element = a.order.PushBack(e)
	heap.Push(&a.idle, e)
	a.entries[e.key] = e
	scope := a.scopes[e.key.scope]
	if scope == nil {
		scope = map[key]*entry{}
		a.scopes[e.key.scope] = scope
	}
	scope[e.key] = e
}

// remove forgets one entry from every index.
func (a *Assembler) remove(e *entry) {
	a.order.Remove(e.element)
	heap.Remove(&a.idle, e.slot)
	delete(a.entries, e.key)
	if scope := a.scopes[e.key.scope]; scope != nil {
		delete(scope, e.key)
		if len(scope) == 0 {
			delete(a.scopes, e.key.scope)
		}
	}
}

// touch records a new last-seen time.
func (a *Assembler) touch(e *entry, now float64) {
	e.last = now
	heap.Fix(&a.idle, e.slot)
}

// Len is the number of connections held.
func (a *Assembler) Len() int { return len(a.entries) }

// Clear forgets every connection.
func (a *Assembler) Clear() {
	a.order.Init()
	a.entries = map[key]*entry{}
	a.idle = nil
	a.scopes = map[string]map[key]*entry{}
	a.names = map[string]*list.Element{}
	a.nameOrder.Init()
}

// Reset forgets every connection of one flow scope (the host ended or restarted the flow); it visits only that
// scope's entries.
func (a *Assembler) Reset(scope string) {
	for _, e := range a.scopes[scope] {
		a.remove(e)
	}
	a.ForgetServerName(scope)
}

// ForgetServerName forgets one scope's first server name and leaves its CRYPTO entries alone: the host calls it for
// a datagram whose flow it did not admit (a full flow table), whose scope it will therefore never reset, so that
// such orphan names cannot push a live flow's name out of the MaxNames bound (PRO-291).
func (a *Assembler) ForgetServerName(scope string) {
	if element := a.names[scope]; element != nil {
		a.nameOrder.Remove(element)
		delete(a.names, scope)
	}
}

// expire removes every entry idle for more than IdleSeconds (quic.QuicAssembler.expire): the heap's oldest entry
// is the only one that can be next, so it visits only the entries it removes.
func (a *Assembler) expire(now float64) {
	for len(a.idle) > 0 && now-a.idle[0].last > a.IdleSeconds {
		a.remove(a.idle[0])
		a.Counts["expired"]++
	}
}

// Conflicted reports whether this connection carries a conflict marker; the marker binds every later datagram of
// the connection, CRYPTO or not, until reset or expiry. It refreshes the entry's idle time but not its LRU place.
func (a *Assembler) Conflicted(dcid []byte, scope string, version uint32, now *float64) bool {
	e := a.marker(dcid, scope, version, now)
	if e == nil {
		return false
	}
	a.refresh(e, now)
	return true
}

// marker expires idle entries and returns this connection's conflict marker, or nil, without refreshing it: the
// caller first decides whether the datagram may count (PRO-315), then calls refresh.
func (a *Assembler) marker(dcid []byte, scope string, version uint32, now *float64) *entry {
	if now != nil {
		a.expire(*now)
	}
	e := a.entries[key{scope, version, string(dcid)}]
	if e == nil || !e.conflict {
		return nil
	}
	return e
}

// refresh records a datagram that the conflict marker binds as the marker's last-seen time.
func (a *Assembler) refresh(e *entry, now *float64) {
	if now != nil {
		a.touch(e, *now)
	}
}

// SameServerName records the server name of a complete ClientHello of this connection and reports whether it
// agrees with the first complete ClientHello of the same flow scope (SEC-QUIC-3, a Go-only rule; the Python
// reference keeps the flow's first identification). The name lives as long as the flow: Reset(scope) and Clear
// forget it, while eviction, expiry or exhaustion of the scope's connections do not (Codex PRO-290 P2, PRO-291: the
// flow keeps its identification, so its name must stay the comparison base). Beyond MaxNames the least recently
// used name is dropped and counted (NameEvictions); the analyzer sizes MaxNames above its flow table, whose
// every flow end resets both scopes, so a live flow's name is not dropped there. The work is one map lookup and
// O(1) list moves. A disagreement turns this connection into a sticky conflict marker. The empty scope of a bare
// datagram inspector, which holds unrelated datagrams, is never compared.
func (a *Assembler) SameServerName(dcid []byte, scope string, version uint32, hasHost bool, hostname string) bool {
	e := a.entries[key{scope, version, string(dcid)}]
	if scope == "" || e == nil {
		return true
	}
	name := ""
	if hasHost {
		name = "sni:" + hostname
	}
	element := a.names[scope]
	if element == nil {
		if a.nameOrder.Len() >= a.MaxNames && a.nameOrder.Len() > 0 {
			oldest := a.nameOrder.Front()
			delete(a.names, oldest.Value.(*serverName).scope)
			a.nameOrder.Remove(oldest)
			a.NameEvictions++
		}
		a.names[scope] = a.nameOrder.PushBack(&serverName{scope, name})
		return true
	}
	a.nameOrder.MoveToBack(element)
	if element.Value.(*serverName).name == name {
		return true
	}
	e.fragments, e.conflict = nil, true
	a.Counts["conflicts"]++
	return false
}

// Add merges fragments for one connection and returns the status and, when complete, the handshake message.
func (a *Assembler) Add(dcid []byte, fragments []Fragment, scope string, version uint32, now *float64) (string, []byte) {
	if now != nil {
		a.expire(*now)
	}
	k := key{scope, version, string(dcid)}
	e := a.entries[k]
	if e != nil {
		a.order.MoveToBack(e.element) // the reference pops and re-inserts: most recently used
		if now != nil {
			a.touch(e, *now)
		}
	} else {
		if len(a.entries) >= a.MaxConnections {
			a.remove(a.order.Front().Value.(*entry))
			a.Counts["evictions"]++
		}
		e = &entry{key: k}
		if now != nil {
			e.last = *now
		}
		a.insert(e)
	}
	if e.conflict {
		return Conflict, nil
	}
	merged := merge(e.fragments, fragments)
	// Codex PRO-13 P2 (PRO-201), a Go-only ordering: a contradiction with retained bytes is checked before the
	// budget, so an over-budget datagram that also contradicts keeps the sticky marker (and its retraction) rather
	// than silently forgetting the connection. merged is sorted by offset; the work is bounded by the retained
	// MaxFragments plus this datagram's frames.
	if contradicts(merged) {
		e.fragments, e.conflict = nil, true
		a.Counts["conflicts"]++
		return Conflict, nil
	}
	total := 0
	for _, f := range merged {
		total += len(f.Data)
	}
	if len(merged) > MaxFragments || total > MaxCrypto {
		a.Counts["exhausted"]++
		a.remove(e)
		return Exhausted, nil // over budget: this connection is forgotten
	}
	status, data := Assemble(merged)
	if status == Conflict {
		e.fragments, e.conflict = nil, true
		a.Counts["conflicts"]++
	} else {
		e.fragments = merged
	}
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

// contradicts reports whether two fragments of items (sorted by offset) disagree on a shared offset.
func contradicts(items []Fragment) bool {
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
				return true
			}
		}
	}
	return false
}

// Assemble is quic.assemble: every overlapping pair is compared byte for byte before anything is assembled;
// complete returns exactly one handshake message from offset zero.
func Assemble(fragments []Fragment) (string, []byte) {
	items := append([]Fragment{}, fragments...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Offset < items[j].Offset })
	if contradicts(items) {
		return Conflict, nil
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
