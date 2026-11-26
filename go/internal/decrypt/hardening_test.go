package decrypt

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// awaitingKeysConnection is one connection stuck in awaiting_keys (PRO-119, SEC-DEC-1): the client sends its
// hello and clientBytes of application records before the server hello arrives (one reassembled delta, so the
// framer frames all of them into the queue), then the server hello and serverBytes of records. No secret is
// ever indexed, so nothing is decrypted.
func awaitingKeysConnection(t testing.TB, keys Keys, clientBytes, serverBytes int) (*Connection, int) {
	random := bytes.Repeat([]byte{0x5a}, 32)
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	sh := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...), 0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	records := func(total int) []byte {
		var out []byte
		for len(out) < total {
			out = append(out, plainRecord(23, bytes.Repeat([]byte{0xee}, 1019))...) // 1 KiB per record
		}
		return out
	}
	client := append(plainRecord(22, handshake(1, hello)), records(clientBytes)...)
	server := append(plainRecord(22, handshake(2, sh)), records(serverBytes)...)
	c := NewConnection(keys, "c", "s")
	c.Feed("c", client)
	c.Advance(64)
	c.Feed("s", server)
	c.Advance(64)
	if c.State != StateAwaitingKeys {
		t.Fatalf("state %s %s", c.State, c.Reason)
	}
	return c, len(client) + len(server)
}

// SEC-DEC-1 (PRO-119): 64 connections waiting for keys hold each fed byte about once. Before the fix the framer
// kept the consumed prefix of every reassembled delta reachable through its tail slice while the queue held a
// second copy of every framed record, so the decoder held about twice what the tier had admitted. The 64 x 2 x 16
// KiB fed here is the 2 MiB of payload the keylogcap tier's 4 MiB aggregate budget admits (it counts each
// retained byte twice), so the decoder side now stays inside that budget as well.
func TestAwaitingKeysConnectionsHoldEachByteOnce(t *testing.T) {
	keys := NewKeyProvider()
	const n = 64
	conns := make([]*Connection, n)
	fed := 0
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range conns {
		c, bytesFed := awaitingKeysConnection(t, keys, 30*1024, 2*1024)
		conns[i], fed = c, fed+bytesFed
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := int(after.HeapAlloc) - int(before.HeapAlloc)
	runtime.KeepAlive(conns)
	t.Logf("64 awaiting_keys connections: %d bytes fed, %d bytes of heap held", fed, held)
	// Each byte once, plus record headers, queue slots and the hello buffers: at most 1.35x what was fed.
	// Without the fix this measured above 2x.
	if limit := fed * 135 / 100; held > limit {
		t.Fatalf("64 awaiting_keys connections hold %d bytes of heap for %d fed (limit %d)", held, fed, limit)
	}
	if held > 4*1024*1024 {
		t.Fatalf("64 awaiting_keys connections hold %d bytes, beyond the tier's 4 MiB aggregate budget", held)
	}
	for _, c := range conns {
		if tail := cap(c.framers[0].pending) + cap(c.framers[1].pending); tail > 0 {
			t.Fatalf("framers retain %d bytes after framing every complete record", tail)
		}
		if c.hellos[0].records != nil || c.hellos[1].records != nil {
			t.Fatal("hello records are kept after negotiation (a second copy of the hellos)")
		}
	}
}

// The framer keeps only the incomplete tail of what it was fed, in a buffer of its own: never the consumed prefix.
func TestFramerCompactsToItsIncompleteTail(t *testing.T) {
	f := &recordFramer{}
	data := append(plainRecord(23, bytes.Repeat([]byte{1}, 4000)), plainRecord(23, bytes.Repeat([]byte{2}, 4000))...)
	data = append(data, 23, 3, 3, 0) // four bytes of the next header (an empty record)
	if err := f.feed(data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, ok, err := f.next(); !ok || err != nil {
			t.Fatalf("record %d: %v %v", i, ok, err)
		}
	}
	if _, ok, _ := f.next(); ok {
		t.Fatal("an incomplete header framed a record")
	}
	f.compact()
	if !bytes.Equal(f.pending, []byte{23, 3, 3, 0}) || cap(f.pending) > 64 {
		t.Fatalf("tail %v (cap %d): the consumed prefix is still reachable", f.pending, cap(f.pending))
	}
	if err := f.feed([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if !f.ready() {
		t.Fatal("a compacted tail plus its last byte is a complete (empty) record")
	}
}

// SEC-DEC-1: a record that was decrypted leaves the queue's backing array, so queued[1:] does not keep processed
// bodies reachable while later records wait.
func TestProcessedRecordsLeaveTheQueue(t *testing.T) {
	s := tls13Session(0x1301)
	keys := NewKeyProvider()
	c := NewConnection(keys, "c", "s")
	c.Feed("c", s.client)
	c.Feed("s", s.server)
	c.Advance(64)
	if c.State != StateAwaitingKeys || len(c.queued[0]) < 3 {
		t.Fatalf("state %s, %d queued", c.State, len(c.queued[0]))
	}
	queue := c.queued[0] // shares the backing array the decoder pops from
	if _, err := keys.Append(s.keylog); err != nil {
		t.Fatal(err)
	}
	c.Advance(2) // one record of each direction
	if queue[0].body != nil || queue[0].header != nil {
		t.Fatal("a processed record is still reachable through the queue's backing array")
	}
	if queue[1].body == nil {
		t.Fatal("an unprocessed record was dropped")
	}
	for c.HasWork() {
		c.Advance(1)
	}
	if c.Finish() != StateComplete {
		t.Fatalf("finish: %s %s", c.State, c.Reason)
	}
}

// SEC-KEY-1 (PRO-119): Expire overwrites a stale secret before forgetting it.
func TestExpireZeroesStaleSecrets(t *testing.T) {
	now, age := 0.0, 5.0
	p := NewKeyProvider()
	p.MaxAge, p.Clock = &age, func() float64 { return now }
	random := bytes.Repeat([]byte{0xab}, 32)
	if _, err := p.Append("CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("01", 48)); err != nil {
		t.Fatal(err)
	}
	now = 3
	if _, err := p.Append("CLIENT_RANDOM " + strings.Repeat("cd", 32) + " " + strings.Repeat("02", 48)); err != nil {
		t.Fatal(err)
	}
	stale, _ := p.Lookup("CLIENT_RANDOM", random)
	fresh, _ := p.Lookup("CLIENT_RANDOM", bytes.Repeat([]byte{0xcd}, 32))
	if len(stale) != 48 || len(fresh) != 48 {
		t.Fatal("secrets not indexed")
	}
	now = 6
	if n := p.Expire(nil); n != 1 || p.Len() != 1 {
		t.Fatalf("expire: %d len %d", n, p.Len())
	}
	if !bytes.Equal(stale, make([]byte, 48)) {
		t.Fatalf("expired secret left in memory: %x", stale)
	}
	if !bytes.Equal(fresh, bytes.Repeat([]byte{2}, 48)) {
		t.Fatal("a live secret was overwritten")
	}
}

// SEC-KEY-1: KeyUpdate overwrites the superseded application traffic secret (a derived copy, never the key
// provider's) before the next generation replaces it; decryption and the epochs are unchanged.
func TestKeyUpdateZeroesTheSupersededSecret(t *testing.T) {
	s := tls13Session(0x1301)
	keys := NewKeyProvider()
	if _, err := keys.Append(s.keylog); err != nil {
		t.Fatal(err)
	}
	c := NewConnection(keys, "c", "s")
	c.Feed("c", s.client)
	c.Feed("s", s.server)
	c.Advance(1)
	client := c.dirs[0].(*tls13Direction)
	generation0 := client.secrets[phaseApplication]
	logged, _ := keys.Lookup("CLIENT_"+phaseApplication, bytes.Repeat([]byte{0x5a}, 32))
	if !bytes.Equal(generation0, logged) {
		t.Fatal("direction does not hold the application secret")
	}
	var epochs []string
	for c.HasWork() {
		for _, d := range c.Advance(1) {
			epochs = append(epochs, d.Endpoint+":"+d.Epoch)
		}
		if client.updates == 1 {
			break
		}
	}
	if client.updates != 1 {
		t.Fatal("KeyUpdate not processed")
	}
	if !bytes.Equal(generation0, make([]byte, len(generation0))) {
		t.Fatalf("superseded traffic secret left in memory: %x", generation0)
	}
	if !bytes.Equal(logged, bytes.Repeat([]byte{3}, 32)) {
		t.Fatal("KeyUpdate wrote the key provider's own secret")
	}
	for c.HasWork() {
		for _, d := range c.Advance(1) {
			epochs = append(epochs, d.Endpoint+":"+d.Epoch)
		}
	}
	if c.Finish() != StateComplete || strings.Join(epochs, ",") != "c:application,c:application+1,s:application" {
		t.Fatalf("%s %s, epochs %v", c.State, c.Reason, epochs)
	}
}
