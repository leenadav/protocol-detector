package quicx

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

func load(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var defaults = Options{MaxHeaders: 64, MaxBytes: 65536, Decrypt: true}

var dcid = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

func fieldsOf(m *Match) map[string]string {
	out := map[string]string{}
	for _, r := range m.Evidence {
		out[r.Field] = r.Value
	}
	return out
}

// The published RFC 9001 Appendix A.2 client Initial opens with the standard library AES-GCM and HKDF.
func TestRFC9001ClientInitialOpens(t *testing.T) {
	m, err := Validate(load(t, "rfc9001_client_initial.hex"), defaults, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	f := fieldsOf(m)
	if !m.HasHost || m.Hostname != "example.com" || len(m.ALPN) != 1 || m.ALPN[0] != "alpn" || m.Retracts {
		t.Fatalf("match %+v", m)
	}
	if f["quic_version"] != "1" || f["packet_type"] != "initial" || f["initial_protection"] != "removed" || f["crypto_assembly"] != "complete" {
		t.Fatalf("evidence %v", f)
	}
	for _, r := range m.Evidence {
		if strings.Contains(r.Value, "8394c8f0") {
			t.Fatal("the connection ID is never emitted")
		}
	}
}

// The test sealer and the validator agree, for both versions (an independent key derivation in testframes).
func TestSealedInitialsOpenForBothVersions(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	for _, version := range []uint32{V1, V2} {
		frame := testframes.CryptoFrames(hello)[0]
		m, err := Validate(testframes.QUICInitial(version, dcid, nil, frame, 2, nil, 1200), defaults, nil, "", nil)
		if err != nil || m.Hostname != "example.com" || fieldsOf(m)["quic_version"] != versionName[version] {
			t.Fatalf("version %x: %+v %v", version, m, err)
		}
	}
}

func TestDisabledDecryptionAndDamagedPackets(t *testing.T) {
	packet := load(t, "rfc9001_client_initial.hex")
	m, _ := Validate(packet, Options{MaxHeaders: 64, MaxBytes: 65536}, nil, "", nil)
	if fieldsOf(m)["initial_protection"] != "skipped" || m.HasHost {
		t.Fatalf("decrypt off: %+v", m)
	}
	damaged := append([]byte{}, packet...)
	damaged[len(damaged)-1] ^= 1
	m, _ = Validate(damaged, defaults, nil, "", nil)
	if fieldsOf(m)["initial_protection"] != "unverified" || m.HasHost {
		t.Fatalf("damaged tag: %+v", m)
	}
	if _, err := Validate(packet[:30], defaults, nil, "", nil); err == nil {
		t.Fatal("a truncated Initial validated")
	}
	if _, err := Validate([]byte("GET / HTTP/1.1"), defaults, nil, "", nil); err == nil {
		t.Fatal("non-QUIC bytes validated")
	}
}

func TestFrameProfile(t *testing.T) {
	cases := []struct {
		frames []byte
		budget bool
		field  string
	}{
		{[]byte{1}, false, "partial"},                        // PING only
		{[]byte{0x08, 0}, false, "unverified"},               // STREAM is not an Initial frame
		{[]byte{6, 0x7f, 0xfc, 10}, true, ""},                // CRYPTO beyond the assembly budget
		{[]byte{6, 0, 0x47, 0xff, 'a'}, false, "unverified"}, // CRYPTO longer than the packet
		{[]byte{0x1c, 0, 0, 0}, false, "partial"},            // CONNECTION_CLOSE
		{[]byte{2, 5, 0, 0x3f, 0}, true, ""},                 // ACK with 63 ranges over a 4-frame budget
		{append(bytes.Repeat([]byte{1}, 5), 0), true, ""},    // frame count over budget
		{[]byte{3, 0, 0, 0, 0, 1, 1, 1}, false, "partial"},   // ACK_ECN
	}
	for i, c := range cases {
		m, err := Validate(testframes.QUICInitial(V1, dcid, nil, c.frames, 2, nil, 1200), Options{MaxHeaders: 4, MaxBytes: 65536, Decrypt: true}, nil, "", nil)
		if c.budget {
			if err == nil || !strings.Contains(err.Error(), "budget") {
				t.Fatalf("case %d: want a budget error, got %v %+v", i, err, m)
			}
			continue
		}
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		f := fieldsOf(m)
		if f["crypto_assembly"] != c.field && f["initial_protection"] != c.field {
			t.Fatalf("case %d: %v", i, f)
		}
	}
}

func split(hello []byte, cut int) (Fragment, Fragment) {
	return Fragment{0, hello[:cut]}, Fragment{uint64(cut), hello[cut:]}
}

func TestAssembleOrderingsDuplicatesAndConflicts(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	first, second := split(hello, 100)
	for _, order := range [][]Fragment{{first, second, first}, {second, first, first}, {first, first, second}} {
		if status, data := Assemble(order); status != Complete || !bytes.Equal(data, hello) {
			t.Fatalf("order: %s", status)
		}
	}
	if s, _ := Assemble([]Fragment{second}); s != Partial {
		t.Fatal(s)
	}
	flipped := make([]byte, 20)
	for i := range flipped {
		flipped[i] = hello[90+i] ^ 1
	}
	conflict := Fragment{90, flipped}
	for _, order := range [][]Fragment{{first, second, conflict}, {conflict, second, first}, {second, conflict, first}} {
		if s, _ := Assemble(order); s != Conflict {
			t.Fatalf("contradictory overlap: %s", s)
		}
	}
	if s, _ := Assemble([]Fragment{{0, []byte("\x01\x00\x00\x04abcd")}, {4, []byte("XXXX")}}); s != Conflict {
		t.Fatal("a complete message followed by a contradicting overlap")
	}
	if s, d := Assemble([]Fragment{{0, []byte("\x01\x00\x00\x04abcd")}, {4, []byte("abcd")}}); s != Complete || string(d) != "\x01\x00\x00\x04abcd" {
		t.Fatal("an agreeing overlap")
	}
}

func TestAssemblerScopesStickyConflictExpiryAndReset(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	first, second := split(hello, 100)
	at := func(v float64) *float64 { return &v }
	a := NewAssembler(4, 10)
	if s, _ := a.Add(dcid, []Fragment{first}, "A", V1, at(0)); s != Partial {
		t.Fatal(s)
	}
	if s, _ := a.Add(dcid, []Fragment{second}, "B", V1, at(0)); s != Partial {
		t.Fatal("fragments of another scope met")
	}
	if s, _ := a.Add(dcid, []Fragment{second}, "A", V2, at(0)); s != Partial {
		t.Fatal("fragments of another version met")
	}
	if s, d := a.Add(dcid, []Fragment{second}, "A", V1, at(1)); s != Complete || !bytes.Equal(d, hello) {
		t.Fatalf("scope A: %s", s)
	}
	// A late contradiction of a complete hello: sticky until reset.
	bad := Fragment{50, bytes.Repeat([]byte{0xee}, 10)}
	if s, _ := a.Add(dcid, []Fragment{bad}, "A", V1, at(2)); s != Conflict || !a.Conflicted(dcid, "A", V1, at(3)) {
		t.Fatal("late contradiction")
	}
	if s, _ := a.Add(dcid, []Fragment{first, second}, "A", V1, at(4)); s != Conflict {
		t.Fatal("the conflict marker did not stick")
	}
	a.Reset("A")
	if a.Conflicted(dcid, "A", V1, at(5)) {
		t.Fatal("reset kept the marker")
	}
	// Idle expiry (strictly beyond IdleSeconds) and LRU eviction at MaxConnections.
	b := NewAssembler(2, 10)
	b.Add(dcid, []Fragment{first}, "A", V1, at(0))
	b.Add(dcid, []Fragment{first}, "B", V1, at(5))
	b.Add(dcid, []Fragment{first}, "C", V1, at(6)) // evicts A, the least recently used
	if b.Counts["evictions"] != 1 || b.Len() != 2 {
		t.Fatalf("counts %v len %d", b.Counts, b.Len())
	}
	b.Conflicted(dcid, "x", V1, at(15)) // B is exactly 10 idle: kept
	if b.Len() != 2 {
		t.Fatal("expired at exactly the idle limit")
	}
	b.Conflicted(dcid, "x", V1, at(15.5))
	if b.Len() != 1 || b.Counts["expired"] != 1 {
		t.Fatalf("expiry: len %d counts %v", b.Len(), b.Counts)
	}
	// Over the fragment budget the connection is forgotten.
	c := NewAssembler(4, 10)
	for i := 0; i < MaxFragments; i++ {
		c.Add(dcid, []Fragment{{uint64(200 + i*2), []byte{byte(i)}}}, "A", V1, nil)
	}
	if s, _ := c.Add(dcid, []Fragment{{400, []byte{1}}}, "A", V1, nil); s != Exhausted || c.Len() != 0 {
		t.Fatalf("exhaustion: %s len %d", s, c.Len())
	}
}

// Reordered Initials assemble across datagrams in one scope; a contradicting retransmission invalidates and a
// later PING-only Initial of the connection stays invalidated (contracts C5/C6).
func TestReorderedAssemblyAndStickyInvalidation(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	frames := testframes.CryptoFrames(hello, 100)
	a := NewAssembler(8, 60)
	at := 1.0
	m, _ := Validate(testframes.QUICInitial(V1, dcid, nil, frames[1], 3, nil, 1200), defaults, a, "c>s", &at)
	if fieldsOf(m)["crypto_assembly"] != "partial" {
		t.Fatalf("second half first: %v", fieldsOf(m))
	}
	m, _ = Validate(testframes.QUICInitial(V1, dcid, nil, frames[0], 2, nil, 1200), defaults, a, "c>s", &at)
	if m.Hostname != "example.com" {
		t.Fatalf("reordered assembly: %+v", m)
	}
	changed := append([]byte{}, hello...)
	changed[150] ^= 0xff
	m, _ = Validate(testframes.QUICInitial(V1, dcid, nil, testframes.CryptoFrames(changed, 100)[1], 4, nil, 1200), defaults, a, "c>s", &at)
	if !m.Retracts || fieldsOf(m)["crypto_assembly"] != "conflict" {
		t.Fatalf("contradiction: %+v", m)
	}
	m, _ = Validate(testframes.QUICInitial(V1, dcid, nil, []byte{1}, 5, nil, 1200), defaults, a, "c>s", &at)
	if !m.Retracts {
		t.Fatal("a PING-only Initial revived the invalidated connection")
	}
	m, _ = Validate(testframes.QUICInitial(V1, dcid, nil, []byte{1}, 5, nil, 1200), defaults, a, "s>c", &at)
	if m.Retracts {
		t.Fatal("the marker leaked into another scope")
	}
}

func FuzzValidateStaysBounded(f *testing.F) {
	f.Add(load(f, "rfc9001_client_initial.hex"), uint8(0))
	f.Add(testframes.QUICInitial(V2, dcid, nil, []byte{6, 0, 4, 1, 0, 0, 9}, 1, []byte("t"), 0), uint8(1))
	f.Add([]byte{0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, scope uint8) {
		a := NewAssembler(4, 5)
		now := float64(scope)
		for i := 0; i < 3; i++ {
			m, err := Validate(data, Options{MaxHeaders: 16, MaxBytes: 4096, Decrypt: true}, a, string(rune('a'+scope%3)), &now)
			if err == nil && m == nil {
				t.Fatal("nil match without an error")
			}
		}
		if a.Len() > 4 {
			t.Fatalf("assembler holds %d connections", a.Len())
		}
	})
}

// With fingerprints the RFC 9001 ClientHello carries the reference's JA4 (protocol code q).
func TestRFC9001JA4(t *testing.T) {
	opts := defaults
	opts.Fingerprints = true
	m, err := Validate(load(t, "rfc9001_client_initial.hex"), opts, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	last := m.Evidence[len(m.Evidence)-1]
	if last.Field != "ja4" || last.Value != "q13d0211an_62ed6f6ca7ad_4d634acda6c0" || last.Source != "wire:quic_client_hello" || last.Strength != "derived" {
		t.Fatalf("%+v", last)
	}
}

// A datagram that both contradicts retained CRYPTO bytes and pushes the connection over its fragment or byte budget
// is a contradiction first (Codex PRO-13 P2, PRO-201): reporting it as exhausted would drop the entry without a
// retraction, so the host could keep the identity the earlier bytes established.
func TestContradictionOutranksExhaustion(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	a := NewAssembler(4, 10)
	for i := 0; i < MaxFragments; i++ {
		if s, _ := a.Add(dcid, []Fragment{{uint64(200 + i*2), []byte{byte(i)}}}, "A", V1, nil); s != Partial {
			t.Fatalf("fragment %d: %s", i, s)
		}
	}
	// Offset 200 held byte 0; this fragment says 9 there and is the ninth fragment.
	if s, _ := a.Add(dcid, []Fragment{{200, []byte{9}}}, "A", V1, nil); s != Conflict {
		t.Fatalf("contradiction over the fragment budget: got %s, want %s", s, Conflict)
	}
	if !a.Conflicted(dcid, "A", V1, nil) || a.Counts["conflicts"] != 1 || a.Counts["exhausted"] != 0 {
		t.Fatalf("conflict marker not kept: len %d counts %v", a.Len(), a.Counts)
	}
	// The byte budget too: a contradicting fragment that also overflows MaxCrypto is a contradiction.
	b := NewAssembler(4, 10)
	b.Add(dcid, []Fragment{{0, []byte{1, 2, 3, 4}}}, "A", V1, nil)
	if s, _ := b.Add(dcid, []Fragment{{0, make([]byte, MaxCrypto)}}, "A", V1, nil); s != Conflict || !b.Conflicted(dcid, "A", V1, nil) {
		t.Fatalf("contradiction over the byte budget: got %s, want %s", s, Conflict)
	}
	// Without a contradiction the budget still forgets the connection.
	c := NewAssembler(4, 10)
	c.Add(dcid, []Fragment{{0, []byte{1, 2, 3, 4}}}, "A", V1, nil)
	big := make([]byte, MaxCrypto)
	copy(big, []byte{1, 2, 3, 4})
	if s, _ := c.Add(dcid, []Fragment{{0, big}}, "A", V1, nil); s != Exhausted || c.Len() != 0 {
		t.Fatalf("exhaustion without contradiction: got %s len %d", s, c.Len())
	}
}

// SEC-QUIC-3: the RFC 9000 section 14.1 minimum is on the client Initial's UDP datagram. 1199 bytes is malformed
// and feeds nothing to the assembler; 1200 identifies; a 300-byte Initial alone is malformed, while the same
// Initial coalesced into a 1200-byte datagram (trailing bytes after its Length) identifies.
func TestClientInitialDatagramMinimum(t *testing.T) {
	frame := testframes.CryptoFrames(load(t, "rfc9001_client_hello.hex"))[0]
	a := NewAssembler(8, 60)
	if _, err := Validate(testframes.QUICInitial(V1, dcid, nil, frame, 2, nil, 1199), defaults, a, "c>s", nil); err == nil ||
		!strings.Contains(err.Error(), "1200 bytes") || a.Len() != 0 {
		t.Fatalf("1199 bytes: err %v, %d assembler entries", err, a.Len())
	}
	if m, err := Validate(testframes.QUICInitial(V1, dcid, nil, frame, 2, nil, 1200), defaults, a, "c>s", nil); err != nil || m.Hostname != "example.com" {
		t.Fatalf("1200 bytes: %+v %v", m, err)
	}
	short := testframes.QUICInitial(V1, dcid, nil, []byte{1}, 2, nil, 300)
	if _, err := Validate(short, defaults, nil, "", nil); err == nil {
		t.Fatal("a 300-byte client Initial alone was accepted")
	}
	coalesced := append(append([]byte{}, short...), make([]byte, 1200-len(short))...)
	if m, err := Validate(coalesced, defaults, nil, "", nil); err != nil || fieldsOf(m)["initial_protection"] != "removed" {
		t.Fatalf("a 300-byte Initial coalesced into 1200 bytes: %+v %v", m, err)
	}
	// Without protection removal nothing says the packet is a client's, and nothing is asserted: unchanged.
	if _, err := Validate(short, Options{MaxHeaders: 64, MaxBytes: 65536}, nil, "", nil); err != nil {
		t.Fatalf("framing-only validation of a short Initial: %v", err)
	}
}

// SEC-QUIC-3: within one flow scope a complete ClientHello naming another server than the scope's first one is a
// sticky conflict on its connection; the same name (a Retry's new DCID) agrees, the bare inspector's empty scope
// is never compared, and resetting the scope forgets the name.
func TestServerNameDisagreementWithinAScope(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	other := append([]byte{}, hello...)
	copy(other[strings.Index(string(hello), "example.com"):], "example.org")
	initial := func(id, h []byte) []byte {
		return testframes.QUICInitial(V1, id, nil, testframes.CryptoFrames(h)[0], 2, nil, 1200)
	}
	second, third := []byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}
	a := NewAssembler(8, 60)
	for _, step := range []struct {
		id, hello []byte
		scope     string
		retracts  bool
	}{
		{dcid, hello, "c>s", false},
		{second, hello, "c>s", false}, // the same ClientHello on a new DCID
		{third, other, "c>s", true},   // another server name
		{third, hello, "c>s", true},   // the conflict marker is sticky
		{third, other, "x>y", false},  // another flow
		{dcid, hello, "", false},      // the bare inspector's scope
		{second, other, "", false},
	} {
		m, err := Validate(initial(step.id, step.hello), defaults, a, step.scope, nil)
		if err != nil || m.Retracts != step.retracts {
			t.Fatalf("%x in %q: %+v %v", step.id, step.scope, m, err)
		}
	}
	a.Reset("c>s")
	if m, _ := Validate(initial(third, other), defaults, a, "c>s", nil); m.Retracts || m.Hostname != "example.org" {
		t.Fatalf("after the reset: %+v", m)
	}
}

// Codex PRO-290 P2 (PRO-291): the first server name of a flow scope lives until the host resets the scope, not
// while the scope happens to hold an assembler entry. Losing the scope's last entry (LRU eviction by the next
// connection, idle expiry, or an over-budget merge) used to forget the name, so a later ClientHello naming another
// server was accepted as the first and the flow's earlier identification was never retracted.
func TestServerNameOutlivesTheScopesLastEntry(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	other := append([]byte{}, hello...)
	copy(other[strings.Index(string(hello), "example.com"):], "example.org")
	initial := func(id, h []byte) []byte {
		return testframes.QUICInitial(V1, id, nil, testframes.CryptoFrames(h)[0], 2, nil, 1200)
	}
	second := []byte{1, 1, 1, 1}
	at := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		name string
		lose func(a *Assembler) // removes the scope's only entry, as each path does
		now  *float64
	}{
		{"eviction", func(*Assembler) {}, nil}, // one slot: inserting the second DCID evicts the first
		{"expiry", func(*Assembler) {}, at(100)},
		{"exhaustion", func(a *Assembler) {
			frames := make([]Fragment, MaxFragments+1)
			for i := range frames {
				frames[i] = Fragment{Offset: uint64(4096 + 2*i), Data: []byte{0}}
			}
			if s, _ := a.Add(dcid, frames, "c>s", V1, nil); s != Exhausted {
				t.Fatalf("exhaustion setup: %s", s)
			}
		}, nil},
	} {
		a := NewAssembler(1, 60)
		if m, err := Validate(initial(dcid, hello), defaults, a, "c>s", at(0)); err != nil || m.Retracts || m.Hostname != "example.com" {
			t.Fatalf("%s: first ClientHello: %+v %v", c.name, m, err)
		}
		c.lose(a)
		m, err := Validate(initial(second, other), defaults, a, "c>s", c.now)
		if err != nil || !m.Retracts || m.Hostname != "" {
			t.Fatalf("%s: a different server name after the scope lost its entry: %+v %v", c.name, m, err)
		}
	}
	// Reset and Clear still forget the name: the host ended the flow.
	a := NewAssembler(1, 60)
	if _, err := Validate(initial(dcid, hello), defaults, a, "c>s", nil); err != nil {
		t.Fatal(err)
	}
	a.Clear()
	if m, _ := Validate(initial(second, other), defaults, a, "c>s", nil); m.Retracts || m.Hostname != "example.org" {
		t.Fatalf("after Clear: %+v", m)
	}
}

// The per-scope names are bounded by MaxNames, least recently used first, and counted when one is dropped.
func TestServerNamesAreBounded(t *testing.T) {
	a := NewAssembler(1, 60)
	a.MaxNames = 2
	for i, scope := range []string{"a", "b", "c"} {
		f := []Fragment{{0, []byte{1}}}
		a.Add([]byte{byte(i)}, f, scope, V1, nil)
		a.SameServerName([]byte{byte(i)}, scope, V1, true, scope+".test")
	}
	if len(a.names) != 2 || a.NameEvictions != 1 {
		t.Fatalf("%d names, %d evictions", len(a.names), a.NameEvictions)
	}
	if _, kept := a.names["a"]; kept {
		t.Fatal("the least recently used name was kept")
	}
}
