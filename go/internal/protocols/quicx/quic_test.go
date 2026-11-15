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
