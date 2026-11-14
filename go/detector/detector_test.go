package detector

import (
	"crypto/tls"
	"errors"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

func allFamilies() Config {
	c := DefaultConfig()
	c.Families = ProfileFamilies()
	return c
}

func mustEngine(t testing.TB, c Config) *Engine {
	t.Helper()
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustFlow(t testing.TB, e *Engine) *Flow {
	t.Helper()
	f, err := e.NewFlow("flow-1")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var (
	httpRequest  = []byte("GET /index.html HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: lab\r\nAccept: */*\r\n\r\n")
	httpResponse = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
	sshBanner    = []byte("SSH-2.0-OpenSSH_9.6\r\n")
	smtpEHLO     = []byte("EHLO client.example.test\r\n")
	postgres     = []byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}                     // SSLRequest
	http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")                  // selects http2, not ported
	junk         = []byte("\x01\x02\x03\x04\x05 not a protocol prefix at all") // outside every family
)

func TestConfigValidation(t *testing.T) {
	if _, err := New(DefaultConfig()); err != nil {
		t.Fatalf("default config: %v", err)
	}
	bad := map[string]func(*Config){
		"empty profile":      func(c *Config) { c.Families = nil },
		"unknown family":     func(c *Config) { c.Families = []string{"http", "gopher"} },
		"family not offered": func(c *Config) { c.Families = []string{"postgresql"} },
		"duplicate family":   func(c *Config) { c.Families = []string{"tls", "tls"} },
		"zero flows":         func(c *Config) { c.MaxFlows = 0 },
		"too many flows":     func(c *Config) { c.MaxFlows = 1<<20 + 1 },
		"negative panics":    func(c *Config) { c.PanicLimit = -1 },
		"bytes below range":  func(c *Config) { c.MaxBytesPerDirection = 63 },
		"bytes above range":  func(c *Config) { c.MaxBytesPerDirection = 1048577 },
		"zero feeds":         func(c *Config) { c.MaxFeedsPerDirection = 0 },
	}
	for name, mutate := range bad {
		c := DefaultConfig()
		mutate(&c)
		if _, err := New(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
	c := DefaultConfig()
	e := mustEngine(t, c)
	c.Families[0] = "smtp" // the engine copied its profile
	if got := e.Families(); got[0] != "http" {
		t.Fatalf("profile aliased the caller's slice: %v", got)
	}
	got := ProfileFamilies()
	got[0] = "mutated"
	if ProfileFamilies()[0] == "mutated" {
		t.Fatal("ProfileFamilies returned the package slice")
	}
}

func TestVocabulariesAreClosed(t *testing.T) {
	check := func(name string, values []string, valid func(string) bool) {
		seen := map[string]bool{}
		for _, v := range values {
			if v == "" || seen[v] || !valid(v) {
				t.Errorf("%s: bad or duplicate value %q", name, v)
			}
			seen[v] = true
		}
		if valid("not-a-value") {
			t.Errorf("%s accepts a foreign value", name)
		}
	}
	var outcomes, reasons, causes, classes, dirs []string
	for _, v := range AllOutcomes() {
		outcomes = append(outcomes, v.String())
	}
	for _, v := range AllReasons() {
		reasons = append(reasons, v.String())
	}
	for _, v := range AllEndCauses() {
		causes = append(causes, v.String())
	}
	for _, v := range AllEvidenceClasses() {
		classes = append(classes, v.String())
	}
	for _, v := range AllDirections() {
		dirs = append(dirs, v.String())
	}
	check("outcome", outcomes, func(s string) bool { return Outcome(s).Valid() })
	check("reason", reasons, func(s string) bool { return Reason(s).Valid() })
	check("end cause", causes, func(s string) bool { return EndCause(s).Valid() })
	check("evidence class", classes, func(s string) bool { return EvidenceClass(s).Valid() })
	if len(dirs) != 2 || Direction(2).Valid() || Direction(2).String() != "invalid" {
		t.Errorf("directions: %v", dirs)
	}
	// Every engine status maps onto an outcome of the same name.
	for _, st := range []contracts.Status{contracts.Detecting, contracts.Identified, contracts.Unknown, contracts.Malformed,
		contracts.Incomplete, contracts.BudgetExhausted, contracts.Invalidated} {
		if !Outcome(st).Valid() {
			t.Errorf("engine status %q has no outcome", st)
		}
	}
}

type want struct {
	outcome Outcome
	reason  Reason
	family  string
	host    Hostname
}

func observe(t *testing.T, e *Engine, client, server []byte) Snapshot {
	t.Helper()
	f := mustFlow(t, e)
	if client != nil {
		if _, err := f.Feed(ClientToServer, client); err != nil {
			t.Fatal(err)
		}
	}
	if server != nil {
		if _, err := f.Feed(ServerToClient, server); err != nil {
			t.Fatal(err)
		}
	}
	return f.Close()
}

func expect(t *testing.T, label string, got DirectionSnapshot, w want) {
	t.Helper()
	if got.Outcome != w.outcome || got.Reason != w.reason || got.Family != w.family || got.Hostname != w.host || !got.Done {
		t.Errorf("%s %s: got outcome=%s reason=%s family=%q host=%q done=%v detail=%q; want %+v", label, got.Direction,
			got.Outcome, got.Reason, got.Family, got.Hostname, got.Done, got.Detail, w)
	}
}

func TestProfileOutcomes(t *testing.T) {
	e := mustEngine(t, allFamilies())
	ch, sh := tlsFlights(t, "www.example.test", []string{"h2", "http/1.1"}, []tls.CurveID{tls.X25519})
	cases := []struct {
		name           string
		client, server []byte
		c, s           want
	}{
		{"http", httpRequest, httpResponse, want{OutcomeIdentified, ReasonEngine, "http", "www.example.test"}, want{OutcomeIdentified, ReasonEngine, "http", ""}},
		{"tls x25519", ch, sh, want{OutcomeIdentified, ReasonEngine, "tls", "www.example.test"}, want{OutcomeIdentified, ReasonEngine, "tls", ""}},
		{"ssh server first", nil, sshBanner, want{OutcomeIncomplete, ReasonClosed, "", ""}, want{OutcomeIdentified, ReasonEngine, "ssh", ""}},
		{"smtp client", smtpEHLO, nil, want{OutcomeIdentified, ReasonEngine, "smtp", ""}, want{OutcomeIncomplete, ReasonClosed, "", ""}},
		{"postgresql", postgres, nil, want{OutcomeOutsideProfile, ReasonOutsideProfile, "postgresql", ""}, want{OutcomeIncomplete, ReasonClosed, "", ""}},
		{"http2 not ported", http2Preface, nil, want{OutcomeUnsupported, ReasonNotPorted, "", ""}, want{OutcomeIncomplete, ReasonClosed, "", ""}},
		{"junk", junk, nil, want{OutcomeUnknown, ReasonEngine, "", ""}, want{OutcomeIncomplete, ReasonClosed, "", ""}},
	}
	for _, c := range cases {
		s := observe(t, e, c.client, c.server)
		expect(t, c.name, s.Direction(ClientToServer), c.c)
		expect(t, c.name, s.Direction(ServerToClient), c.s)
	}
	// A family outside the profile is never reported as identified, even when the engine identifies it.
	tlsOnly := DefaultConfig()
	tlsOnly.Families = []string{"tls"}
	s := observe(t, mustEngine(t, tlsOnly), httpRequest, sshBanner)
	expect(t, "tls-only profile", s.Direction(ClientToServer), want{OutcomeOutsideProfile, ReasonOutsideProfile, "http", ""})
	expect(t, "tls-only profile", s.Direction(ServerToClient), want{OutcomeOutsideProfile, ReasonOutsideProfile, "ssh", ""})
	if ev := s.Direction(ClientToServer).Evidence; len(ev) != 0 {
		t.Errorf("outside-profile direction kept evidence: %v", ev)
	}
}

// TestPostQuantumServerHelloGap pins a known detection gap (working plan B2 and work item #4): a ServerHello
// selecting the X25519MLKEM768 hybrid group, the default of current clients and of Go's crypto/tls, is
// reported as unknown. The ClientHello side is identified. When #4 lands this test must be inverted.
func TestPostQuantumServerHelloGap(t *testing.T) {
	ch, sh := tlsFlights(t, "pq.example.test", []string{"h2"}, nil)
	s := observe(t, mustEngine(t, allFamilies()), ch, sh)
	expect(t, "pq", s.Direction(ClientToServer), want{OutcomeIdentified, ReasonEngine, "tls", "pq.example.test"})
	srv := s.Direction(ServerToClient)
	if srv.Outcome != OutcomeUnknown || srv.Detail != "Server key share group outside supported profile" {
		t.Fatalf("post-quantum ServerHello: got %s %q; if this now identifies, invert this test with work item #4",
			srv.Outcome, srv.Detail)
	}
}

func TestHostnameEvidenceIsTyped(t *testing.T) {
	e := mustEngine(t, allFamilies())
	ch, _ := tlsFlights(t, "sni.example.test", nil, []tls.CurveID{tls.X25519})
	for label, in := range map[string][]byte{"tls": ch, "http": httpRequest, "smtp": smtpEHLO} {
		s := observe(t, e, in, nil).Direction(ClientToServer)
		hosts := 0
		for _, ev := range s.Evidence {
			if !ev.Class.Valid() {
				t.Errorf("%s: invalid class %q", label, ev.Class)
			}
			if ev.Class == ClassHostname {
				hosts++
				if ev.Value == "" {
					t.Errorf("%s: empty hostname evidence", label)
				}
			}
			if ev.Class == ClassWithheld && ev.Value != "" {
				t.Errorf("%s: withheld evidence kept its value", label)
			}
		}
		if hosts != 1 {
			t.Errorf("%s: %d hostname-class evidence items, want 1: %v", label, hosts, s.Evidence)
		}
	}
}

func TestUnclassifiedEvidenceIsWithheldAndValuesBounded(t *testing.T) {
	e := mustEngine(t, allFamilies())
	f := mustFlow(t, e)
	long := strings.Repeat("é", 300) // 600 bytes
	ds := &f.dirs[ClientToServer]
	f.copyObservation(ds, contracts.Observation{Status: contracts.Identified, Transport: "tcp", Hostname: &long,
		Evidence: []contracts.Evidence{{Field: "socks_target", Value: "10.0.0.1:22", Source: "wire", Strength: "asserted"},
			{Field: "hostname", Value: long, Source: "wire", Strength: "asserted"}}}, 1, "http", ReasonEngine)
	got := ds.snap.Evidence
	if got[0].Class != ClassWithheld || got[0].Value != "" {
		t.Errorf("unclassified field not withheld: %+v", got[0])
	}
	if len(got[1].Value) > MaxEvidenceValue || len(ds.snap.Hostname) > MaxEvidenceValue || !strings.HasPrefix(long, got[1].Value) {
		t.Errorf("value not bounded on a rune boundary: %d bytes", len(got[1].Value))
	}
	many := make([]contracts.Evidence, MaxEvidence+5)
	for i := range many {
		many[i] = contracts.Evidence{Field: "http_method", Value: "GET", Source: "wire", Strength: "structural"}
	}
	f.copyObservation(ds, contracts.Observation{Status: contracts.Identified, Transport: "tcp", Evidence: many}, 2, "http", ReasonEngine)
	if len(ds.snap.Evidence) != MaxEvidence || !ds.snap.EvidenceTruncated {
		t.Errorf("evidence not bounded: %d truncated=%v", len(ds.snap.Evidence), ds.snap.EvidenceTruncated)
	}
}

func feedChunks(t *testing.T, f *Flow, d Direction, data []byte, sizes func() int) {
	t.Helper()
	for len(data) > 0 {
		n := sizes()
		if n > len(data) {
			n = len(data)
		}
		if _, err := f.Feed(d, data[:n]); err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
}

func stable(s DirectionSnapshot) DirectionSnapshot {
	s.BytesFed, s.BytesInspected, s.Revision = 0, 0, 0
	return s
}

func TestFragmentationGivesTheSameResultWithinBudget(t *testing.T) {
	c := allFamilies()
	c.MaxFeedsPerDirection = 100000
	e := mustEngine(t, c)
	ch, _ := tlsFlights(t, "frag.example.test", []string{"h2", "http/1.1"}, nil)
	rng := rand.New(rand.NewSource(20261114))
	for label, input := range map[string][]byte{"tls": ch, "http": httpRequest, "ssh": sshBanner} {
		whole := observe(t, e, input, nil).Direction(ClientToServer)
		if whole.Outcome != OutcomeIdentified {
			t.Fatalf("%s whole: %s %q", label, whole.Outcome, whole.Detail)
		}
		splits := map[string]func() int{"1-byte": func() int { return 1 }, "random": func() int { return 1 + rng.Intn(40) }}
		for name, sizes := range splits {
			f := mustFlow(t, e)
			feedChunks(t, f, ClientToServer, input, sizes)
			got := f.Close().Direction(ClientToServer)
			if !reflect.DeepEqual(stable(got), stable(whole)) {
				t.Errorf("%s %s split differs:\n got %+v\nwant %+v", label, name, got, whole)
			}
		}
	}
}

func TestFeedBudgetIsExplicit(t *testing.T) {
	c := allFamilies()
	c.MaxFeedsPerDirection = 16
	e := mustEngine(t, c)
	ch, _ := tlsFlights(t, "budget.example.test", nil, nil)
	f := mustFlow(t, e)
	feedChunks(t, f, ClientToServer, ch, func() int { return 1 })
	got := f.Snapshot().Direction(ClientToServer)
	if got.Outcome != OutcomeBudgetExhausted || got.Reason != ReasonEngine || !got.Done {
		t.Fatalf("1-byte ClientHello under a 16-call budget: %s %s done=%v", got.Outcome, got.Reason, got.Done)
	}
	if got.BytesFed != len(ch) {
		t.Errorf("BytesFed %d, want %d (bytes after the budget still counted)", got.BytesFed, len(ch))
	}
}

func TestLifecycle(t *testing.T) {
	e := mustEngine(t, allFamilies())
	ch, _ := tlsFlights(t, "life.example.test", nil, nil)

	f := mustFlow(t, e)
	u, err := f.EndDirection(ServerToClient, EndEOF)
	if err != nil || !u.Done || u.Outcome != OutcomeIncomplete {
		t.Fatalf("end before bytes: %+v %v", u, err)
	}
	if s := f.Snapshot().Direction(ServerToClient); s.Reason != ReasonEnded {
		t.Errorf("end before bytes reason %s", s.Reason)
	}
	if u, _ := f.Feed(ClientToServer, ch[:20]); u.Done || u.Outcome != OutcomeDetecting {
		t.Fatalf("partial hello: %+v", u)
	}
	u, _ = f.EndDirection(ClientToServer, EndReset)
	if s := f.Snapshot().Direction(ClientToServer); !u.Done || s.Outcome != OutcomeIncomplete || s.Reason != ReasonEnded ||
		s.Detail != EndReset.sentence() {
		t.Fatalf("end mid-hello: %+v %+v", u, s)
	}
	if u, _ := f.Feed(ClientToServer, ch[20:]); !u.Done || u.Changed {
		t.Errorf("feed after end changed the direction: %+v", u)
	}
	first := f.Close()
	if second := f.Close(); !reflect.DeepEqual(first, second) || !second.Closed {
		t.Error("Close is not idempotent")
	}
	if _, err := f.Feed(ClientToServer, ch); !errors.Is(err, ErrClosed) {
		t.Errorf("feed after close: %v", err)
	}
	if err := f.Expire(); !errors.Is(err, ErrClosed) {
		t.Errorf("expire after close: %v", err)
	}

	// Expiry ends both directions without input and leaves later feeds as no-ops.
	g := mustFlow(t, e)
	g.Feed(ClientToServer, ch[:10])
	if err := g.Expire(); err != nil {
		t.Fatal(err)
	}
	for _, d := range AllDirections() {
		if s := g.Snapshot().Direction(d); s.Outcome != OutcomeIncomplete || s.Reason != ReasonExpired || !s.Done {
			t.Errorf("expire %s: %+v", d, s)
		}
	}
	if u, _ := g.Feed(ClientToServer, ch[10:]); !u.Done || u.Changed {
		t.Errorf("feed after expire: %+v", u)
	}
	g.Close()

	// An identification survives expiry and close.
	h := mustFlow(t, e)
	h.Feed(ClientToServer, httpRequest)
	h.Expire()
	if s := h.Close().Direction(ClientToServer); s.Outcome != OutcomeIdentified || s.Family != "http" {
		t.Errorf("identification lost at expiry: %+v", s)
	}
	if a := e.Stats().Active; a != 0 {
		t.Errorf("active flows after close: %d", a)
	}
	if _, err := f.Feed(Direction(7), nil); !errors.Is(err, ErrDirection) {
		t.Errorf("bad direction: %v", err)
	}
}

func TestEngineStateIsReleasedWhenDone(t *testing.T) {
	e := mustEngine(t, allFamilies())
	f := mustFlow(t, e)
	f.Feed(ClientToServer, httpRequest)
	f.Feed(ServerToClient, junk)
	for _, d := range AllDirections() {
		if f.dirs[d].in != nil {
			t.Errorf("%s: inspector retained after a final outcome", d)
		}
	}
	g := mustFlow(t, e)
	g.Feed(ClientToServer, httpRequest[:5])
	if g.dirs[ClientToServer].in == nil || g.dirs[ServerToClient].in != nil {
		t.Error("inspectors: the fed direction should hold one, the idle direction none")
	}
	g.Close()
	if g.dirs[ClientToServer].in != nil {
		t.Error("Close kept an inspector")
	}
}

func TestAdmission(t *testing.T) {
	c := allFamilies()
	c.MaxFlows = 2
	e := mustEngine(t, c)
	a, _ := e.NewFlow("a")
	b, _ := e.NewFlow("b")
	if _, err := e.NewFlow("c"); !errors.Is(err, ErrAdmission) {
		t.Fatalf("third flow: %v", err)
	}
	a.Close()
	a.Close() // the slot is returned once
	if _, err := e.NewFlow("d"); err != nil {
		t.Fatalf("after close: %v", err)
	}
	if _, err := e.NewFlow("e"); !errors.Is(err, ErrAdmission) {
		t.Fatalf("double close returned two slots: %v", err)
	}
	b.Close()
	st := e.Stats()
	if st.Admitted != 3 || st.Refused != 2 || st.Active != 1 {
		t.Errorf("stats %+v", st)
	}
	long, _ := e.NewFlow(strings.Repeat("x", 1000))
	if len(long.Snapshot().ID) != MaxFlowID {
		t.Errorf("flow id not bounded")
	}
}

func TestPanicIsContainedAndQuarantined(t *testing.T) {
	c := allFamilies()
	c.PanicLimit = 2
	e := mustEngine(t, c)
	for i, op := range []string{"feed", "end", "expire"} {
		e.testHook = func(o string, d Direction) {
			if o == op {
				panic("injected " + string(httpRequest)) // a panic value that quotes input
			}
		}
		f, err := e.NewFlow("p")
		if i == 2 {
			if !errors.Is(err, ErrDisabled) {
				t.Fatalf("breaker did not open after %d panics: %v", c.PanicLimit, err)
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		f.Feed(ClientToServer, httpRequest[:4]) // panics for "feed"
		var opErr error
		switch op {
		case "feed":
			_, opErr = f.Feed(ClientToServer, httpRequest[4:])
		case "end":
			_, opErr = f.EndDirection(ClientToServer, EndEOF)
		}
		if !errors.Is(opErr, ErrQuarantined) {
			t.Errorf("%s: call after panic: %v", op, opErr)
		}
		s := f.Close()
		if !s.Quarantined {
			t.Errorf("%s: flow not quarantined", op)
		}
		for _, ds := range s.Directions {
			if ds.Outcome != OutcomeFailed || ds.Reason != ReasonPanic || ds.Detail != "" || ds.Evidence != nil || !ds.Done {
				t.Errorf("%s: %+v", op, ds)
			}
		}
		if f.dirs[ClientToServer].in != nil {
			t.Errorf("%s: quarantined flow kept its inspector", op)
		}
	}
	st := e.Stats()
	if st.Panics != 2 || !st.Disabled || st.Active != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestSnapshotIsDetachedAndInputIsBorrowed(t *testing.T) {
	e := mustEngine(t, allFamilies())
	ch, _ := tlsFlights(t, "detached.example.test", []string{"h2", "http/1.1"}, nil)
	buf := append([]byte(nil), ch...)
	f := mustFlow(t, e)
	f.Feed(ClientToServer, buf[:100])
	for i := range buf[:100] { // the host reuses its read buffer
		buf[i] = 0
	}
	f.Feed(ClientToServer, ch[100:])
	s := f.Snapshot()
	if got := s.Direction(ClientToServer); got.Outcome != OutcomeIdentified || got.Hostname != "detached.example.test" {
		t.Fatalf("reused input buffer changed the result: %+v", got)
	}
	s.Directions[ClientToServer].Evidence[0].Value = "mutated"
	s.Directions[ClientToServer].OfferedALPN[0] = "mutated"
	again := f.Snapshot().Direction(ClientToServer)
	if again.Evidence[0].Value == "mutated" || again.OfferedALPN[0] == "mutated" {
		t.Error("snapshot shares memory with the flow")
	}
	f.Close()
}

func TestConcurrentDirectionsExpireAndClose(t *testing.T) {
	c := allFamilies()
	c.MaxFeedsPerDirection = 100000
	e := mustEngine(t, c)
	ch, sh := tlsFlights(t, "race.example.test", nil, []tls.CurveID{tls.X25519})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		f, err := e.NewFlow("race")
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(3)
		go func() { defer wg.Done(); feedAll(f, ClientToServer, ch) }()
		go func() { defer wg.Done(); feedAll(f, ServerToClient, sh) }()
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				f.Snapshot()
			}
			if i%2 == 0 {
				f.Expire()
			}
			f.Close()
		}(i)
	}
	wg.Wait()
	if st := e.Stats(); st.Active != 0 || st.Panics != 0 {
		t.Errorf("stats after concurrent use: %+v", st)
	}
}

func feedAll(f *Flow, d Direction, data []byte) {
	for i := 0; i < len(data); i += 7 {
		end := i + 7
		if end > len(data) {
			end = len(data)
		}
		f.Feed(d, data[i:end])
	}
}

func TestModuleIsStandardLibraryOnly(t *testing.T) {
	data, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 && (f[0] == "require" || f[0] == "replace") {
			t.Fatalf("go/go.mod has a %s directive; third-party modules need an ADR (migration/adr/0002): %q", f[0], line)
		}
	}
}
