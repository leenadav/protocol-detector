package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// Security requirements, batch A: precise engine-level checks that each named protection holds.

func securityFeed(t *testing.T, cfg contracts.Config, hint string, chunks ...[]byte) *Inspector {
	t.Helper()
	in, err := New(cfg, hint)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chunks {
		in.Feed(c)
	}
	return in
}

func fastcgiRecord(kind byte, data, padding []byte) []byte {
	out := []byte{1, kind, 0, 1, 0, 0, byte(len(padding)), 0}
	binary.BigEndian.PutUint16(out[4:6], uint16(len(data)))
	return append(append(out, data...), padding...)
}

func fastcgiBegin(padding []byte) []byte {
	return fastcgiRecord(1, []byte{0, 1, 1, 0, 0, 0, 0, 0}, padding)
}

// SR-1: update, byte, line and header budgets end the inspection as budget_exhausted (never as a mismatch or a
// positive result), the byte budget caps the bytes inspected, and a length field that would read past the
// remaining byte budget is refused before any of it is buffered.
func TestSecurityBudgetsEndAsBudgetExhausted(t *testing.T) {
	cfg := contracts.DefaultConfig()
	cfg.MaxUpdates = 2
	if in := securityFeed(t, cfg, "", []byte("G"), []byte("E"), []byte("T")); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("update budget: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	cfg = contracts.DefaultConfig()
	cfg.MaxBytes = 64
	in := securityFeed(t, cfg, "", append([]byte("GET /"), bytes.Repeat([]byte("a"), 100)...))
	if in.Observation.Status != contracts.BudgetExhausted || in.Metrics.BytesInspected != 64 {
		t.Fatalf("byte budget: %s after %d bytes", in.Observation.Status, in.Metrics.BytesInspected)
	}
	cfg = contracts.DefaultConfig()
	cfg.MaxLine = 32
	if in := securityFeed(t, cfg, "", append([]byte("GET /"), bytes.Repeat([]byte("a"), 40)...)); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("line budget: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	cfg = contracts.DefaultConfig()
	cfg.MaxHeaders = 1
	if in := securityFeed(t, cfg, "", []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX: y\r\n\r\n")); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("header budget: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	if in := securityFeed(t, contracts.DefaultConfig(), "", []byte{0x16, 3, 3, 0xff, 0xff}); in.Observation.Status != contracts.Malformed {
		t.Fatalf("oversized TLS record: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	if in := securityFeed(t, contracts.DefaultConfig(), "", []byte{0x16, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff}); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("TLS handshake length past the budget: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	// FastCGI: a 65535-byte params record is refused at its header; an exactly-64-byte message fits 64 bytes.
	huge := append(fastcgiBegin(nil), 1, 4, 0, 1, 0xff, 0xff, 0, 0)
	if in := securityFeed(t, contracts.DefaultConfig(), "", huge); in.Observation.Status != contracts.BudgetExhausted || in.Metrics.BytesInspected > len(huge) {
		t.Fatalf("FastCGI record past the budget: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	cfg = contracts.DefaultConfig()
	cfg.MaxBytes = 64
	exact := append(fastcgiBegin(make([]byte, 40)), fastcgiRecord(4, nil, nil)...)
	if len(exact) != 64 {
		t.Fatalf("fixture is %d bytes", len(exact))
	}
	if in := securityFeed(t, cfg, "", exact); in.Observation.Status != contracts.Identified || in.Observation.ApplicationProtocol == nil || *in.Observation.ApplicationProtocol != "fastcgi/1" {
		t.Fatalf("exact 64-byte FastCGI: %s %q", in.Observation.Status, in.Observation.Reason)
	}
	over := append(fastcgiBegin(make([]byte, 41)), fastcgiRecord(4, nil, nil)...)
	if in := securityFeed(t, cfg, "", over); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("65-byte FastCGI in 64 bytes: %s %q", in.Observation.Status, in.Observation.Reason)
	}
}

var (
	securityCasesOnce sync.Once
	securityCases     *parity.Document
	securityCasesErr  error
)

// securityPayloads returns the committed fixtures (migration/fixtures/cases.json) of one label: a stream case's
// joined chunks or a datagram case's payload, in file order, without duplicates.
func securityPayloads(t *testing.T, kind, label string) [][]byte {
	t.Helper()
	securityCasesOnce.Do(func() {
		securityCases, securityCasesErr = parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	})
	if securityCasesErr != nil {
		t.Fatal(securityCasesErr)
	}
	seen := map[string]bool{}
	var out [][]byte
	for i := range securityCases.Cases {
		c := &securityCases.Cases[i]
		if c.Kind != kind || c.Label != label || c.Hint != nil {
			continue
		}
		var data []byte
		if kind == "datagram" {
			data, _ = hex.DecodeString(c.Payload)
		} else {
			for _, chunk := range c.Chunks {
				b, _ := hex.DecodeString(chunk)
				data = append(data, b...)
			}
		}
		if len(data) > 0 && !seen[string(data)] {
			seen[string(data)] = true
			out = append(out, data)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s fixture labelled %s", kind, label)
	}
	return out
}

var securityDatagramStatuses = map[contracts.Status]bool{contracts.Identified: true, contracts.Unknown: true, contracts.Malformed: true, contracts.BudgetExhausted: true}

// SR-16: seeded random bytes and single-byte mutations of a TLS ClientHello, fed in 7-byte pieces, select at
// most one candidate and never inspect more bytes than were supplied; mutated datagrams and random noise on every
// hint stay within the documented statuses; mutated IKEv2 requests take at most three parser calls, inspect no
// more than the datagram and never name an application or an encryption.
func TestSecurityRandomAndMutatedInputsStayBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(77))
	tls := securityPayloads(t, "stream", "tls")[0]
	var samples [][]byte
	for i := 0; i < 500; i++ {
		data := make([]byte, rng.Intn(1024))
		rng.Read(data)
		samples = append(samples, data)
	}
	for i := 0; i < 200; i++ {
		data := append([]byte{}, tls...)
		data[rng.Intn(len(data))] = byte(rng.Intn(256))
		samples = append(samples, data)
	}
	for _, data := range samples {
		in, err := New(contracts.DefaultConfig(), "")
		if err != nil {
			t.Fatal(err)
		}
		for start := 0; start < len(data); start += 7 {
			in.Feed(data[start:minInt(start+7, len(data))])
		}
		in.End("fin")
		if in.Metrics.CandidatesSelected > 1 || in.Metrics.BytesInspected > len(data) {
			t.Fatalf("%x: %d candidates, %d of %d bytes inspected", data, in.Metrics.CandidatesSelected, in.Metrics.BytesInspected, len(data))
		}
	}
	rng = rand.New(rand.NewSource(51926))
	for _, label := range []string{"dns", "dhcp", "snmp", "stun", "quic", "dtls", "syslog", "coap", "tftp", "wireguard", "ikev2", "sip"} {
		for _, base := range securityPayloads(t, "datagram", label)[:1] {
			d, _ := NewDatagram(contracts.DefaultConfig())
			for i := 0; i < 300; i++ {
				changed := append([]byte{}, base...)
				changed[rng.Intn(len(changed))] = byte(rng.Intn(256))
				obs, err := d.Inspect(changed, "")
				if err == nil && !securityDatagramStatuses[obs.Status] {
					t.Fatalf("%s mutation %x: status %s", label, changed, obs.Status)
				}
			}
		}
	}
	hints := []string{""}
	for hint := range DatagramHints {
		hints = append(hints, hint)
	}
	for size := 0; size < 300; size++ {
		data := make([]byte, size)
		rng.Read(data)
		for _, hint := range hints {
			d, _ := NewDatagram(contracts.DefaultConfig())
			if obs, err := d.Inspect(data, hint); err == nil && !securityDatagramStatuses[obs.Status] {
				t.Fatalf("noise %x hint %q: status %s", data, hint, obs.Status)
			}
		}
	}
	rng = rand.New(rand.NewSource(7296))
	request := securityPayloads(t, "datagram", "ikev2")[0]
	for i := 0; i < 3000; i++ {
		data := append([]byte{}, request...)
		for n := 1 + rng.Intn(4); n > 0; n-- {
			data[rng.Intn(len(data))] = byte(rng.Intn(256))
		}
		d, _ := NewDatagram(contracts.DefaultConfig())
		obs, err := d.Inspect(data, "")
		if err != nil {
			continue
		}
		if !securityDatagramStatuses[obs.Status] || d.Metrics.ParserCalls > 3 || d.Metrics.BytesInspected > len(data) || obs.Application != nil || obs.Encryption != nil {
			t.Fatalf("IKEv2 mutation %x: %s, %d parser calls, %d of %d bytes, application %v encryption %v", data, obs.Status, d.Metrics.ParserCalls, d.Metrics.BytesInspected, len(data), obs.Application, obs.Encryption)
		}
	}
}

func securityHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func securityEvidence(o contracts.Observation, field string) (contracts.Evidence, bool) {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e, true
		}
	}
	return contracts.Evidence{}, false
}

// securityClientHello is a minimal TLS 1.2 ClientHello record the TLS parser identifies.
var securityClientHello = func() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}()

const securityTLSServer13 = "160303005a020000560303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00130100002e002b0002030400330024001d00200000000000000000000000000000000000000000000000000000000000000000"

// SR-35: a host-opened shift is accepted only on a terminal identified direction that has not shifted, with at
// least 64 bytes of budget left, and only once; the shift marker it adds is peer-derived (source wire:peer) and
// the carrier identification stays (no retraction, the carrier protocol is still reported).
func TestSecurityHostOpenedShiftPreconditions(t *testing.T) {
	connectRequest := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n")
	connectResponse := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	cfg := contracts.DefaultConfig()
	if in := securityFeed(t, cfg, "", connectResponse[:len(connectResponse)-2]); in.OpenShift("http-connect", "") {
		t.Fatal("a detecting direction opened a shift")
	}
	in := securityFeed(t, cfg, "", connectResponse)
	if !in.OpenShift("http-connect", "") {
		t.Fatalf("a terminal identified direction refused: %+v", in.Observation)
	}
	if in.OpenShift("http-connect", "") {
		t.Fatal("a second shift opened while one is pending")
	}
	events := in.Feed(securityHex(t, securityTLSServer13))
	if len(events) != 1 || events[0].Kind != contracts.Shifted || in.Observation.Encryption == nil || *in.Observation.Encryption != "tls" {
		t.Fatalf("tunnel bytes: %+v", events)
	}
	if marker, ok := securityEvidence(in.Observation, "shift"); !ok || marker.Value != "http-connect" || marker.Source != "wire:peer" {
		t.Fatalf("shift marker %+v (want peer-derived)", marker)
	}
	if from, ok := securityEvidence(in.Observation, "shift_from"); !ok || from.Value != "http/1.1" || from.Source != "wire" {
		t.Fatalf("carrier %+v", from)
	}
	if a := in.Announcement; in.Observation.Status != contracts.Identified || a == nil || a.Status != contracts.Identified || a.ApplicationProtocol == nil || *a.ApplicationProtocol != "http/1.1" {
		t.Fatalf("the carrier identification was not kept: %+v announcement %+v", in.Observation, in.Announcement)
	}
	if in.OpenShift("http-connect", "") {
		t.Fatal("a shift opened after the direction shifted")
	}
	if more := in.Feed([]byte("more")); len(more) != 0 {
		t.Fatalf("bytes after the tunnel phase: %+v", more)
	}
	if in := securityFeed(t, cfg, "", append(append([]byte{}, connectRequest...), securityClientHello...)); in.OpenShift("http-connect", "") {
		t.Fatal("a direction that shifted by itself opened a host shift")
	}
	if in := securityFeed(t, cfg, "", append([]byte{0xfa, 0xfb}, make([]byte, 30)...)); in.OpenShift("http-connect", "") {
		t.Fatal("an unknown direction opened a shift")
	}
	tight := contracts.DefaultConfig()
	tight.MaxBytes = 64
	if in := securityFeed(t, tight, "", connectResponse); in.OpenShift("http-connect", "") {
		t.Fatal("a shift opened with fewer than 64 bytes of budget left")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("an empty boundary was accepted")
			}
		}()
		securityFeed(t, cfg, "", connectResponse).OpenShift("", "")
	}()
	restricted := securityFeed(t, cfg, "", connectResponse)
	if !restricted.OpenShift("http-connect", "tls") {
		t.Fatal("restricted shift refused")
	}
	for _, e := range append(restricted.Feed([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), restricted.End("fin")...) {
		if e.Kind == contracts.Retracted {
			t.Fatalf("the carrier was retracted: %+v", e)
		}
	}
	payload, _ := securityEvidence(restricted.Observation, "shifted_payload")
	if restricted.Observation.ApplicationProtocol == nil || *restricted.Observation.ApplicationProtocol != "http/1.1" || (payload.Value != "unknown" && payload.Value != "malformed") {
		t.Fatalf("an HTTP request inside a tls-restricted tunnel: %+v", restricted.Observation)
	}
}

// securityFixture is one committed case input with the reference's expected output text.
type securityFixture struct {
	id, kind, hint string
	data           []byte
	expected       string
}

func securityFixtures(t *testing.T, labels ...string) []securityFixture {
	t.Helper()
	securityPayloads(t, "stream", "tls") // loads the document
	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}
	seen := map[string]bool{}
	var out []securityFixture
	for i := range securityCases.Cases {
		c := &securityCases.Cases[i]
		family := c.Label
		if j := strings.IndexByte(family, '/'); j >= 0 {
			family = family[:j]
		}
		if !want[family] || (c.Kind != "stream" && c.Kind != "datagram") {
			continue
		}
		if o := c.Config; o.Fingerprints || o.Certificates || o.Continuation > 0 || o.Heuristics || o.RetainContexts {
			continue
		}
		f := securityFixture{id: c.ID, kind: c.Kind, expected: string(c.Expected)}
		if c.Hint != nil {
			f.hint = *c.Hint
		}
		if c.Kind == "datagram" {
			f.data, _ = hex.DecodeString(c.Payload)
		} else {
			for _, chunk := range c.Chunks {
				b, _ := hex.DecodeString(chunk)
				f.data = append(f.data, b...)
			}
		}
		key := f.kind + "|" + f.hint + "|" + string(f.data)
		if len(f.data) == 0 || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatalf("no fixtures for %v", labels)
	}
	return out
}

// securityRuns is every run of at least six printable, non-space ASCII bytes in data.
func securityRuns(data []byte) []string {
	var out []string
	start := -1
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] > 0x20 && data[i] < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 6 {
			out = append(out, string(data[start:i]))
		}
		start = -1
	}
	return out
}

var securityStatuses = map[contracts.Status]bool{contracts.Identified: true, contracts.Unknown: true, contracts.Malformed: true,
	contracts.Detecting: true, contracts.BudgetExhausted: true, contracts.Incomplete: true}

// securityInspect runs one input through the stream or datagram inspector and returns the final observation and
// the bytes inspected; ok is false when the Go backend reports the input as not ported.
func securityInspect(t *testing.T, kind, hint string, data []byte) (contracts.Observation, int, bool) {
	t.Helper()
	if kind == "datagram" {
		d, err := NewDatagram(contracts.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		obs, err := d.Inspect(data, hint)
		return obs, d.Metrics.BytesInspected, err == nil
	}
	in, err := New(contracts.DefaultConfig(), hint)
	if err != nil {
		t.Fatal(err)
	}
	in.Feed(data)
	in.End("fin")
	return in.Observation, in.Metrics.BytesInspected, in.NotPorted == nil
}

// securityDestinationFields are the documented destination names a client request is identified by (the TLS
// or HTTP server name, the SOCKS request target); they are emitted by design and exempt from the leak check.
var securityDestinationFields = map[string]bool{"hostname": true, "socks_target": true}

// securityLeak names an input string that the observation emits (in an evidence value other than a destination name,
// the reason or the application) although the reference never emitted it for any fixture of the family.
func securityLeak(obs contracts.Observation, data []byte, approved string) string {
	var emitted []string
	for _, e := range obs.Evidence {
		if !securityDestinationFields[e.Field] {
			emitted = append(emitted, e.Value)
		}
	}
	emitted = append(emitted, obs.Reason)
	if obs.Application != nil {
		emitted = append(emitted, *obs.Application)
	}
	for _, run := range securityRuns(data) {
		for _, text := range emitted {
			for k := 0; k+6 <= len(run); k++ {
				piece := run[k : k+6]
				if strings.Contains(text, piece) && !strings.Contains(approved, piece) {
					return piece + " in " + text
				}
			}
		}
	}
	return ""
}

// securitySources is the text of the engine's and the protocol parsers' non-test Go sources.
func securitySources(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	for _, root := range []string{".", "../protocols"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && path != root && (d.Name() == "testdata" || root == ".") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				text, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				out.Write(text)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if out.Len() < 100000 {
		t.Fatalf("only %d bytes of parser sources", out.Len())
	}
	return out.String()
}

// securityMutationsStayClosed feeds every committed fixture of the families, unmodified and with seeded 1-2 byte
// mutations, and checks that each ends in a documented status, inspects no more bytes than it was given, and
// emits no input string outside the family's reference vocabulary (no URL, reason, user, value or name).
func securityMutationsStayClosed(t *testing.T, seed int64, rounds int, labels ...string) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	fixtures := securityFixtures(t, labels...)
	// The closed vocabulary: everything the reference emitted for any fixture of the family, and the fixed text
	// compiled into the engine and its parsers (labels and reasons), which no input byte can extend.
	var vocabulary strings.Builder
	for _, f := range fixtures {
		vocabulary.WriteString(f.expected)
	}
	vocabulary.WriteString(securitySources(t))
	approved := vocabulary.String()
	for _, f := range fixtures {
		for i := 0; i <= rounds; i++ {
			data := append([]byte{}, f.data...)
			if i > 0 {
				for n := 1 + rng.Intn(2); n > 0; n-- {
					data[rng.Intn(len(data))] = byte(rng.Intn(256))
				}
			}
			obs, inspected, ok := securityInspect(t, f.kind, f.hint, data)
			if !ok {
				continue
			}
			if !securityStatuses[obs.Status] || inspected > len(data) {
				t.Fatalf("%s mutated to %x: status %s, %d of %d bytes", f.id, data, obs.Status, inspected, len(data))
			}
			if leak := securityLeak(obs, data, approved); leak != "" {
				t.Fatalf("%s mutated to %x leaks %q: %+v", f.id, data, leak, obs)
			}
		}
	}
}

// SR-40: OPC UA and SOCKS5 fixtures, whole and mutated, stay within the documented statuses and the bytes they
// supplied, and never emit an endpoint URL, server URI, error reason or bound address.
func TestSecurityOPCUAAndSOCKS5MutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 41, 300, "opcua", "socks5")
}

func securityLE32(values ...uint32) []byte {
	out := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}

func securityOPCUA(kind string, body []byte) []byte {
	return append(append([]byte(kind+"F"), securityLE32(uint32(8+len(body)))...), body...)
}

func securityOPCUAString(s []byte) []byte {
	if s == nil {
		return securityLE32(0xffffffff)
	}
	return append(securityLE32(uint32(len(s))), s...)
}

func securityOPCUAHello(receive, send uint32, url []byte) []byte {
	return securityOPCUA("HEL", append(securityLE32(0, receive, send, 0, 0), securityOPCUAString(url)...))
}

func securityIdentified(t *testing.T, hint string, data []byte) contracts.Observation {
	t.Helper()
	obs, _, _ := securityInspect(t, "stream", hint, data)
	return obs
}

// SR-40: OPC UA server and client messages identify only with exact field coverage, buffer minimums, the
// opc.tcp scheme and printable strings of at most 4096 bytes; SOCKS5 server replies only with a valid reply
// header and bound address, and the shared 05 00 prefix routes only on the complete six-byte discriminator.
func TestSecurityOPCUAAndSOCKS5ServerRejections(t *testing.T) {
	url := []byte("opc.tcp://placeholder:4840/UA/Server")
	good := securityOPCUAHello(65536, 65536, url)
	if obs := securityIdentified(t, "", good); obs.Status != contracts.Identified {
		t.Fatalf("the reference Hello: %+v", obs)
	}
	long := append([]byte("opc.tcp://"), bytes.Repeat([]byte("x"), 4087)...)
	rejected := [][]byte{
		securityOPCUAHello(8191, 65536, url), securityOPCUAHello(65536, 4096, url),
		securityOPCUAHello(65536, 65536, []byte("http://placeholder")),
		securityOPCUAHello(65536, 65536, []byte("opc.tcp://pl\x01ce")),
		securityOPCUAHello(65536, 65536, nil),
		securityOPCUAHello(65536, 65536, long),
		append(append([]byte{}, good[:len(good)-1]...), 0, 0),
		append(append(append([]byte{}, good[:4]...), 7, 0, 0, 0), good[8:]...),
		append(append(append([]byte{}, good[:3]...), 'C'), good[4:]...),
		securityOPCUA("ACK", append(securityLE32(0, 65536, 65536, 0, 0), 0)),
		securityOPCUA("ERR", append(securityLE32(0), securityOPCUAString([]byte("ok"))...)),
		securityOPCUA("ERR", securityLE32(0x80020000)),
		securityOPCUA("RHE", append(securityOPCUAString([]byte("urn:x")), securityOPCUAString([]byte("tcp://x"))...)),
		securityOPCUA("OPN", make([]byte, 20)),
	}
	for _, data := range rejected {
		for _, hint := range []string{"", "opcua"} {
			if obs := securityIdentified(t, hint, data); obs.Status == contracts.Identified {
				t.Fatalf("OPC UA %x (hint %q) identified: %+v", data[:16], hint, obs)
			}
		}
	}
	server := func(method, version, reply, reserved, atyp byte, address []byte) []byte {
		return append(append([]byte{5, method, version, reply, reserved, atyp}, address...), 4, 0x38)
	}
	if obs := securityIdentified(t, "", server(0, 5, 0, 0, 1, []byte{10, 0, 0, 1})); obs.Status != contracts.Identified {
		t.Fatalf("the reference SOCKS5 reply: %+v", obs)
	}
	for _, data := range [][]byte{server(0, 4, 0, 0, 1, []byte{10, 0, 0, 1}), server(0, 5, 9, 0, 1, []byte{10, 0, 0, 1}),
		server(0, 5, 0, 1, 1, []byte{10, 0, 0, 1}), server(0, 5, 0, 0, 2, []byte{10, 0, 0, 1}), server(0, 5, 0, 0, 3, []byte{0}),
		server(0, 5, 0, 0, 3, []byte("\x03a b")), server(1, 5, 0, 0, 1, []byte{10, 0, 0, 1}), {5, 0xff}} {
		if obs := securityIdentified(t, "", data); obs.Status == contracts.Identified && obs.Scope == "negotiation_response" {
			t.Fatalf("SOCKS5 reply %x identified: %+v", data, obs)
		}
	}
	if got := Select([]byte{5, 0, 5, 0, 0}); got != Wait {
		t.Fatalf("a five-byte 05 00 prefix routed to %q", got)
	}
	if got := Select([]byte{5, 0, 5, 0, 0, 2}); got != "dcerpc" {
		t.Fatalf("05 00 05 00 00 02 routed to %q", got)
	}
	if got := Select(server(0, 5, 0, 0, 1, []byte{10, 0, 0, 1})[:6]); got != "socks5" {
		t.Fatalf("the SOCKS5 reply prefix routed to %q", got)
	}
}

// SR-44: PostgreSQL, LDAP and CQL server replies and MySQL handshakes, whole and mutated, stay within the
// documented statuses and bytes and emit no salt, SASL data, message text, DN, option value, user, database or
// attribute bytes.
func TestSecurityDatabaseRepliesMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 45, 250, "postgresql", "ldap", "cql", "mysql")
}

// SR-51: X11, SPICE, DSI (AFP), FINS, RIP and RTCP fixtures, whole and mutated, stay within the documented
// statuses and bytes and emit no cookie, vendor string, public key, node number, RIP password or report content.
func TestSecurityDesktopStorageMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 51, 250, "x11", "x11-server", "spice", "afp", "fins", "rip", "rtcp")
}

// SR-53: mDNS, NetBIOS name service and LLMNR fixtures, whole and mutated, stay within the documented statuses
// and bytes and emit no service name, host name, address, TXT data or node status.
func TestSecurityLocalNameServicesMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 55, 250, "mdns", "netbios-ns", "llmnr")
}

// SR-47: TFTP, L2TP, PPTP, memcached, git and FastCGI messages and the DHCP, NTP, MongoDB and WireGuard
// direction fixtures, whole and mutated, stay within the documented statuses and bytes and emit no option
// value, key, error text, refname, capability, object id or record content.
func TestSecurityMoreRepliesMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 47, 200, "tftp", "l2tp", "pptp", "memcached", "git", "fastcgi", "dhcp", "ntp", "mongodb", "wireguard")
}

// SR-37 and SR-42: SNMP (v1, v2c and v3) and DNS fixtures, whole and mutated, stay within the documented statuses
// and bytes and emit no value, OID, community, user name, engine identifier, agent address or name.
func TestSecuritySNMPAndDNSMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 42, 250, "snmp", "dns")
}

// SR-57 and SR-59: SMB2, TDS, PostgreSQL and MySQL fixtures, whole and mutated, stay within the documented
// statuses and bytes and emit no NETNAME, parameter, user, database or credential byte.
func TestSecurityTransportPostureMutationsNeverLeak(t *testing.T) {
	securityMutationsStayClosed(t, 59, 150, "smb2", "tds", "postgresql", "mysql")
}

type securityMySQL struct {
	capabilities   uint32
	user, database []byte
	attrs          int
	trailing       bool
}

func (m securityMySQL) build() []byte {
	caps := m.capabilities
	if caps == 0 {
		caps = 0x3fa20f
	}
	user := m.user
	if user == nil {
		user = []byte("placeholder")
	}
	p := append(securityLE32(caps, 0x1000000), 0xff)
	p = append(append(append(p, make([]byte, 23)...), user...), 0)
	p = append(append(p, 32), make([]byte, 32)...)
	if caps&0x8 != 0 {
		db := m.database
		if db == nil {
			db = []byte("placeholderdb")
		}
		p = append(append(p, db...), 0)
	}
	if caps&0x80000 != 0 {
		p = append(append(p, "caching_sha2_password"...), 0)
	}
	if caps&0x100000 != 0 {
		var block []byte
		if m.attrs == 0 {
			block = []byte("\x0c_client_name\x08libmysql")
		}
		for i := 0; i < m.attrs; i++ {
			block = append(block, 1, 'k', 1, 'v')
		}
		p = append(append(p, byte(len(block))), block...)
	}
	size := len(p)
	if m.trailing {
		p = append(p, 0)
		size = len(p)
	}
	return append([]byte{byte(size), byte(size >> 8), byte(size >> 16), 1}, p...)
}

// SR-44: a MySQL HandshakeResponse41 identifies only when it is complete and exactly covered: no trailing byte in
// the packet, a user of at most 128 bytes, a database of at most 64, at most 32 attribute strings, and
// CLIENT_PROTOCOL_41 without CLIENT_SSL; it reports the plugin label only.
func TestSecurityMySQLHandshakeResponseExactCoverage(t *testing.T) {
	good := securityIdentified(t, "mysql", securityMySQL{}.build())
	if good.Status != contracts.Identified || good.Scope != "authentication_request" {
		t.Fatalf("the reference HandshakeResponse41: %+v", good)
	}
	if plugin, _ := securityEvidence(good, "mysql_auth_plugin"); plugin.Value != "caching_sha2_password" {
		t.Fatalf("plugin label %+v", plugin)
	}
	if ok := securityIdentified(t, "mysql", securityMySQL{attrs: 16}.build()); ok.Status != contracts.Identified {
		t.Fatalf("16 attribute pairs: %+v", ok)
	}
	whole := securityMySQL{}.build()
	for name, data := range map[string][]byte{
		"protocol 41 missing": securityMySQL{capabilities: 0x0fa00f}.build(),
		"ssl without request": securityMySQL{capabilities: 0x3faa0f}.build(),
		"user too long":       securityMySQL{user: bytes.Repeat([]byte("u"), 129)}.build(),
		"database too long":   securityMySQL{database: bytes.Repeat([]byte("d"), 65)}.build(),
		"attribute budget":    securityMySQL{attrs: 33}.build(),
		"trailing byte":       securityMySQL{trailing: true}.build(),
		"truncated":           append(append([]byte{byte(len(whole) - 5)}, whole[1:4]...), whole[4:len(whole)-1]...),
	} {
		if obs := securityIdentified(t, "mysql", data); obs.Status == contracts.Identified {
			t.Fatalf("%s identified: %+v", name, obs)
		}
	}
}

func securityPG(kind byte, body []byte) []byte {
	out := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(body)))
	return append(out, body...)
}

func securityBE32(v uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
}

// SR-44: PostgreSQL server messages identify only when complete and exactly covered (an MD5 salt of exactly four
// bytes, no data on fixed methods, a terminated upper-case SASL list, error fields with a valid severity and a
// five-character SQLSTATE, no repeated field); the evidence names the method and the SQLSTATE class only.
func TestSecurityPostgreSQLServerExactCoverage(t *testing.T) {
	salt := []byte{0x9a, 0x7b, 0xc3, 0x11}
	md5 := securityIdentified(t, "", securityPG('R', append(securityBE32(5), salt...)))
	if auth, _ := securityEvidence(md5, "postgresql_auth"); md5.Status != contracts.Identified || auth.Value != "md5-password" {
		t.Fatalf("MD5 request: %+v", md5)
	}
	for _, e := range append(md5.Evidence, contracts.Evidence{Value: md5.Reason}) {
		if strings.Contains(e.Value, string(salt)) || strings.Contains(e.Value, hex.EncodeToString(salt)) {
			t.Fatalf("salt emitted: %+v", md5)
		}
	}
	errorReply := securityIdentified(t, "", securityPG('E', []byte("SFATAL\x00C28P01\x00Mpassword authentication failed for user placeholder\x00\x00")))
	if class, _ := securityEvidence(errorReply, "postgresql_error_class"); errorReply.Status != contracts.Identified || class.Value != "28" {
		t.Fatalf("error reply: %+v", errorReply)
	}
	if strings.Contains(fmt.Sprint(errorReply), "placeholder") || strings.Contains(fmt.Sprint(errorReply), "28P01") {
		t.Fatalf("error text or full SQLSTATE emitted: %+v", errorReply)
	}
	for name, data := range map[string][]byte{
		"crypt":              securityPG('R', securityBE32(4)),
		"unknown method":     securityPG('R', securityBE32(13)),
		"ok with data":       securityPG('R', append(securityBE32(0), 'x')),
		"three-byte salt":    securityPG('R', append(securityBE32(5), "abc"...)),
		"five-byte salt":     securityPG('R', append(securityBE32(5), "abcde"...)),
		"unterminated list":  securityPG('R', append(securityBE32(10), "SCRAM-SHA-256\x00"...)),
		"lower-case":         securityPG('R', append(securityBE32(10), "scram\x00\x00"...)),
		"empty continuation": securityPG('R', securityBE32(8)),
		"no method":          securityPG('R', nil),
		"unterminated error": securityPG('E', []byte("SFATAL\x00")),
		"notice severity":    securityPG('E', []byte("SNOTICE\x00C28P01\x00\x00")),
		"short sqlstate":     securityPG('E', []byte("SFATAL\x00C28P\x00\x00")),
		"repeated field":     securityPG('E', []byte("SFATAL\x00SFATAL\x00C28P01\x00\x00")),
		"empty error":        securityPG('E', []byte{0}),
	} {
		if obs := securityIdentified(t, "", data); obs.Status == contracts.Identified {
			t.Fatalf("%s identified: %+v", name, obs)
		}
	}
}

func securityCQL(opcode byte, body []byte) []byte {
	out := []byte{0x84, 0, 0, 0, opcode, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[5:], uint32(len(body)))
	return append(out, body...)
}

// SR-44: a CQL SUPPORTED or AUTHENTICATE response identifies only when its strings exactly cover the body, and
// reports the response kind without the option values or the authenticator class.
func TestSecurityCQLResponsesExactCoverage(t *testing.T) {
	var supported []byte
	supported = append(supported, 0, 1, 0, 11)
	supported = append(supported, "CQL_VERSION"...)
	supported = append(supported, 0, 1, 0, 17)
	supported = append(supported, "placeholder-3.4.5"...)
	obs := securityIdentified(t, "", securityCQL(6, supported))
	if kind, _ := securityEvidence(obs, "cql_response"); obs.Status != contracts.Identified || kind.Value == "" {
		t.Fatalf("SUPPORTED: %+v", obs)
	}
	authenticate := append([]byte{0, 22}, "org.placeholder.Authen"...)
	obs2 := securityIdentified(t, "", securityCQL(3, authenticate))
	if obs2.Status != contracts.Identified {
		t.Fatalf("AUTHENTICATE: %+v", obs2)
	}
	for _, o := range []contracts.Observation{obs, obs2} {
		if strings.Contains(fmt.Sprintf("%+v", o), "placeholder") {
			t.Fatalf("an option value or authenticator class is emitted: %+v", o)
		}
	}
	for name, data := range map[string][]byte{
		"SUPPORTED trailing byte":    securityCQL(6, append(append([]byte{}, supported...), 0)),
		"AUTHENTICATE trailing byte": securityCQL(3, append(append([]byte{}, authenticate...), 0)),
		"SUPPORTED zero count":       securityCQL(6, []byte{0, 0}),
	} {
		if o := securityIdentified(t, "", data); o.Status == contracts.Identified {
			t.Fatalf("%s identified: %+v", name, o)
		}
	}
}

// securityAllRisks is the flow risks the session verdict derives for one direction on a TCP server port.
func securityAllRisks(t *testing.T, o contracts.Observation, port int) []string {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return appid.SessionVerdict(pack, &o, nil, "tcp", port, true, appid.Bytes{N: 100, Known: true}, appid.Bytes{}, true).Risks
}

// securityRisks is the database transport risks among them.
func securityRisks(t *testing.T, o contracts.Observation, port int) []string {
	t.Helper()
	var out []string
	for _, r := range securityAllRisks(t, o, port) {
		if strings.HasPrefix(r, "database-") {
			out = append(out, r)
		}
	}
	return out
}

func securityValues(o contracts.Observation, field string) []string {
	var out []string
	for _, e := range o.Evidence {
		if e.Field == field {
			out = append(out, e.Value)
		}
	}
	return out
}

// securityDecrypted feeds data to an inspector whose evidence carries the decrypted provenance.
func securityDecrypted(t *testing.T, hint string, data []byte) contracts.Observation {
	t.Helper()
	in, err := New(contracts.DefaultConfig(), hint)
	if err != nil {
		t.Fatal(err)
	}
	in.source, in.shiftSource = "decrypted", "decrypted"
	in.Feed(data)
	return in.Observation
}

// SR-59: the TDS session-encryption label comes from a PRELOGIN response's ENCRYPTION value alone (a client's
// offer yields no label and no risk), the PostgreSQL startup marker from a validated StartupMessage (not from an
// SSLRequest), the MySQL risks from the greeting and HandshakeResponse41 rows, and the seen-in-the-clear risks
// read wire rows only: the same messages with decrypted provenance raise no seen-in-the-clear risk.
func TestSecurityDatabaseTransportProtection(t *testing.T) {
	tds := func(kind byte, value byte) []byte {
		return securityHex(t, fmt.Sprintf("%02x01001a0000010000000b00060100110001ff%s%02x", kind, map[byte]string{4: "100007d00000", 0x12: "000000000000"}[kind], value))
	}
	labels := map[byte]string{0: "login-only", 1: "full", 2: "none", 3: "full"}
	risks := map[byte]string{0: "database-session-unencrypted", 1: "", 2: "database-encryption-unavailable,database-session-unencrypted", 3: ""}
	for value := byte(0); value < 4; value++ {
		o := securityIdentified(t, "", tds(4, value))
		if got := strings.Join(securityValues(o, "tds_session_encryption"), ","); o.Status != contracts.Identified || got != labels[value] {
			t.Fatalf("TDS response %d: %s %q", value, o.Status, got)
		}
		if got := strings.Join(securityRisks(t, o, 1433), ","); got != risks[value] {
			t.Fatalf("TDS response %d risks %q, want %q", value, got, risks[value])
		}
		request := securityIdentified(t, "", tds(0x12, value))
		if got := securityValues(request, "tds_session_encryption"); request.Status != contracts.Identified || len(got) != 0 || len(securityRisks(t, request, 1433)) != 0 {
			t.Fatalf("TDS request offering %d: label %v risks %v", value, got, securityRisks(t, request, 1433))
		}
	}
	startup := securityHex(t, "0000002400030000757365720064656d6f006461746162617365006578616d706c650000")
	o := securityIdentified(t, "", startup)
	if strings.Join(securityValues(o, "postgresql_message"), ",") != "startup" || strings.Join(securityRisks(t, o, 5432), ",") != "database-session-unencrypted" {
		t.Fatalf("PostgreSQL startup: %+v risks %v", o, securityRisks(t, o, 5432))
	}
	for _, field := range []string{"demo", "example"} {
		if strings.Contains(fmt.Sprintf("%+v", o), field) {
			t.Fatalf("a startup parameter (%s) is emitted: %+v", field, o)
		}
	}
	ssl := securityIdentified(t, "", securityHex(t, "0000000804d2162f"))
	if len(securityValues(ssl, "postgresql_message")) != 0 || len(securityRisks(t, ssl, 5432)) != 0 {
		t.Fatalf("PostgreSQL SSLRequest: %+v risks %v", ssl, securityRisks(t, ssl, 5432))
	}
	response := securityMySQL{}.build()
	clear := append([]byte{}, response...)
	if i := bytes.Index(clear, []byte("caching_sha2_password")); i > 0 {
		clear = append(append(append([]byte{}, clear[:i]...), "mysql_clear_password"...), clear[i+len("caching_sha2_password"):]...)
		clear[0] = byte(len(clear) - 4)
	}
	if got := strings.Join(securityRisks(t, securityIdentified(t, "mysql", response), 3306), ","); got != "database-session-unencrypted" {
		t.Fatalf("HandshakeResponse41 on the wire: %q", got)
	}
	if got := strings.Join(securityAllRisks(t, securityIdentified(t, "mysql", clear), 3306), ","); got != "cleartext-credential-protocol,database-session-unencrypted" {
		t.Fatalf("mysql_clear_password on the wire: %q", got)
	}
	for _, c := range []struct {
		hint string
		data []byte
		port int
	}{{"mysql", response, 3306}, {"mysql", clear, 3306}, {"", startup, 5432}} {
		d := securityDecrypted(t, c.hint, c.data)
		if d.Status != contracts.Identified {
			t.Fatalf("decrypted %q: %+v", c.hint, d)
		}
		if got := securityRisks(t, d, c.port); len(got) != 0 {
			t.Fatalf("decrypted %q bytes were seen in the clear: %v", c.hint, got)
		}
		if got := securityAllRisks(t, d, c.port); c.hint == "mysql" && len(got) != 0 {
			t.Fatalf("decrypted MySQL handshake raised %v", got)
		}
	}
	if got := securityRisks(t, securityDecrypted(t, "", tds(4, 2)), 1433); strings.Join(got, ",") != "database-encryption-unavailable,database-session-unencrypted" {
		t.Fatalf("decrypted TDS response asserting no encryption: %v", got)
	}
}

func securityDatagram(t *testing.T, hint string, data []byte) contracts.Observation {
	t.Helper()
	obs, _, _ := securityInspect(t, "datagram", hint, data)
	return obs
}

// SR-51: every length agrees with its container and stays within its bound: SPICE capability counts at most 32,
// DSI payloads at most 64 bytes (4096 for a GetStatus reply), FINS frames at most 2048 bytes, at most 25 RIP
// entries and 8 RTCP packets; the X11 setup reply and RTCP identify only with their hint.
func TestSecurityDesktopStorageLengthBounds(t *testing.T) {
	spice := func(common int) []byte {
		body := append(append(securityLE32(0), 1, 0), securityLE32(uint32(common), 0, 18)...)
		body = append(body, make([]byte, 4*common)...)
		return append(append([]byte("REDQ"), securityLE32(2, 2, uint32(len(body)))...), body...)
	}
	dsi := func(flags, command byte, payload []byte) []byte {
		out := []byte{flags, command, 0, 1, 0, 0, 0, 0}
		out = append(out, securityBE32(uint32(len(payload)))...)
		return append(append(out, 0, 0, 0, 0), payload...)
	}
	fins := func(length int) []byte {
		body := append([]byte{0x80, 0, 2, 0, 1, 0, 0, 11, 0, 5, 1, 2}, make([]byte, length-8-12)...)
		return append(append(append([]byte("FINS"), securityBE32(uint32(8+len(body)))...), 0, 0, 0, 2, 0, 0, 0, 0), body...)
	}
	rip := func(entries int) []byte {
		out := []byte{2, 2, 0, 0}
		for i := 0; i < entries; i++ {
			out = append(out, 0, 2, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
		}
		return out
	}
	rr := []byte{0x80, 0xc9, 0, 1, 0, 0, 0, 0}
	for name, c := range map[string]struct {
		obs  contracts.Observation
		want bool
	}{
		"32 SPICE capabilities":    {securityIdentified(t, "", spice(32)), true},
		"33 SPICE capabilities":    {securityIdentified(t, "", spice(33)), false},
		"4096-byte DSI status":     {securityIdentified(t, "", dsi(1, 3, make([]byte, 4096))), true},
		"4097-byte DSI status":     {securityIdentified(t, "", dsi(1, 3, make([]byte, 4097))), false},
		"2048-byte FINS frame":     {securityIdentified(t, "", fins(2048)), true},
		"2049-byte FINS frame":     {securityIdentified(t, "", fins(2049)), false},
		"25 RIP entries":           {securityDatagram(t, "", rip(25)), true},
		"26 RIP entries":           {securityDatagram(t, "", rip(26)), false},
		"8 RTCP packets":           {securityDatagram(t, "rtcp", bytes.Repeat(rr, 8)), true},
		"9 RTCP packets":           {securityDatagram(t, "rtcp", bytes.Repeat(rr, 9)), false},
		"unhinted RTCP":            {securityDatagram(t, "", bytes.Repeat(rr, 2)), false},
		"hinted X11 setup reply":   {securityIdentified(t, "x11-server", securityHex(t, securityX11Reply)), true},
		"unhinted X11 setup reply": {securityIdentified(t, "", securityHex(t, securityX11Reply)), false},
	} {
		if got := c.obs.Status == contracts.Identified; got != c.want {
			t.Fatalf("%s: identified %v, want %v (%s %q)", name, got, c.want, c.obs.Status, c.obs.Reason)
		}
	}
	for _, payload := range [][]byte{make([]byte, 65), make([]byte, 66)} {
		for _, flags := range []byte{0, 1} {
			o := securityIdentified(t, "", dsi(flags, 4, payload))
			if o.Status == contracts.Identified || o.Reason != "DSI payload length outside the profile" {
				t.Fatalf("a %d-byte DSI OpenSession (flags %d): %s %q", len(payload), flags, o.Status, o.Reason)
			}
		}
	}
}

const securityX11Reply = "01000b000000160088a5b80000004000ffff3f00000100000800ffff01010000202008ff0000000076656e646f722d78200120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// SR-8: fixtures of the protocols that carry credentials or payload values (LDAP simple and SASL binds, MQTT 5
// CONNECT with user, password, will topic and properties, FastCGI parameters, FTP, POP3 and IMAP authentication,
// RADIUS, TACACS+, SNMP communities), whole and mutated, never emit an input string outside the reference
// vocabulary in an observation or reason.
func TestSecurityCredentialsNeverInObservations(t *testing.T) {
	securityMutationsStayClosed(t, 8, 200, "ldap", "mqtt", "fastcgi", "ftp", "pop3", "imap", "radius", "tacacs-plus", "snmp")
}

// SR-8: an LDAP simple bind, an MQTT 5 CONNECT with credentials and will properties, and FastCGI parameters are
// identified while the password, user, will payload, property values and parameter values stay out of the
// observation.
func TestSecurityCredentialFieldsAreNotEmitted(t *testing.T) {
	secret := "s3cr3t-placeholder"
	bind := append([]byte{0x30, 0, 2, 1, 1, 0x60, 0, 2, 1, 3, 4, 8}, "cn=admin"...)
	bind = append(append(bind, 0x80, byte(len(secret))), secret...)
	bind[1], bind[6] = byte(len(bind)-2), byte(len(bind)-7)
	ldap := securityIdentified(t, "", bind)
	if ldap.Status != contracts.Identified || ldap.ApplicationProtocol == nil || !strings.HasPrefix(*ldap.ApplicationProtocol, "ldap") {
		t.Fatalf("LDAP simple bind: %+v", ldap)
	}
	mqttString := func(s string) []byte { return append([]byte{0, byte(len(s))}, s...) }
	var body []byte
	body = append(body, mqttString("MQTT")...)
	body = append(body, 5, 0xc6, 0, 60, 0) // v5, user+password+will (QoS 0), keepalive 60, no properties
	body = append(body, mqttString("client-placeholder")...)
	body = append(body, 5, 0x02, 0, 0, 0, 9) // will properties: message expiry 9
	body = append(body, mqttString("will/topic-placeholder")...)
	body = append(body, mqttString("will-payload-placeholder")...)
	body = append(body, mqttString("user-placeholder")...)
	body = append(body, mqttString(secret)...)
	mqtt := securityIdentified(t, "", append([]byte{0x10, byte(len(body))}, body...))
	if mqtt.Status != contracts.Identified || mqtt.ApplicationProtocol == nil || !strings.HasPrefix(*mqtt.ApplicationProtocol, "mqtt") {
		t.Fatalf("MQTT 5 CONNECT: %+v", mqtt)
	}
	name, value := "SCRIPT_FILENAME", "/srv/placeholder.php"
	params := append(append([]byte{byte(len(name)), byte(len(value))}, name...), value...)
	cgi := append(fastcgiBegin(nil), fastcgiRecord(4, params, nil)...)
	cgi = append(cgi, fastcgiRecord(4, nil, nil)...)
	fcgi := securityIdentified(t, "", cgi)
	if fcgi.Status != contracts.Identified {
		t.Fatalf("FastCGI: %+v", fcgi)
	}
	for _, o := range []contracts.Observation{ldap, mqtt, fcgi} {
		rendered := fmt.Sprintf("%+v", o)
		for _, e := range o.Evidence {
			rendered += " " + e.Value
		}
		for _, forbidden := range []string{secret, "placeholder", "cn=admin", "SCRIPT_FILENAME"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%q emitted: %s", forbidden, rendered)
			}
		}
	}
}

// SR-20: a candidate hint never opens unknown-payload signature evaluation: the same unknown stream prefix and
// unknown datagram that match an unknown-payload signature unhinted match nothing under any hint.
func TestSecurityHintsNeverOpenUnknownPayloadSignatures(t *testing.T) {
	set := testSet(t)
	stream := append(make([]byte, 300), "PROBE-v1"...)
	if o := signedStream(t, set, stream, "fin").Observation; o.Application == nil || *o.Application != "probe-app" {
		t.Fatalf("the unhinted stream no longer matches: %+v", o)
	}
	datagram := []byte("\xffUDPPROBE payload")
	d, _ := NewDatagram(retaining())
	if err := d.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	if o, err := d.Inspect(datagram, ""); err != nil || o.Application == nil || *o.Application != "udp-probe" {
		t.Fatalf("the unhinted datagram no longer matches: %+v %v", o, err)
	}
	for _, hint := range []string{"dns", "tls", "http", "smb2", "ldap", "mqtt", "kerberos"} {
		in, err := New(retaining(), hint)
		if err != nil {
			continue
		}
		if err := in.SetSignatures(set); err != nil {
			t.Fatal(err)
		}
		in.Feed(stream)
		in.End("fin")
		if o := in.Observation; o.Application != nil || o.Scope == "signature_match" || in.Metrics.SignatureCandidates != 0 {
			t.Fatalf("stream hint %q opened unknown-payload signatures: %+v", hint, o)
		}
	}
	for hint := range DatagramHints {
		d, _ := NewDatagram(retaining())
		if err := d.SetSignatures(set); err != nil {
			t.Fatal(err)
		}
		o, err := d.Inspect(datagram, hint)
		if err == nil && (o.Application != nil || o.Scope == "signature_match") {
			t.Fatalf("datagram hint %q opened unknown-payload signatures: %+v", hint, o)
		}
	}
}

func securityVerdict(t *testing.T, client, server *contracts.Observation, port int) *appid.Verdict {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	serverBytes := appid.Bytes{}
	if server != nil {
		serverBytes = appid.Bytes{N: 20, Known: true}
	}
	return appid.SessionVerdict(pack, client, server, "tcp", port, true, appid.Bytes{N: 12, Known: true}, serverBytes, true)
}

// SR-25: a text line shared by several protocols is an unknown observation whose only evidence is the
// ambiguous_candidates context (no protocol, no line content); only the intersection of both directions'
// candidate sets, when it is a single family, names the application. A lone ambiguous direction (even with a single
// candidate), disjoint sets, or an intersection of two families never become an identity.
func TestSecuritySharedLinesAreContextNotIdentity(t *testing.T) {
	for line, want := range map[string]string{"220 mail.example.org ESMTP\r\n": "smtp,ftp", "USER alice\r\n": "ftp,pop3",
		"PASS secret\r\n": "ftp,pop3,irc", "QUIT\r\n": "ftp,pop3", "* OK ready\r\n": "imap"} {
		o := securityIdentified(t, "", []byte(line))
		if o.Status != contracts.Unknown || o.ApplicationProtocol != nil || len(o.Evidence) != 1 ||
			o.Evidence[0].Field != "ambiguous_candidates" || o.Evidence[0].Value != want || o.Evidence[0].Strength != "context" {
			t.Fatalf("%q: %+v", line, o)
		}
		if rendered := fmt.Sprintf("%+v", o); strings.Contains(rendered, "secret") || strings.Contains(rendered, "alice") {
			t.Fatalf("%q: the line content is emitted: %s", line, rendered)
		}
	}
	observe := func(line string) *contracts.Observation {
		o := securityIdentified(t, "", []byte(line))
		return &o
	}
	if v := securityVerdict(t, observe("USER alice\r\n"), observe("220 ftp.example.org ready\r\n"), 21); v.App != "ftp" || v.Status != "correlated" {
		t.Fatalf("USER with an FTP-or-SMTP greeting: %s %s", v.App, v.Status)
	}
	for name, c := range map[string]struct {
		client, server *contracts.Observation
		port           int
	}{
		"disjoint sets":            {observe("* OK ready\r\n"), observe("220 ready\r\n"), 143},
		"lone ambiguous direction": {observe("USER alice\r\n"), nil, 21},
		"lone single candidate":    {observe("* OK ready\r\n"), nil, 143},
		"two common families":      {observe("USER alice\r\n"), observe("QUIT\r\n"), 21},
	} {
		if v := securityVerdict(t, c.client, c.server, c.port); v.App != "unknown-tcp" || v.Status != "unknown" {
			t.Fatalf("%s: %s %s", name, v.App, v.Status)
		}
	}
}

func securityBER(tag byte, content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	if len(content) < 256 {
		return append([]byte{tag, 0x81, byte(len(content))}, content...)
	}
	return append([]byte{tag, 0x82, byte(len(content) >> 8), byte(len(content))}, content...)
}

func securityCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func securitySNMPv3(flags byte, engine, user, auth, priv, scoped []byte) []byte {
	header := securityBER(0x30, securityCat(securityBER(2, []byte{0x12, 0x34, 0x56, 0x78}), securityBER(2, []byte{0, 0xff, 0xe3}),
		securityBER(4, []byte{flags}), securityBER(2, []byte{3})))
	usm := securityBER(0x30, securityCat(securityBER(4, engine), securityBER(2, []byte{0}), securityBER(2, []byte{0}), securityBER(4, user),
		securityBER(4, auth), securityBER(4, priv)))
	return securityBER(0x30, securityCat(securityBER(2, []byte{3}), header, securityBER(4, usm), scoped))
}

func securityScoped(kind byte, bindings []byte, errorStatus byte) []byte {
	pdu := securityBER(kind, securityCat(securityBER(2, []byte{1}), securityBER(2, []byte{errorStatus}), securityBER(2, []byte{0}), securityBER(0x30, bindings)))
	return securityBER(0x30, securityCat(securityBER(4, nil), securityBER(4, nil), pdu))
}

// SR-37: SNMPv3 identifies only within the RFC 3412/3414 bounds (engine id and user at most 32 bytes, flags
// consistent with the security parameters, an encrypted PDU under privacy, at most 128 bindings) and never emits the
// user name, the engine identifier or the authentication and privacy parameters.
func TestSecuritySNMPv3BoundsAndSecrets(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04}
	auth, priv := bytes.Repeat([]byte{0xa7}, 12), bytes.Repeat([]byte{0x5b}, 8)
	encrypted := securityDatagram(t, "", securitySNMPv3(0x07, engine, []byte("operator"), auth, priv, securityBER(4, bytes.Repeat([]byte{0x33}, 48))))
	if encrypted.Status != contracts.Identified || encrypted.ApplicationProtocol == nil || *encrypted.ApplicationProtocol != "snmp/3" {
		t.Fatalf("encrypted SNMPv3: %+v", encrypted)
	}
	rendered := fmt.Sprintf("%+v", encrypted)
	for _, e := range encrypted.Evidence {
		rendered += fmt.Sprintf(" %s %x", e.Value, e.Value)
	}
	for _, secret := range [][]byte{[]byte("operator"), engine, auth, priv} {
		if strings.Contains(rendered, string(secret)) || strings.Contains(rendered, hex.EncodeToString(secret)) || strings.Contains(rendered, "1f88") {
			t.Fatalf("a user, engine id or key is emitted: %s", rendered)
		}
	}
	binding := securityBER(0x30, securityCat(securityBER(6, []byte{0x2b, 6, 1, 2, 1, 1, 1, 0}), securityBER(5, nil)))
	if o := securityDatagram(t, "", securitySNMPv3(0x04, nil, nil, nil, nil, securityScoped(0xa0, bytes.Repeat(binding, 128), 0))); o.Status != contracts.Identified {
		t.Fatalf("128 bindings: %+v", o)
	}
	if o := securityDatagram(t, "", securitySNMPv3(0x04, bytes.Repeat([]byte("x"), 32), bytes.Repeat([]byte("u"), 32), nil, nil, securityScoped(0xa0, binding, 0))); o.Status != contracts.Identified {
		t.Fatalf("32-byte engine id and user: %+v", o)
	}
	for name, data := range map[string][]byte{
		"privacy without authentication": securitySNMPv3(0x02, nil, nil, nil, nil, securityScoped(0xa0, nil, 0)),
		"reserved flag":                  securitySNMPv3(0x08, nil, nil, nil, nil, securityScoped(0xa0, nil, 0)),
		"auth flag without parameters":   securitySNMPv3(0x01, engine, []byte("u"), nil, nil, securityScoped(0xa0, nil, 0)),
		"plaintext PDU under privacy":    securitySNMPv3(0x03, engine, []byte("u"), auth, priv, securityScoped(0xa0, nil, 0)),
		"empty encrypted PDU":            securitySNMPv3(0x03, engine, []byte("u"), auth, priv, securityBER(4, nil)),
		"engine id too long":             securitySNMPv3(0x04, bytes.Repeat([]byte("x"), 33), nil, nil, nil, securityScoped(0xa0, nil, 0)),
		"user too long":                  securitySNMPv3(0x04, nil, bytes.Repeat([]byte("u"), 33), nil, nil, securityScoped(0xa0, nil, 0)),
		"error status on a request":      securitySNMPv3(0x04, nil, nil, nil, nil, securityScoped(0xa0, binding, 1)),
		"binding budget":                 securitySNMPv3(0x04, nil, nil, nil, nil, securityScoped(0xa0, bytes.Repeat(binding, 129), 0)),
	} {
		if o := securityDatagram(t, "", data); o.Status == contracts.Identified {
			t.Fatalf("%s identified: %+v", name, o)
		}
	}
}

// SR-42: a DNS response is identified only when every record stays within its type and the message (no trailing
// byte, an A record of exactly four bytes) and reports the message kind and rcode only; an SNMPv2c response
// reports its PDU kind and never its community, OIDs or values.
func TestSecurityDNSAndSNMPResponsesStayInTheirMessage(t *testing.T) {
	question := securityCat([]byte("\x03www\x07example\x03com\x00"), []byte{0, 1, 0, 1})
	response := func(rdata []byte, trailing int) []byte {
		answer := securityCat([]byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, byte(len(rdata))}, rdata)
		return securityCat([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, question, answer, make([]byte, trailing))
	}
	ok := securityDatagram(t, "", response([]byte{192, 0, 2, 7}, 0))
	if rcode, _ := securityEvidence(ok, "dns_rcode"); ok.Status != contracts.Identified || rcode.Value != "noerror" {
		t.Fatalf("DNS response: %+v", ok)
	}
	if rendered := fmt.Sprintf("%+v", ok); strings.Contains(rendered, "example") || strings.Contains(rendered, "192.0.2.7") {
		t.Fatalf("a DNS name or address is emitted: %s", rendered)
	}
	for name, data := range map[string][]byte{"trailing byte": response([]byte{192, 0, 2, 7}, 1), "five-byte A record": response([]byte{192, 0, 2, 7, 1}, 0),
		"three-byte A record": response([]byte{192, 0, 2}, 0)} {
		if o := securityDatagram(t, "", data); o.Status == contracts.Identified {
			t.Fatalf("DNS %s identified: %+v", name, o)
		}
	}
	binding := securityBER(0x30, securityCat(securityBER(6, []byte{0x2b, 6, 1, 2, 1, 1, 5, 0}), securityBER(4, []byte("secret-sysname"))))
	pdu := securityBER(0xa2, securityCat(securityBER(2, []byte{7}), securityBER(2, []byte{0}), securityBER(2, []byte{0}), securityBER(0x30, binding)))
	snmp := securityDatagram(t, "", securityBER(0x30, securityCat(securityBER(2, []byte{1}), securityBER(4, []byte("community-x")), pdu)))
	if kind, _ := securityEvidence(snmp, "snmp_pdu"); snmp.Status != contracts.Identified || kind.Value == "" {
		t.Fatalf("SNMPv2c response: %+v", snmp)
	}
	rendered := fmt.Sprintf("%+v", snmp)
	for _, e := range snmp.Evidence {
		rendered += " " + e.Value
	}
	for _, forbidden := range []string{"community-x", "secret-sysname", "1.3.6.1.2.1.1.5", "2b06010201010500"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("%q emitted: %s", forbidden, rendered)
		}
	}
}

// SR-53: NetBIOS name service data is keyed by opcode and type (the WACK flags word in responses only, 6-byte NB
// entries, NBSTAT node status in responses only), multicast DNS takes at most 8 questions, LLMNR is named only
// with its hint (the same bytes unhinted are plain DNS), and no name, address or node status is emitted.
func TestSecurityLocalNameServiceProfiles(t *testing.T) {
	mdns := func(n int) []byte {
		out := []byte{0, 0, 0, 0, 0, byte(n), 0, 0, 0, 0, 0, 0}
		for i := 0; i < n; i++ {
			out = append(append(out, 5, 'h', 'o', 's', 't', byte('0'+i), 5, 'l', 'o', 'c', 'a', 'l', 0), 0, 1, 0, 1)
		}
		return out
	}
	for name, c := range map[string]struct {
		hex, hint, protocol string
	}{
		"WACK response":     {"8001bc000000000100000000204547454a454d454646444546464346474546464343414341434143414341434100002000010000000200022910", "", "netbios-ns"},
		"WACK request":      {"80013c000000000100000000204547454a454d454646444546464346474546464343414341434143414341434100002000010000000200022910", "", ""},
		"6-byte NB entry":   {"8001ad800000000100000000204547454a454d45464644454646434647454646434341434143414341434143410000200001000493e000060000c0000205", "", "netbios-ns"},
		"7-byte NB entry":   {"8001ad800000000100000000204547454a454d45464644454646434647454646434341434143414341434143410000200001000493e000070000c000020500", "", ""},
		"NBSTAT response":   {"800484000000000100000000204547454a454d454646444546464346474546464343414341434143414341434100002100010000000000530246494c45534552564552202020202000040046494c45534552564552202020202020040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "", "netbios-ns"},
		"NBSTAT request":    {"800404000000000100000000204547454a454d454646444546464346474546464343414341434143414341434100002100010000000000530246494c45534552564552202020202000040046494c45534552564552202020202020040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "", ""},
		"LLMNR hinted":      {"424200000001000000000000066c6170746f700000010001", "llmnr", "llmnr"},
		"LLMNR bytes alone": {"424200000001000000000000066c6170746f700000010001", "", "dns"},
		"8 mDNS questions":  {hex.EncodeToString(mdns(8)), "", "mdns"},
		"9 mDNS questions":  {hex.EncodeToString(mdns(9)), "", ""},
	} {
		o := securityDatagram(t, c.hint, securityHex(t, c.hex))
		got := ""
		if o.Status == contracts.Identified && o.ApplicationProtocol != nil {
			got = *o.ApplicationProtocol
		}
		if got != c.protocol {
			t.Fatalf("%s: identified as %q, want %q (%s %q)", name, got, c.protocol, o.Status, o.Reason)
		}
		rendered := fmt.Sprintf("%+v", o)
		for _, e := range o.Evidence {
			rendered += " " + e.Value
		}
		for _, forbidden := range []string{"FILESERVER", "laptop", "host0", "192.0.2.5", "c0000205", "EGEJEMEF"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%s: %q emitted: %s", name, forbidden, rendered)
			}
		}
	}
}

// SR-55: with certificate inspection on, a TLS 1.2 ServerHello keeps its identification and its closed posture
// labels (key exchange and cipher mode from the fixed suite table) whatever its Certificate message holds: a leaf
// that is not DER adds no certificate field and withdraws nothing.
func TestSecurityCertificateDeviationKeepsTheServerHello(t *testing.T) {
	record := func(body []byte) []byte {
		return append([]byte{0x16, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	handshake := func(kind byte, body []byte) []byte {
		return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	hello := securityCat([]byte{3, 3}, bytes.Repeat([]byte{7}, 32), []byte{0, 0xc0, 0x2f, 0, 0, 0})
	leaf := []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x01} // a SEQUENCE whose NULL has a length byte: not DER
	certificate := securityCat([]byte{0, 0, byte(len(leaf) + 3), 0, 0, byte(len(leaf))}, leaf)
	cfg := contracts.DefaultConfig()
	cfg.Certificates = true
	for _, flight := range [][]byte{securityCat(record(handshake(2, hello)), record(handshake(11, certificate))),
		record(securityCat(handshake(2, hello), handshake(11, certificate)))} {
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		var kinds []string
		for _, e := range in.Feed(flight) {
			kinds = append(kinds, string(e.Kind))
		}
		for _, e := range in.End("fin") {
			kinds = append(kinds, string(e.Kind))
		}
		o := in.Observation
		if o.Status != contracts.Identified || o.Encryption == nil || *o.Encryption != "tls" {
			t.Fatalf("a malformed leaf after the ServerHello: %+v (events %v)", o, kinds)
		}
		for _, k := range kinds {
			if k == string(contracts.Retracted) {
				t.Fatalf("the ServerHello was withdrawn: %v", kinds)
			}
		}
		if kx, _ := securityEvidence(o, "selected_key_exchange"); kx.Value != "ecdhe" {
			t.Fatalf("key exchange label %+v", kx)
		}
		if mode, _ := securityEvidence(o, "selected_cipher_mode"); mode.Value != "aead" {
			t.Fatalf("cipher mode label %+v", mode)
		}
		for _, e := range o.Evidence {
			if strings.HasPrefix(e.Field, "tls_certificate_") {
				t.Fatalf("a certificate field from a malformed leaf: %+v", e)
			}
		}
	}
}

// SR-57: SMB transport posture comes only from a validated NEGOTIATE response: a 3.1.1 response selects exactly
// one cipher and one signing algorithm with lengths matching their counts and reports closed labels; the NETNAME
// context is never read or emitted, and a request (which may offer several of each) gains no posture rows.
func TestSecuritySMBNegotiatePosture(t *testing.T) {
	want := map[string]string{"smb_dialect": "3.1.1", "smb_signing": "required", "smb_encryption": "supported",
		"smb_encryption_cipher": "aes-128-gcm", "smb_signing_algorithm": "aes-cmac"}
	posture := func(o contracts.Observation) map[string]string {
		out := map[string]string{}
		for _, e := range o.Evidence {
			if strings.HasPrefix(e.Field, "smb_") {
				out[e.Field] = e.Value
			}
		}
		return out
	}
	for name, h := range map[string]string{
		"cipher and signing": "000000d4fe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030300000102030405060708090a0b0c0d0e0f7f00000000008000000080000000800000000000000000000000000000000000800008008800000060060604706c616301002600000000000100200001000000000000000000000000000000000000000000000000000000000000000000000002000400000000000100020000000000080004000000000001000100",
		"with a NETNAME":     "000000fafe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030400000102030405060708090a0b0c0d0e0f7f00000000008000000080000000800000000000000000000000000000000000800008008800000060060604706c6163010026000000000001002000010000000000000000000000000000000000000000000000000000000000000000000000020004000000000001000200000000000800040000000000010001000000000005001a00000000007300650063007200650074002d00730065007200760065007200",
	} {
		o := securityIdentified(t, "", securityHex(t, h))
		if got := posture(o); o.Status != contracts.Identified || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: %s %v", name, o.Status, got)
		}
		if rendered := fmt.Sprintf("%+v", o); strings.Contains(rendered, "secret") || strings.Contains(rendered, "s\x00e\x00c") {
			t.Fatalf("%s: the NETNAME is emitted: %s", name, rendered)
		}
	}
	for name, h := range map[string]string{
		"two signing algorithms": "000000c6fe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030200000102030405060708090a0b0c0d0e0f7f00000000008000000080000000800000000000000000000000000000000000800008008800000060060604706c61630100260000000000010020000100000000000000000000000000000000000000000000000000000000000000000000000800060000000000020000000100",
		"signing length":         "000000c6fe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030200000102030405060708090a0b0c0d0e0f7f00000000008000000080000000800000000000000000000000000000000000800008008800000060060604706c61630100260000000000010020000100000000000000000000000000000000000000000000000000000000000000000000000800060000000000010000000000",
		"two ciphers":            "000000c6fe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030200000102030405060708090a0b0c0d0e0f7f00000000008000000080000000800000000000000000000000000000000000800008008800000060060604706c61630100260000000000010020000100000000000000000000000000000000000000000000000000000000000000000000000200060000000000020001000200",
	} {
		if o := securityIdentified(t, "", securityHex(t, h)); o.Status == contracts.Identified {
			t.Fatalf("%s identified: %+v", name, o)
		}
	}
	request := securityIdentified(t, "", securityHex(t, "00000096fe534d42400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240002000100000000000000000102030405060708090a0b0c0d0e0f68000000030000000203110301000600000000000100000001000000020006000000000002000100020000000800060000000000020000000100"))
	if got := posture(request); request.Status != contracts.Identified || fmt.Sprint(got) != "map[smb_signing:enabled]" {
		t.Fatalf("a 3.1.1 request offering two ciphers and two signing algorithms: %s %v", request.Status, got)
	}
}
