package engine

// PRO-401 (Lee, 2026-11-25: the Python reference is removed): the Go-only replacement of the randomized Go-vs-Python
// differential (migration/parity/random_diff.py, whose seed-1 run is now frozen in
// migration/fixtures/golden/random.json.gz). Its generator drew valid-shaped TLS ClientHellos, HTTP/1.x request
// heads, SSH identification lines and protected QUIC v1/v2 client Initials with random content, then varied how
// they arrive (fragments, truncation, wrong hints, tight budgets), and needed the reference to say what the right
// answer was. Here the generators build messages whose identity is known by construction, so no oracle is needed:
//
//   - round trip: the whole message, unhinted, under the default budget, is identified as what was built, with the
//     hostname it carries (the SNI, the Host header) and the ALPN list it offers;
//   - split invariance and determinism: any fragmentation gives the outcome of the whole message;
//   - truncation: a strict prefix never names another identity than the whole message;
//   - hints select candidates and never establish identity: a hint other than the message's own family never makes
//     the engine name an identity the unhinted run does not;
//   - budgets: a tight byte budget is never exceeded, and never changes an identification into another one.
//
// The nightly job runs the same properties with many more checks (make property-long, -rapid.checks).

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// opening is one generated message and the identity it was built with.
type opening struct {
	family   string // the registry family the bytes belong to (the hint that is not "wrong")
	data     []byte
	datagram bool
	identity string // what the whole message must be identified as: application_protocol or encryption
	hostname string // the name it carries ("" when it carries none)
	alpn     []string
}

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func vector(width int, data []byte) []byte {
	if width == 1 {
		return append([]byte{byte(len(data))}, data...)
	}
	return append(u16(len(data)), data...)
}

func genLabel(t *rapid.T, name string) string {
	return rapid.StringMatching(`[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?`).Draw(t, name)
}

func genHost(t *rapid.T) string {
	labels := []string{}
	for i, n := 0, rapid.IntRange(1, 3).Draw(t, "labels"); i < n; i++ {
		labels = append(labels, genLabel(t, "label"))
	}
	return strings.Join(append(labels, rapid.SampledFrom([]string{"com", "net", "org", "io", "example", "test"}).Draw(t, "tld")), ".")
}

var grease = func() []uint16 {
	out := make([]uint16, 16)
	for i := range out {
		out[i] = 0x0a0a + 0x1010*uint16(i)
	}
	return out
}()

// clientHelloBody is a TLS 1.3 ClientHello handshake message (type, length, body) offering host and alpn.
func clientHelloBody(t *rapid.T, host string, alpn []string, quicParameters bool) []byte {
	var ciphers []byte
	if rapid.Bool().Draw(t, "grease cipher") {
		ciphers = append(ciphers, u16(int(rapid.SampledFrom(grease).Draw(t, "grease")))...)
	}
	for _, suite := range rapid.SliceOfNDistinct(rapid.SampledFrom([]int{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8}),
		1, 9, rapid.ID[int]).Draw(t, "ciphers") {
		ciphers = append(ciphers, u16(suite)...)
	}
	ext := func(kind int, body []byte) []byte { return append(append(u16(kind), u16(len(body))...), body...) }
	var extensions [][]byte
	if host != "" {
		name := append([]byte{0}, vector(2, []byte(host))...)
		extensions = append(extensions, ext(0, vector(2, name)))
	}
	if len(alpn) > 0 {
		var list []byte
		for _, protocol := range alpn {
			list = append(list, vector(1, []byte(protocol))...)
		}
		extensions = append(extensions, ext(16, vector(2, list)))
	}
	extensions = append(extensions,
		ext(43, vector(1, append(u16(0x0304), u16(0x0303)...))),
		ext(10, vector(2, append(u16(0x001d), u16(0x0017)...))),
		ext(13, vector(2, append(u16(0x0403), u16(0x0804)...))),
		ext(51, vector(2, append(append(u16(0x001d), u16(32)...), make([]byte, 32)...))))
	if quicParameters {
		extensions = append(extensions, ext(0x39, []byte{0x01, 0x02, 0x40, 0x64}))
	}
	if rapid.Bool().Draw(t, "grease extension") {
		extensions = append(extensions, ext(int(rapid.SampledFrom(grease).Draw(t, "grease ext")), nil))
	}
	if !quicParameters && rapid.Bool().Draw(t, "padding") {
		extensions = append(extensions, ext(21, make([]byte, rapid.IntRange(0, 200).Draw(t, "padding length"))))
	}
	// Shuffle all but the first extension's position stays meaningful only for the server name; order is free.
	order := rapid.Permutation(extensions).Draw(t, "extension order")
	var all []byte
	for _, e := range order {
		all = append(all, e...)
	}
	session := []byte{}
	if !quicParameters && rapid.Bool().Draw(t, "legacy session") {
		session = make([]byte, 32)
	}
	body := append(append([]byte{3, 3}, make([]byte, 32)...), vector(1, session)...)
	body = append(append(body, vector(2, ciphers)...), 1, 0)
	body = append(body, vector(2, all)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func genALPN(t *rapid.T, choices []string) []string {
	if !rapid.Bool().Draw(t, "offers alpn") {
		return nil
	}
	return rapid.SliceOfNDistinct(rapid.SampledFrom(choices), 1, len(choices), rapid.ID[string]).Draw(t, "alpn")
}

func genTLS(t *rapid.T) opening {
	host, alpn := "", genALPN(t, []string{"h2", "http/1.1", "spdy/3", "acme-tls/1"})
	if rapid.IntRange(0, 9).Draw(t, "no sni") > 0 {
		host = genHost(t)
	}
	hello := clientHelloBody(t, host, alpn, false)
	record := append(append([]byte{0x16, 3, byte(rapid.IntRange(1, 3).Draw(t, "record minor"))}, u16(len(hello))...), hello...)
	return opening{family: "tls", data: record, identity: "tls", hostname: host, alpn: alpn}
}

func genHTTP(t *rapid.T) opening {
	host := genHost(t)
	method := rapid.SampledFrom([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}).Draw(t, "method")
	path := "/" + rapid.StringMatching(`[a-z0-9/._-]{0,40}`).Draw(t, "path")
	version := rapid.SampledFrom([]string{"1.1", "1.0"}).Draw(t, "version")
	end := "\r\n" // both profiles require CRLF (a bare LF is malformed)
	lines := []string{method + " " + path + " HTTP/" + version, "Host: " + host}
	for i, n := 0, rapid.IntRange(0, 6).Draw(t, "headers"); i < n; i++ {
		lines = append(lines, "X-"+rapid.StringMatching(`[A-Za-z][A-Za-z0-9-]{0,15}`).Draw(t, "header")+": "+
			rapid.StringMatching(`[ -~]{0,40}`).Draw(t, "value"))
	}
	if rapid.Bool().Draw(t, "user agent") {
		lines = append(lines, "User-Agent: "+rapid.StringMatching(`[A-Za-z0-9/. ()]{1,40}`).Draw(t, "agent"))
	}
	return opening{family: "http", data: []byte(strings.Join(lines, end) + end + end), identity: "http/" + version, hostname: host}
}

func genSSH(t *rapid.T) opening {
	line := "SSH-2.0-" + rapid.StringMatching(`[A-Za-z0-9_.]{1,24}`).Draw(t, "software")
	if rapid.Bool().Draw(t, "comment") {
		line += " " + rapid.StringMatching(`[A-Za-z0-9_.+ -]{1,30}`).Draw(t, "comment text")
	}
	end := "\r\n" // both profiles require CRLF (a bare LF is malformed)
	return opening{family: "ssh", data: []byte(line + end), identity: "ssh"}
}

func genQUIC(t *rapid.T) opening {
	host, alpn := genHost(t), genALPN(t, []string{"h3", "h3-29", "doq"})
	hello := clientHelloBody(t, host, alpn, true)
	var cuts []int
	if len(hello) > 2 {
		for _, cut := range rapid.SliceOfNDistinct(rapid.IntRange(1, len(hello)-1), 0, 3, rapid.ID[int]).Draw(t, "crypto cuts") {
			cuts = append(cuts, cut)
		}
		sort.Ints(cuts)
	}
	framesList := testframes.CryptoFrames(hello, cuts...)
	order := rapid.Permutation(framesList).Draw(t, "crypto order")
	var frames []byte
	if rapid.Bool().Draw(t, "ping") {
		frames = append(frames, 1)
	}
	for _, frame := range order {
		frames = append(frames, frame...)
	}
	version := rapid.SampledFrom([]uint32{1, 0x6b3343cf}).Draw(t, "quic version")
	dcid := rapid.SliceOfN(rapid.Byte(), 8, 20).Draw(t, "dcid")
	scid := rapid.SliceOfN(rapid.Byte(), 0, 20).Draw(t, "scid")
	token := rapid.SliceOfN(rapid.Byte(), 0, 16).Draw(t, "token")
	datagram := testframes.QUICInitial(version, dcid, scid, frames, uint32(rapid.IntRange(0, 1000).Draw(t, "packet number")), token, 1200)
	return opening{family: "quic", data: datagram, datagram: true, identity: "quic", hostname: host, alpn: alpn}
}

func genOpening(t *rapid.T) opening {
	switch rapid.IntRange(0, 3).Draw(t, "kind") {
	case 0:
		return genTLS(t)
	case 1:
		return genHTTP(t)
	case 2:
		return genSSH(t)
	}
	return genQUIC(t)
}

// identity is what an observation names: its application protocol, else its encryption ("" when neither).
func identity(obs contracts.Observation) string {
	if obs.ApplicationProtocol != nil {
		return *obs.ApplicationProtocol
	}
	if obs.Encryption != nil {
		return *obs.Encryption
	}
	return ""
}

func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// observe runs one opening through a fresh inspector (a stream, fed in the pieces cuts delimit, then ended) or a
// datagram inspector, and checks the budget on the way.
func observe(t failer, o opening, cfg contracts.Config, hint string, data []byte, cuts []int) contracts.Observation {
	t.Helper()
	if o.datagram {
		d, err := NewDatagram(cfg)
		if err != nil {
			t.Fatal(err)
		}
		obs, _ := d.Inspect(data, hint)
		return obs
	}
	in, err := New(cfg, hint)
	if err != nil {
		t.Fatal(err)
	}
	fed := 0
	for _, piece := range piecesOf(data, cuts) {
		in.Feed(piece)
		fed += len(piece)
		if in.NotPorted != nil {
			t.Fatalf("not ported: %v", in.NotPorted)
		}
		if in.Metrics.BytesInspected > cfg.MaxBytes {
			t.Fatalf("inspected %d bytes over the %d budget", in.Metrics.BytesInspected, cfg.MaxBytes)
		}
	}
	in.End("fin")
	if in.Metrics.BytesReceived != fed {
		t.Fatalf("received %d of %d bytes", in.Metrics.BytesReceived, fed)
	}
	return in.Observation
}

func piecesOf(data []byte, cuts []int) [][]byte {
	var out [][]byte
	start := 0
	for _, cut := range cuts {
		out = append(out, data[start:cut])
		start = cut
	}
	return append(out, data[start:])
}

func render(obs contracts.Observation) string {
	return fmt.Sprintf("%s %q host=%q alpn=%v reason=%q", obs.Status, identity(obs), text(obs.Hostname), obs.OfferedALPN, obs.Reason)
}

// checkRoundTrip: the whole message is identified as built.
func checkRoundTrip(t failer, o opening) contracts.Observation {
	t.Helper()
	obs := observe(t, o, contracts.DefaultConfig(), "", o.data, nil)
	if obs.Status != contracts.Identified || identity(obs) != o.identity {
		t.Fatalf("%s opening %x: %s, want identified %s", o.family, o.data, render(obs), o.identity)
	}
	if o.hostname != "" && text(obs.Hostname) != o.hostname {
		t.Fatalf("%s opening carries %q: %s", o.family, o.hostname, render(obs))
	}
	if o.family == "tls" || o.family == "quic" {
		want := o.alpn
		if want == nil {
			want = []string{}
		}
		if fmt.Sprint(obs.OfferedALPN) != fmt.Sprint(want) {
			t.Fatalf("%s opening offers %v: %s", o.family, want, render(obs))
		}
	}
	return obs
}

func TestGeneratedOpeningsAreIdentifiedAsBuilt(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) { checkRoundTrip(rt, genOpening(rt)) })
}

func TestGeneratedOpeningsAreSplitInvariantAndDeterministic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		o := genOpening(rt)
		if o.datagram {
			o = genTLS(rt) // a datagram is never split
		}
		whole := render(observe(rt, o, contracts.DefaultConfig(), "", o.data, nil))
		if again := render(observe(rt, o, contracts.DefaultConfig(), "", o.data, nil)); again != whole {
			rt.Fatalf("not deterministic:\n first  %s\n second %s", whole, again)
		}
		cuts := genCuts(rt, o.data)
		if split := render(observe(rt, o, contracts.DefaultConfig(), "", o.data, cuts)); split != whole {
			rt.Fatalf("%s opening %x split at %v:\n whole %s\n split %s", o.family, o.data, cuts, whole, split)
		}
	})
}

func TestTruncatedOpeningsNeverNameAnotherIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		o := genOpening(rt)
		whole := checkRoundTrip(rt, o)
		cut := rapid.IntRange(1, len(o.data)-1).Draw(rt, "truncate at")
		obs := observe(rt, o, contracts.DefaultConfig(), "", o.data[:cut], genCuts(rt, o.data[:cut]))
		if obs.Status == contracts.Identified && identity(obs) != identity(whole) {
			rt.Fatalf("%s opening cut at %d of %d is identified as %q (whole: %s)", o.family, cut, len(o.data), identity(obs), render(whole))
		}
		if obs.Status == contracts.Identified && obs.Hostname != nil && text(obs.Hostname) != text(whole.Hostname) {
			rt.Fatalf("%s opening cut at %d names host %q (whole: %s)", o.family, cut, text(obs.Hostname), render(whole))
		}
	})
}

func TestHintsSelectCandidatesButNeverEstablishIdentity(t *testing.T) {
	var streamHints []string // every registry family the inspector takes as a hint
	for _, family := range registry() {
		if _, err := New(contracts.DefaultConfig(), family); err == nil {
			streamHints = append(streamHints, family)
		}
	}
	if len(streamHints) < 40 {
		t.Fatalf("only %d stream hints", len(streamHints))
	}
	datagramHints := []string{}
	for hint := range DatagramHints {
		datagramHints = append(datagramHints, hint)
	}
	sort.Strings(datagramHints)
	rapid.Check(t, func(rt *rapid.T) {
		o := genOpening(rt)
		unhinted := checkRoundTrip(rt, o)
		hints := streamHints
		if o.datagram {
			hints = datagramHints
		}
		hint := rapid.SampledFrom(hints).Draw(rt, "hint")
		if hint == o.family {
			return
		}
		data := o.data
		if !o.datagram && rapid.Bool().Draw(rt, "truncated") {
			data = data[:rapid.IntRange(1, len(data)-1).Draw(rt, "truncate at")]
		}
		obs := observe(rt, o, contracts.DefaultConfig(), hint, data, nil)
		if obs.Status == contracts.Identified && identity(obs) != identity(unhinted) {
			rt.Fatalf("hint %q made %s bytes %x identified as %q (unhinted whole message: %s)", hint, o.family, data, identity(obs), render(unhinted))
		}
	})
}

func TestTightBudgetsHoldAndNeverChangeTheIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		o := genOpening(rt)
		whole := checkRoundTrip(rt, o)
		cfg := contracts.DefaultConfig()
		cfg.MaxBytes = rapid.SampledFrom([]int{64, 256, 1024}).Draw(rt, "max bytes")
		if cfg.MaxBytes < cfg.MaxLine && !o.datagram {
			cfg.MaxLine = cfg.MaxBytes
		}
		if err := cfg.Validate(); err != nil {
			rt.Skip("configuration out of range: " + err.Error())
		}
		var cuts []int
		if !o.datagram {
			cuts = genCuts(rt, o.data)
		}
		obs := observe(rt, o, cfg, "", o.data, cuts)
		if obs.Status == contracts.Identified && (identity(obs) != identity(whole) || text(obs.Hostname) != text(whole.Hostname)) {
			rt.Fatalf("budget %d changed the identification of %s bytes: %s (default budget: %s)", cfg.MaxBytes, o.family, render(obs), render(whole))
		}
		if !o.datagram && len(o.data) > cfg.MaxBytes && obs.Status == contracts.Identified && o.family == "tls" {
			rt.Fatalf("a %d-byte ClientHello was identified within a %d-byte budget: %s", len(o.data), cfg.MaxBytes, render(obs))
		}
	})
}

// The generators themselves: every family is drawn, and the TLS record length matches its body.
func TestOpeningGeneratorsCoverEveryFamily(t *testing.T) {
	seen := map[string]int{}
	rapid.Check(t, func(rt *rapid.T) {
		o := genOpening(rt)
		seen[o.family]++
		if o.family == "tls" && int(binary.BigEndian.Uint16(o.data[3:5])) != len(o.data)-5 {
			rt.Fatalf("record length %d for %d bytes", binary.BigEndian.Uint16(o.data[3:5]), len(o.data)-5)
		}
	})
	for _, family := range []string{"tls", "http", "ssh", "quic"} {
		if seen[family] == 0 {
			t.Fatalf("no %s opening drawn: %v", family, seen)
		}
	}
}
