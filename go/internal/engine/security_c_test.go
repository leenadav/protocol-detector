package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// SR-14 (Go form): an inspector that reached a terminal state (identified, malformed, invalidated, ended) drops
// its parser and the parser's buffers itself, so nothing it retains depends on the garbage collector finding a
// cycle; only the dispatch prefix's capacity may stay, and it is truncated to zero length.
func TestTerminalInspectionReleasesItsParserBuffers(t *testing.T) {
	type run struct {
		name   string
		chunks []string
		end    bool
		inval  bool
	}
	runs := []run{
		{name: "identified http", chunks: []string{"GET /a HTTP/1.1\r\nHo", "st: a.example\r\n", "\r\n"}},
		{name: "malformed http", chunks: []string{"GET /a HTTP/1.1\r\nHost a.example\r\n", "\r\n"}},
		{name: "ended text", chunks: []string{"GET /a HTTP/1.1\r\nHost: a.exa"}, end: true},
		{name: "invalidated", chunks: []string{"GET /a HTTP/1.1\r\nHost: a.exa"}, inval: true},
		{name: "identified ssh, then ended", chunks: []string{"SSH-2.0-Open", "SSH_9.6\r\n"}, end: true},
	}
	for _, r := range runs {
		in, err := New(contracts.DefaultConfig(), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.chunks {
			in.Feed([]byte(c))
		}
		if r.end {
			in.End("fin")
		}
		if r.inval {
			in.Invalidate("conflicting retransmission")
		}
		if !in.terminal {
			t.Fatalf("%s: not terminal (status %s)", r.name, in.Observation.Status)
		}
		if in.parser != nil || in.next != nil || in.carrier != nil {
			t.Fatalf("%s: a terminal inspector still holds parser state (parser %T, next %v)", r.name, in.parser, in.next != nil)
		}
		if len(in.prefix) != 0 {
			t.Fatalf("%s: the dispatch prefix keeps %d bytes", r.name, len(in.prefix))
		}
		if n, _ := in.RetainedBytes(); n > cap(in.prefix) {
			t.Fatalf("%s: a terminal inspector retains %d bytes beyond its prefix capacity %d", r.name, n, cap(in.prefix))
		}
	}
}

// scClientHello is a TLS 1.3 ClientHello record with an SNI, an ALPN offer and the given random, legacy session id
// and X25519 key share: the bytes a fingerprint must never carry or depend on.
func scClientHello(random, session, key []byte) []byte {
	ext := func(kind int, body []byte) []byte { return append(append(u16(kind), u16(len(body))...), body...) }
	name := append([]byte{0}, vector(2, []byte("fp.example"))...)
	extensions := append(ext(0, vector(2, name)), ext(16, vector(2, vector(1, []byte("h2"))))...)
	extensions = append(extensions, ext(43, vector(1, append(u16(0x0304), u16(0x0303)...)))...)
	extensions = append(extensions, ext(10, vector(2, u16(0x001d)))...)
	extensions = append(extensions, ext(13, vector(2, u16(0x0403)))...)
	extensions = append(extensions, ext(51, vector(2, append(append(u16(0x001d), u16(len(key))...), key...)))...)
	body := append(append([]byte{3, 3}, random...), vector(1, session)...)
	body = append(append(body, vector(2, append(u16(0x1301), u16(0xc02f)...))...), 1, 0)
	body = append(body, vector(2, extensions)...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 3, 1}, u16(len(hs))...), hs...)
}

func scFill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b + byte(i)
	}
	return out
}

// SR-22: fingerprint rows (JA3, JA4) are derived only when Config.Fingerprints is set, and they are a function of
// the offer's structure only: changing the random, the legacy session id and the key share changes neither value,
// and no fingerprint row carries those bytes.
func TestFingerprintsOnlyWhenConfiguredAndFreeOfPerConnectionBytes(t *testing.T) {
	run := func(fingerprints bool, hello []byte) contracts.Observation {
		cfg := contracts.DefaultConfig()
		cfg.Fingerprints = fingerprints
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		in.Feed(hello)
		if in.Observation.Status != contracts.Identified {
			t.Fatalf("fingerprints=%v: %s %s", fingerprints, in.Observation.Status, in.Observation.Reason)
		}
		return in.Observation
	}
	derived := func(o contracts.Observation) map[string]string {
		out := map[string]string{}
		for _, e := range o.Evidence {
			if e.Strength == "derived" || e.Field == "ja3" || e.Field == "ja4" {
				out[e.Field] = e.Value
			}
		}
		return out
	}
	first := scClientHello(scFill(0x11, 32), scFill(0x51, 32), scFill(0x91, 32))
	second := scClientHello(scFill(0x22, 32), scFill(0x62, 32), scFill(0xa2, 32))
	if rows := derived(run(false, first)); len(rows) != 0 {
		t.Fatalf("fingerprints derived although not configured: %v", rows)
	}
	a, b := derived(run(true, first)), derived(run(true, second))
	if a["ja3"] == "" || a["ja4"] == "" || len(a) != 2 {
		t.Fatalf("configured fingerprints: %v", a)
	}
	if a["ja3"] != b["ja3"] || a["ja4"] != b["ja4"] {
		t.Fatalf("a fingerprint depends on the random, session id or key share: %v vs %v", a, b)
	}
	for _, secret := range [][]byte{scFill(0x11, 32), scFill(0x51, 32), scFill(0x91, 32)} {
		for field, value := range a {
			if strings.Contains(value, hex.EncodeToString(secret[:4])) || strings.Contains(value, string(secret[:4])) {
				t.Fatalf("%s carries per-connection bytes: %s", field, value)
			}
		}
	}
}

func scRandom(n int) []byte {
	r := rand.New(rand.NewSource(29))
	out := make([]byte, n)
	r.Read(out)
	return out
}

func scField(o contracts.Observation, field string) (string, bool) {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e.Value, true
		}
	}
	return "", false
}

func scDNSQuery(labels ...string) []byte {
	out := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range labels {
		out = append(append(out, byte(len(l))), l...)
	}
	return append(out, 0, 0, 1, 0, 1)
}

// SR-29: payload heuristics are off by default, never identify (an unknown payload stays unknown whatever its
// entropy), profile at most heuristic_bytes, are never added to an identified stream, and emit no payload bytes and
// no query name. Ported from test_risks.py (unknown stream, datagram and DNS name shape, identified streams).
func TestHeuristicsNeverIdentifyAreBoundedAndOffByDefault(t *testing.T) {
	random := scRandom(1200)
	unknown := append([]byte{0xfa, 0xfb}, random...) // 0xfa selects no family
	heuristic := contracts.DefaultConfig()
	heuristic.Heuristics = true
	stream := func(cfg contracts.Config, data []byte, end bool) *Inspector {
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		in.Feed(data)
		if end {
			in.End("fin")
		}
		return in
	}
	noPayload := func(name string, o contracts.Observation, payload []byte) {
		t.Helper()
		for _, e := range o.Evidence {
			for i := 0; i+6 <= len(payload); i += 6 {
				if chunk := string(payload[i : i+6]); strings.Contains(e.Value, chunk) || strings.Contains(e.Value, hex.EncodeToString(payload[i:i+3])) {
					t.Fatalf("%s: evidence %s=%q carries payload bytes", name, e.Field, e.Value)
				}
			}
		}
	}

	plain := stream(contracts.DefaultConfig(), unknown[:100], true)
	if plain.Observation.Status != contracts.Unknown || len(plain.Observation.Evidence) != 0 {
		t.Fatalf("default configuration profiled the payload: %+v", plain.Observation)
	}
	waiting := stream(heuristic, unknown[:300], false)
	if waiting.Observation.Status != contracts.Detecting {
		t.Fatalf("collecting up to heuristic_bytes: %s", waiting.Observation.Status)
	}
	waiting.Feed(unknown[300:])
	o := waiting.Observation
	if o.Status != contracts.Unknown || o.ApplicationProtocol != nil || o.Application != nil || o.Encryption != nil {
		t.Fatalf("a high-entropy payload was identified: %+v", o)
	}
	if class, _ := scField(o, "payload_class"); class != "high-entropy" {
		t.Fatalf("payload_class %q", class)
	}
	if n, _ := scField(o, "payload_bytes_profiled"); n != "512" {
		t.Fatalf("payload_bytes_profiled %q", n)
	}
	for _, e := range o.Evidence {
		if e.Strength != "heuristic" || e.Source != "wire:heuristic" {
			t.Fatalf("evidence row %+v", e)
		}
	}
	if waiting.Metrics.BytesInspected > 512 {
		t.Fatalf("inspected %d bytes, heuristic_bytes is 512", waiting.Metrics.BytesInspected)
	}
	noPayload("unknown stream", o, unknown)

	small := heuristic
	small.HeuristicBytes = 64
	bounded := stream(small, unknown[:700], false)
	if n, _ := scField(bounded.Observation, "payload_bytes_profiled"); n != "64" || bounded.Metrics.BytesInspected > 64+24 {
		t.Fatalf("heuristic_bytes=64: profiled %q, inspected %d", n, bounded.Metrics.BytesInspected)
	}
	text := stream(heuristic, append([]byte{0xfa}, []byte(strings.Repeat("hello ", 100))...), false)
	if class, _ := scField(text.Observation, "payload_class"); class != "text" || text.Observation.Status != contracts.Unknown {
		t.Fatalf("text payload: %+v", text.Observation)
	}
	noPayload("text stream", text.Observation, []byte(strings.Repeat("hello ", 2)))

	for _, data := range [][]byte{[]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), []byte("SSH-2.0-OpenSSH_9.6\r\n")} {
		in := stream(heuristic, data, false)
		if in.Observation.Status != contracts.Identified {
			t.Fatalf("%q: %s", data, in.Observation.Status)
		}
		for _, e := range in.Observation.Evidence {
			if e.Strength == "heuristic" {
				t.Fatalf("%q: an identified stream was profiled: %+v", data, e)
			}
		}
	}

	inspect := func(cfg contracts.Config, data []byte) contracts.Observation {
		d, err := NewDatagram(cfg)
		if err != nil {
			t.Fatal(err)
		}
		o, err := d.Inspect(data, "")
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	if o := inspect(contracts.DefaultConfig(), unknown[:200]); o.Status != contracts.Unknown || len(o.Evidence) != 0 {
		t.Fatalf("default datagram profiled: %+v", o)
	}
	profiled := inspect(heuristic, unknown[:200])
	if class, _ := scField(profiled, "payload_class"); profiled.Status != contracts.Unknown || class != "high-entropy" || profiled.ApplicationProtocol != nil {
		t.Fatalf("profiled datagram: %+v", profiled)
	}
	noPayload("datagram", profiled, unknown[:200])
	if n, _ := scField(inspect(small, unknown[:200]), "payload_bytes_profiled"); n != "64" {
		t.Fatalf("datagram with heuristic_bytes=64 profiled %q bytes", n)
	}
	label := "x7q2k9m4z1p8w3j6v5"
	shaped := inspect(heuristic, scDNSQuery(label, "example", "com"))
	if shape, _ := scField(shaped, "dns_query_shape"); shape != "suspicious" || deref(shaped.ApplicationProtocol) != "dns" {
		t.Fatalf("dns name shape: %+v", shaped)
	}
	for _, e := range shaped.Evidence {
		if strings.Contains(e.Value, label) || strings.Contains(e.Value, "example") {
			t.Fatalf("the query name is emitted: %+v", e)
		}
	}
	if _, ok := scField(inspect(contracts.DefaultConfig(), scDNSQuery(label, "example", "com")), "dns_query_shape"); ok {
		t.Fatal("dns name shape without the heuristics option")
	}
}

// scLeaf is a DER certificate whose issuer, subject, alternative names and serial are distinctive strings the
// certificate watch must never emit.
func scLeaf(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x5ec7e75e71a1),
		Subject:      pkix.Name{CommonName: "subjectsecretname.example", Organization: []string{"OrgSecretName"}},
		Issuer:       pkix.Name{CommonName: "issuersecretname.example"},
		DNSNames:     []string{"altsecretname.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func scU24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

func scRecord(kind byte, body []byte) []byte {
	return append(append([]byte{kind, 3, 3}, u16(len(body))...), body...)
}

// scServerHello12 is a TLS 1.2 ServerHello record selecting ECDHE-RSA-AES128-GCM-SHA256 with renegotiation_info.
func scServerHello12() []byte {
	body := append([]byte{3, 3}, scFill(0x33, 32)...)
	body = append(body, 0, 0xc0, 0x2f, 0)
	extensions := []byte{0xff, 0x01, 0, 1, 0}
	body = append(append(body, u16(len(extensions))...), extensions...)
	return scRecord(22, append(append([]byte{2}, scU24(len(body))...), body...))
}

// scCertificateMessage is the Certificate handshake message carrying the given DER entries.
func scCertificateMessage(certs ...[]byte) []byte {
	var list []byte
	for _, c := range certs {
		list = append(append(list, scU24(len(c))...), c...)
	}
	body := append(scU24(len(list)), list...)
	return append(append([]byte{11}, scU24(len(body))...), body...)
}

func scCertificateRows(o contracts.Observation) map[string]contracts.Evidence {
	out := map[string]contracts.Evidence{}
	for _, e := range o.Evidence {
		if strings.HasPrefix(e.Field, "tls_certificate_") {
			out[e.Field] = e
		}
	}
	return out
}

// SR-38: the TLS 1.2 certificate watch is opt-in, follows only an identified TLS 1.2 ServerHello, never consumes
// beyond max_bytes, and emits closed-set structure labels only (no issuer, subject, alternative name, serial, key or
// signature bytes); any fault, the budget end or a ClientHello keeps the identification unchanged and adds nothing.
func TestCertificateWatchIsOptInBoundedAndEmitsStructureLabelsOnly(t *testing.T) {
	leaf := scLeaf(t)
	hello := scServerHello12()
	flight := append(append([]byte{}, hello...), scRecord(22, scCertificateMessage(leaf))...)
	run := func(certificates bool, maxBytes int, data []byte) *Inspector {
		cfg := contracts.DefaultConfig()
		cfg.Certificates = certificates
		if maxBytes > 0 {
			cfg.MaxBytes = maxBytes
		}
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		in.Feed(data)
		in.End("fin")
		return in
	}
	identity := func(name string, in *Inspector) {
		t.Helper()
		if in.Observation.Status != contracts.Identified || deref(in.Observation.Encryption) != "tls" {
			t.Fatalf("%s: the ServerHello identification changed: %s %s", name, in.Observation.Status, in.Observation.Reason)
		}
	}

	plain := run(false, 0, flight)
	identity("default", plain)
	if rows := scCertificateRows(plain.Observation); len(rows) != 0 {
		t.Fatalf("certificate labels without Config.Certificates: %v", rows)
	}
	if plain.Metrics.BytesInspected != len(hello) {
		t.Fatalf("default configuration inspected %d bytes past the ServerHello", plain.Metrics.BytesInspected-len(hello))
	}

	watched := run(true, 0, flight)
	identity("watched", watched)
	rows := scCertificateRows(watched.Observation)
	if rows["tls_certificate_chain"].Value != "single" || rows["tls_certificate_key"].Value != "ec-256" || rows["tls_certificate_san"].Value != "present" {
		t.Fatalf("certificate labels: %v", rows)
	}
	if watched.Metrics.BytesInspected != len(flight) {
		t.Fatalf("inspected %d of %d bytes", watched.Metrics.BytesInspected, len(flight))
	}
	rendering := fmt.Sprintf("%+v", watched.Observation)
	for _, secret := range []string{"secretname", "SecretName", "5ec7e75e71a1", "5EC7E75E71A1", hex.EncodeToString(leaf[len(leaf)-8:])} {
		if strings.Contains(rendering, secret) {
			t.Fatalf("the observation carries certificate content %q: %s", secret, rendering)
		}
	}
	for field, e := range rows {
		want := "asserted"
		if field == "tls_certificate_chain" {
			want = "structural"
		}
		if e.Strength != want || len(e.Value) > 24 {
			t.Fatalf("certificate row %+v", e)
		}
	}

	for _, maxBytes := range []int{64, len(hello) + 15, len(hello) + 100, len(flight) - 1} {
		in := run(true, maxBytes, flight)
		identity(fmt.Sprintf("max_bytes=%d", maxBytes), in)
		if len(scCertificateRows(in.Observation)) != 0 || in.Metrics.BytesInspected > maxBytes {
			t.Fatalf("max_bytes=%d: inspected %d, labels %v", maxBytes, in.Metrics.BytesInspected, scCertificateRows(in.Observation))
		}
	}

	badList := scCertificateMessage(leaf)
	badList[6]++ // the list length no longer agrees with the message
	badDER := append([]byte{}, leaf...)
	badDER[1] = 0x84 // a four-octet DER length that exceeds its container
	for name, data := range map[string][]byte{
		"list length":  append(append([]byte{}, hello...), scRecord(22, badList)...),
		"DER length":   append(append([]byte{}, hello...), scRecord(22, scCertificateMessage(badDER))...),
		"alert record": append(append([]byte{}, hello...), scRecord(21, []byte{2, 40})...),
		"truncated":    flight[:len(flight)-10],
	} {
		in := run(true, 0, data)
		identity(name, in)
		if rows := scCertificateRows(in.Observation); len(rows) != 0 {
			t.Fatalf("%s: labels after a fault: %v", name, rows)
		}
	}

	client := run(true, 0, append(scClientHello(scFill(1, 32), nil, scFill(2, 32)), scRecord(22, scCertificateMessage(leaf))...))
	if client.Observation.Status != contracts.Identified || len(scCertificateRows(client.Observation)) != 0 {
		t.Fatalf("a ClientHello continued into the certificate watch: %+v", client.Observation)
	}
}

func scInspect(t *testing.T, data []byte, hint string) contracts.Observation {
	t.Helper()
	d, err := NewDatagram(contracts.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	o, err := d.Inspect(data, hint)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func scNoLeak(t *testing.T, name string, o contracts.Observation, secrets ...[]byte) {
	t.Helper()
	rendering := fmt.Sprintf("%+v", o)
	for _, s := range secrets {
		if strings.Contains(rendering, string(s)) || strings.Contains(rendering, hex.EncodeToString(s)) {
			t.Fatalf("%s: the observation carries %q: %s", name, s, rendering)
		}
	}
}

func scRadius(code byte, attrs ...[]byte) []byte {
	body := []byte{}
	for _, a := range attrs {
		body = append(body, a...)
	}
	out := append([]byte{code, 7}, u16(20+len(body))...)
	out = append(out, []byte("AuthenticatorXYZ")...)
	return append(out, body...)
}

func scAttr(kind byte, value []byte) []byte {
	return append([]byte{kind, byte(2 + len(value))}, value...)
}

// SR-45: RADIUS and OpenVPN server replies are identified only from complete datagrams whose fields fill the
// message exactly (RADIUS responses need the hint), and emit code and control labels only: no authenticator,
// reply text or session identifier. DTLS and IKEv2 replies are covered by the tlsx and framed tests named in the
// requirement map.
func TestUDPServerRepliesIdentifyOnlyExactDatagramsAndEmitLabelsOnly(t *testing.T) {
	accept := scRadius(2, scAttr(18, []byte("Welcome secretuser")), scAttr(27, []byte{0, 0, 0, 60}))
	o := scInspect(t, accept, "radius")
	if deref(o.ApplicationProtocol) != "radius" || o.Status != contracts.Identified {
		t.Fatalf("Access-Accept: %+v", o)
	}
	if code, _ := scField(o, "radius_code"); code != "access-accept" {
		t.Fatalf("radius_code %q", code)
	}
	scNoLeak(t, "Access-Accept", o, []byte("Welcome"), []byte("secretuser"), []byte("AuthenticatorXYZ"))
	if o := scInspect(t, accept, ""); deref(o.ApplicationProtocol) == "radius" {
		t.Fatalf("an Access-Accept without the hint was identified: %+v", o)
	}
	for name, data := range map[string][]byte{
		"trailing padding":         append(append([]byte{}, accept...), 0),
		"short length field":       append(append([]byte{}, accept[:2]...), append(u16(len(accept)-4), accept[4:]...)...),
		"attribute past the end":   scRadius(2, []byte{18, 9, 'a', 'b'}),
		"two-byte Session-Timeout": scRadius(2, scAttr(27, []byte{0, 1})),
		"reject with Service-Type": scRadius(3, scAttr(6, []byte{0, 0, 0, 2})),
	} {
		if o := scInspect(t, data, "radius"); deref(o.ApplicationProtocol) == "radius" || o.Status == contracts.Identified {
			t.Fatalf("RADIUS %s identified: %+v", name, o)
		}
	}

	session, remote := []byte("SESSION1"), []byte("REMOTEID")
	server := append(append([]byte{8 << 3}, session...), 1, 0, 0, 0, 0)
	server = append(append(server, remote...), 0, 0, 0, 0)
	o = scInspect(t, server, "")
	if deref(o.Encryption) != "openvpn" || o.Status != contracts.Identified {
		t.Fatalf("OpenVPN server reset: %+v", o)
	}
	if control, _ := scField(o, "openvpn_control"); control != "server-hard-reset" {
		t.Fatalf("openvpn_control %q", control)
	}
	scNoLeak(t, "OpenVPN", o, session, remote)
	zeroRemote := append(append([]byte{}, server[:14]...), append(make([]byte, 8), server[22:]...)...)
	for name, data := range map[string][]byte{
		"trailing byte":     append(append([]byte{}, server...), 0),
		"missing byte":      server[:len(server)-1],
		"zero remote id":    zeroRemote,
		"no acknowledgment": append(append([]byte{}, server[:9]...), append([]byte{0}, server[10:]...)...),
	} {
		if o := scInspect(t, data, ""); deref(o.Encryption) == "openvpn" && o.Status == contracts.Identified {
			t.Fatalf("OpenVPN %s identified: %+v", name, o)
		}
	}
}

// SR-34: S7comm is identified only after a validated ISO-TSAP connection TPDU; every S7 length is checked against
// the PDU, and a failed S7 phase keeps the ISO-TSAP identification.
func TestS7CommFollowsAValidatedConnectionAndAFailedPhaseKeepsTheCarrier(t *testing.T) {
	connect := []byte{3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2, 0xc0, 1, 0x0a}
	s7 := func(pdu []byte) []byte {
		return append(append([]byte{3, 0}, u16(7+len(pdu))...), append([]byte{2, 0xf0, 0x80}, pdu...)...)
	}
	setup := []byte{0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1, 1, 0xe0}
	run := func(data []byte) contracts.Observation {
		in := mustNew(t)
		in.Feed(data)
		in.End("fin")
		return in.Observation
	}
	if o := run(append(append([]byte{}, connect...), s7(setup)...)); deref(o.ApplicationProtocol) != "s7comm" || o.Status != contracts.Identified {
		t.Fatalf("valid connection and setup: %+v", o)
	}
	if o := run(s7(setup)); deref(o.ApplicationProtocol) == "s7comm" {
		t.Fatalf("an S7 PDU without the connection was identified: %+v", o)
	}
	trailing := append(append([]byte{}, setup...), 0)
	longer := append([]byte{}, setup...)
	longer[7] = 9 // the parameter length claims a byte the PDU does not have
	badQueue := append([]byte{}, setup...)
	badQueue[13] = 0 // calling queue 0
	for name, pdu := range map[string][]byte{"trailing byte": trailing, "parameter length": longer, "queue": badQueue} {
		o := run(append(append([]byte{}, connect...), s7(pdu)...))
		if deref(o.ApplicationProtocol) != "iso-tsap" || o.Status != contracts.Identified {
			t.Fatalf("%s: the failed S7 phase changed the carrier: %+v", name, o)
		}
	}
}
