package engine

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
)

// Expectations below were produced by the Python reference (Inspector/DatagramInspector with the same set).
const testSignatures = `[
 {"name": "corp-portal", "category": "business-systems", "subcategory": "general-business", "risk": 2, "parent": "web-browsing",
  "conditions": [{"context": "http-req-host-header", "operator": "equal-to", "value": "portal.corp.example"}]},
 {"name": "probe-app", "conditions": [{"context": "unknown-req-tcp-payload", "pattern": "PROBE-v1"}]},
 {"name": "udp-probe", "conditions": [{"context": "unknown-req-udp-payload", "pattern": "UDPPROBE"}]},
 {"name": "corp-dns", "conditions": [{"context": "dns-req-query-name", "pattern": "corp\\.example$"}]}]`

func testSet(t *testing.T) *signatures.Set {
	t.Helper()
	pack, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := signatures.FromJSON([]byte(testSignatures), pack)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func retaining() contracts.Config {
	cfg := contracts.DefaultConfig()
	cfg.RetainContexts = true
	return cfg
}

func signedStream(t *testing.T, set *signatures.Set, data []byte, end string) *Inspector {
	t.Helper()
	in, err := New(retaining(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	in.Feed(data)
	if end != "" {
		in.End(end)
	}
	return in
}

func hasEvidence(o contracts.Observation, field, value, source, strength string) bool {
	for _, e := range o.Evidence {
		if e.Field == field && e.Value == value && e.Source == source && e.Strength == strength {
			return true
		}
	}
	return false
}

func TestSignatureNamesTheApplicationOfAValidatedParser(t *testing.T) {
	set := testSet(t)
	in := signedStream(t, set, []byte("GET / HTTP/1.1\r\nHost: portal.corp.example\r\n\r\n"), "")
	o := in.Observation
	if o.Status != contracts.Identified || o.Application == nil || *o.Application != "corp-portal" || in.Metrics.SignatureCandidates != 1 ||
		!hasEvidence(o, "application", "corp-portal", "signature:http", "configured_signature") {
		t.Fatalf("matching host: %+v candidates %d", o, in.Metrics.SignatureCandidates)
	}
	// The exact-value index skips the signature entirely for another host: no candidate is evaluated.
	in = signedStream(t, set, []byte("GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"), "")
	if in.Observation.Application != nil || in.Metrics.SignatureCandidates != 0 {
		t.Fatalf("other host: %+v candidates %d", in.Observation, in.Metrics.SignatureCandidates)
	}
}

func TestUnknownPayloadSignatureIsTerminalAndScoped(t *testing.T) {
	set := testSet(t)
	in := signedStream(t, set, append(make([]byte, 300), "PROBE-v1"...), "fin")
	o := in.Observation
	if o.Status != contracts.Identified || o.Application == nil || *o.Application != "probe-app" || o.Scope != "signature_match" ||
		o.Reason != "Custom signature matched an unknown payload prefix; no protocol profile validated" ||
		len(o.Evidence) != 1 || !hasEvidence(o, "application", "probe-app", "signature:unknown-tcp", "configured_signature") {
		t.Fatalf("unknown prefix: %+v", o)
	}
	// A prefix that dispatch routes to a text family is never offered to unknown-payload signatures.
	in = signedStream(t, set, []byte("PROBE-v1 hello there"), "fin")
	if in.Observation.Status != contracts.Incomplete || in.Observation.Application != nil {
		t.Fatalf("text-routed prefix: %+v", in.Observation)
	}
}

func TestDatagramSignatures(t *testing.T) {
	set := testSet(t)
	d, err := NewDatagram(retaining())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	var q bytes.Buffer
	binary.Write(&q, binary.BigEndian, []uint16{0x1234, 0x0100, 1, 0, 0, 0})
	q.WriteString("\x03www\x04corp\x07example\x00\x00\x01\x00\x01")
	o, err := d.Inspect(q.Bytes(), "")
	if err != nil || o.Status != contracts.Identified || o.Application == nil || *o.Application != "corp-dns" ||
		!hasEvidence(o, "application", "corp-dns", "signature:dns", "configured_signature") {
		t.Fatalf("dns: %+v %v", o, err)
	}
	o, err = d.Inspect([]byte("\xffUDPPROBE payload"), "")
	if err != nil || o.Status != contracts.Identified || o.Application == nil || *o.Application != "udp-probe" || o.Scope != "signature_match" ||
		o.Transport != "udp" || o.Reason != "Custom signature matched an unknown datagram; no protocol profile validated" {
		t.Fatalf("unknown datagram: %+v %v", o, err)
	}
}

func TestSignaturesRequireRetainedContexts(t *testing.T) {
	set := testSet(t)
	in, _ := New(contracts.DefaultConfig(), "")
	d, _ := NewDatagram(contracts.DefaultConfig())
	const want = "Signatures require Config(retain_contexts=True)"
	if err := in.SetSignatures(set); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("stream: %v", err)
	}
	if err := d.SetSignatures(set); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("datagram: %v", err)
	}
}

// The verdict takes the signature's own metadata over its carrier; port usage comes from the carrier at this
// verdict, never from a carrier another session used (the reference caches port tables by application name).
func TestSignatureApplicationVerdict(t *testing.T) {
	set := testSet(t)
	pack, _ := content.Load("../../../migration/fixtures/content.json")
	in := signedStream(t, set, []byte("GET / HTTP/1.1\r\nHost: portal.corp.example\r\n\r\n"), "")
	if set.Digest != "e8cd8055a8064fe4" {
		t.Fatalf("digest %s", set.Digest)
	}
	for _, v := range []struct {
		port  int
		usage string
		risks []string
	}{{8000, "nonstandard", []string{"nonstandard-port"}}, {80, "standard", nil}, {8000, "nonstandard", []string{"nonstandard-port"}}} {
		verdict := appid.SessionVerdictWith(pack, set, &in.Observation, nil, "tcp", v.port, true, appid.Bytes{N: 40, Known: true},
			appid.Bytes{Known: true}, true, nil)
		if verdict.App != "corp-portal" || verdict.Category != "business-systems" || verdict.Subcategory != "general-business" ||
			verdict.Technology != "client-server" || verdict.Risk != 2 || len(verdict.Characteristics) != 0 || verdict.BaseApp == nil ||
			*verdict.BaseApp != "web-browsing" || len(verdict.ImplicitlyUses) != 1 || verdict.ImplicitlyUses[0] != "web-browsing" ||
			verdict.PortUsage != v.usage || len(verdict.Risks) != len(v.risks) || len(v.risks) > 0 && verdict.Risks[0] != v.risks[0] {
			t.Fatalf("port %d: %+v", v.port, verdict)
		}
	}
}
