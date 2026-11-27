package analyzer

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

var (
	securityProxy           = transport.Endpoint{Addr: "198.51.100.20", Port: 8080}
	securityConnectRequest  = []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n")
	securityConnectResponse = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	securityTLSServer13     = func() []byte {
		b, _ := hex.DecodeString("160303005a020000560303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00130100002e002b0002030400330024001d00200000000000000000000000000000000000000000000000000000000000000000")
		return b
	}()
)

// securityTunnel runs one proxied connection: the request, the response, then each side's tunnel bytes, with
// the data packets in the given capture order (indexes into request, response, client tunnel, server tunnel).
func securityTunnel(t *testing.T, request, response, clientTunnel, serverTunnel []byte, order []int) (*Analyzer, *Sink, *Sink) {
	t.Helper()
	a := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	a.Process(0, seg(client, securityProxy, 999, 0, transport.SYN, nil))
	a.Process(0, seg(securityProxy, client, 8999, 1000, transport.SYN|transport.ACK, nil))
	cr, cs := uint32(1000), uint32(9000)
	packets := []*transport.TCP{
		seg(client, securityProxy, cr, cs, transport.ACK|8, request),
		seg(securityProxy, client, cs, cr+uint32(len(request)), transport.ACK|8, response),
		seg(client, securityProxy, cr+uint32(len(request)), cs+uint32(len(response)), transport.ACK|8, clientTunnel),
		seg(securityProxy, client, cs+uint32(len(response)), cr+uint32(len(request)+len(clientTunnel)), transport.ACK|8, serverTunnel),
	}
	for i, n := range order {
		a.Process(0.001*float64(i+1), packets[n])
	}
	if a.NotPorted != nil {
		t.Fatal(a.NotPorted)
	}
	c := a.Tracker.Manager().Connections[session.KeyOf(client, securityProxy)]
	if c == nil {
		t.Fatal("connection not tracked")
	}
	return a, c.Directions[client].Sink.(*Sink), c.Directions[securityProxy].Sink.(*Sink)
}

func securityField(o contracts.Observation, field string) (contracts.Evidence, bool) {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e, true
		}
	}
	return contracts.Evidence{}, false
}

// SR-35: the server direction of a proxied connection is shifted by the host only when the client's CONNECT
// request and a 2xx status answer it, in either capture order; the opened phase's marker is peer-derived, and
// the carrier (http/1.1) is kept as shift_from. A 403 to a CONNECT, or a 200 to a GET, opens nothing.
func TestSecurityOnlyA2xxToAConnectOpensTheServerTunnel(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2, 3}, {1, 0, 2, 3}} {
		a, cl, sv := securityTunnel(t, securityConnectRequest, securityConnectResponse, clientHello, securityTLSServer13, order)
		if a.Tracker.Counts["connect_tunnels_correlated"] != 1 {
			t.Fatalf("order %v: %d tunnels correlated", order, a.Tracker.Counts["connect_tunnels_correlated"])
		}
		if encryption(cl.In.Observation) != "tls" || encryption(sv.In.Observation) != "tls" {
			t.Fatalf("order %v: client %+v server %+v", order, cl.In.Observation, sv.In.Observation)
		}
		if m, _ := securityField(cl.In.Observation, "shift"); m.Value != "http-connect" || m.Source != "wire" {
			t.Fatalf("order %v: client shift %+v", order, m)
		}
		m, _ := securityField(sv.In.Observation, "shift")
		from, _ := securityField(sv.In.Observation, "shift_from")
		if m.Value != "http-connect" || m.Source != "wire:peer" || from.Value != "http/1.1" || from.Source != "wire" {
			t.Fatalf("order %v: server shift %+v from %+v", order, m, from)
		}
	}
	forbidden := []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	a, _, sv := securityTunnel(t, securityConnectRequest, forbidden, clientHello, securityTLSServer13, []int{0, 1, 2, 3})
	if _, shifted := securityField(sv.In.Observation, "shift"); a.Tracker.Counts["connect_tunnels_correlated"] != 0 || shifted {
		t.Fatalf("a 403 opened the tunnel: %+v", sv.In.Observation)
	}
	if status, _ := securityField(sv.In.Observation, "http_status"); status.Value != "403" || sv.In.Observation.ApplicationProtocol == nil || *sv.In.Observation.ApplicationProtocol != "http/1.1" {
		t.Fatalf("the 403 carrier: %+v", sv.In.Observation)
	}
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	a, cl, sv := securityTunnel(t, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), ok, clientHello, securityTLSServer13, []int{0, 1, 2, 3})
	_, clientShift := securityField(cl.In.Observation, "shift")
	_, serverShift := securityField(sv.In.Observation, "shift")
	if a.Tracker.Counts["connect_tunnels_correlated"] != 0 || clientShift || serverShift {
		t.Fatalf("a 200 to a GET opened a tunnel: client %+v server %+v", cl.In.Observation, sv.In.Observation)
	}
}

// securityRecord runs one HTTP connection naming host through an analyzer on pack and returns its record.
func securityRecord(t *testing.T, pack *content.Pack, host string) (*Analyzer, map[string]interface{}) {
	t.Helper()
	a, err := New(pack, Options{Session: session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 1000, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	web := transport.Endpoint{Addr: "198.51.100.20", Port: 80}
	req := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	a.Process(0, seg(client, web, 999, 0, transport.SYN, nil))
	a.Process(0, seg(web, client, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(0, seg(client, web, 1000, 9000, transport.ACK, nil))
	a.Process(0.1, seg(client, web, 1000, 9000, transport.ACK|8, req))
	if err := a.Finish("end"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 1 {
		t.Fatalf("%d records", len(a.Records))
	}
	return a, a.Records[0]
}

// SR-66: every session record and the run's summary block name the content release in force (version and
// verified digest), and an analyzer built on an earlier release classifies with that release's catalog and says so.
func TestSecuritySessionRecordsPinTheContentRelease(t *testing.T) {
	current, err := content.Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := content.EmbeddedRelease("2025.10.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		pack *content.Pack
		app  string
	}{{current, "openai-platform"}, {earlier, "openai-chatgpt"}} {
		a, record := securityRecord(t, c.pack, "api.openai.com")
		want := map[string]interface{}{"version": c.pack.Release.Version, "digest": c.pack.Digests.Release}
		got, _ := record["content"].(map[string]interface{})
		if got == nil || got["version"] != want["version"] || got["digest"] != want["digest"] || c.pack.Digests.Release != c.pack.Release.Digest {
			t.Fatalf("record content %v, want %v", record["content"], want)
		}
		if summary := a.Content(); summary["version"] != want["version"] || summary["digest"] != want["digest"] {
			t.Fatalf("summary content %v, want %v", summary, want)
		}
		if record["app"] != c.app {
			t.Fatalf("release %s: app %v, want %s", c.pack.Release.Version, record["app"], c.app)
		}
	}
}

// SR-30: a session record carries the flow risks of its verdict (a Telnet negotiation on port 2323:
// cleartext-credential-protocol, nonstandard-port, obsolete-protocol) and no payload value.
func TestSecuritySessionRecordsCarryRisksWithoutPayload(t *testing.T) {
	pack, err := content.Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(pack, Options{Session: session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 1000, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	telnetServer := transport.Endpoint{Addr: "198.51.100.20", Port: 2323}
	telnet := []byte{0xff, 0xfd, 0x18, 0xff, 0xfb, 0x01}
	a.Process(0, seg(client, telnetServer, 999, 0, transport.SYN, nil))
	a.Process(0, seg(telnetServer, client, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(0.1, seg(client, telnetServer, 1000, 9000, transport.ACK|8, telnet))
	if err := a.Finish("end"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 1 {
		t.Fatalf("%d records", len(a.Records))
	}
	risks, _ := a.Records[0]["risks"].([]string)
	if strings.Join(risks, ",") != "cleartext-credential-protocol,nonstandard-port,obsolete-protocol" {
		t.Fatalf("record risks %v", a.Records[0]["risks"])
	}
	text, _ := json.Marshal(a.Records[0])
	if strings.Contains(string(text), "payload") || strings.Contains(string(text), "fffd18") {
		t.Fatalf("the record carries payload: %s", text)
	}
}
