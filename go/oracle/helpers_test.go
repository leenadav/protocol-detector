package oracle

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// The normalisations applied to tshark's columns, without running any tool.
func TestTsharkNormalisations(t *testing.T) {
	for _, c := range []struct{ legacy, supported, want string }{
		{"0x0303", "0x0a0a,0x0304,0x0303", "1.3"}, // GREASE first, then 1.3 and 1.2
		{"0x0303", "", "1.2"},                     // no supported_versions: the legacy version
		{"0x0303,0x0303", "", "1.2"},              // a frame with ClientHello and another handshake message
		{"0x0301", "0x7a7a", "1.0"},               // only GREASE in the list: the legacy version
	} {
		if got := maxTLSVersion(c.legacy, c.supported); got != c.want {
			t.Errorf("maxTLSVersion(%q, %q) = %q, want %q", c.legacy, c.supported, got, c.want)
		}
	}
	for v, want := range map[string]string{"0x00000001": "1", "0x6b3343cf": "2", "0x00000001,0x00000001": "1", "": "", "0xff00001d": "0xff00001d"} {
		if got := quicVersion(v); got != want {
			t.Errorf("quicVersion(%q) = %q, want %q", v, got, want)
		}
	}
	for h, want := range map[string]string{"A.Example.TEST:8080": "a.example.test", "a.example.test": "a.example.test",
		"[2001:db8::1]:443": "[2001:db8::1]", "[2001:db8::1]": "[2001:db8::1]"} {
		if got := hostOnly(h); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", h, got, want)
		}
	}
}

// The recorder and gopacket reader agree: an out-of-order, segmented flow comes back whole and in order, and
// only the client's bytes are kept.
func TestRecorderRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow.pcap")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	request := "GET / HTTP/1.1\r\nHost: round.example.test\r\n\r\n"
	f := rec.NewTCPFlow(client, server, Shape{Segment: 3, Swap: true})
	f.Data(true, []byte(request))
	f.Data(false, []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	f.Close()
	rec.UDP(&net.UDPAddr{IP: client.IP, Port: 5000}, &net.UDPAddr{IP: server.IP, Port: 443}, []byte("first"))
	rec.UDP(&net.UDPAddr{IP: server.IP, Port: 443}, &net.UDPAddr{IP: client.IP, Port: 5000}, []byte("reply"))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	flows, err := ReadFlows(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("want a TCP and a UDP flow, got %d", len(flows))
	}
	var tcp, udp *Flow
	for _, fl := range flows {
		if fl.Proto == "tcp" {
			tcp = fl
		} else {
			udp = fl
		}
	}
	var joined strings.Builder
	for _, c := range tcp.Chunks {
		joined.Write(c)
	}
	if tcp.Key != "tcp 127.0.0.1:40000>127.0.0.1:8080" || joined.String() != request {
		t.Errorf("tcp flow %s: %q", tcp.Key, joined.String())
	}
	if udp.Key != "udp 127.0.0.1:5000>127.0.0.1:443" || len(udp.Chunks) != 1 || string(udp.Chunks[0]) != "first" {
		t.Errorf("udp flow %s: %q", udp.Key, udp.Chunks)
	}
}
