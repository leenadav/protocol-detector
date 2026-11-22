package engine

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

func h2frame(kind, flags byte, stream uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[5:], stream)
	return append(out, payload...)
}

var (
	// RFC 7541 C.4.1 (Huffman): :method GET, :scheme http, :path /, :authority www.example.com.
	h2RequestBlock = []byte{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	// :status 200, content-type application/grpc (literal without indexing, static name 31).
	h2ResponseBlock = append([]byte{0x88, 0x0f, 0x10, 16}, "application/grpc"...)
)

func h2run(t *testing.T, hint string, data ...[]byte) (*Inspector, map[string]string) {
	t.Helper()
	in, err := New(contracts.DefaultConfig(), hint)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range data {
		in.Feed(d)
	}
	in.End("fin")
	if in.NotPorted != nil {
		t.Fatalf("not ported: %v", in.NotPorted)
	}
	fields := map[string]string{}
	for _, e := range in.Observation.Evidence {
		fields[e.Field] = e.Value
	}
	return in, fields
}

func TestHTTP2ClientPrefaceSettingsAndFirstHeaders(t *testing.T) {
	settings := h2frame(4, 0, 0, []byte{0, 3, 0, 0, 0, 100})
	stream := append(append(append([]byte{}, []byte(h2Preface)...), settings...), h2frame(8, 0, 0, []byte{0, 0, 0xff, 0xff})...)
	stream = append(stream, h2frame(1, 0x5, 1, h2RequestBlock)...)
	in, fields := h2run(t, "", stream[:10], stream[10:40], stream[40:])
	o := in.Observation
	if o.Status != contracts.Identified || *o.ApplicationProtocol != "http/2" || o.Scope != "request_headers" {
		t.Fatalf("%+v", o)
	}
	if o.Hostname == nil || *o.Hostname != "www.example.com" || fields["http2_method"] != "GET" || fields["http2_scheme"] != "http" {
		t.Fatalf("decoded request: %v", fields)
	}
	// The identification was published at SETTINGS, before the HEADERS block was decoded.
	in2, _ := New(contracts.DefaultConfig(), "")
	events := in2.Feed(append(append([]byte{}, []byte(h2Preface)...), settings...))
	if len(events) != 1 || events[0].Observation.Scope != "initial_message" || events[0].Observation.Hostname != nil {
		t.Fatalf("SETTINGS publication: %+v", events)
	}
}

func TestHTTP2FramesOutsideTheProfileKeepTheIdentification(t *testing.T) {
	stream := append(append([]byte{}, []byte(h2Preface)...), h2frame(4, 0, 0, nil)...)
	in, fields := h2run(t, "", append(stream, h2frame(0, 1, 1, []byte("data"))...)) // DATA before HEADERS
	if in.Observation.Status != contracts.Identified || fields["http2_method"] != "" || in.Observation.Scope != "initial_message" {
		t.Fatalf("%+v", in.Observation)
	}
	in, _ = h2run(t, "", append(stream, h2frame(1, 0x4, 2, h2RequestBlock)...)) // even stream: malformed continuation
	if in.Observation.Status != contracts.Identified || in.Observation.Hostname != nil {
		t.Fatalf("a malformed HEADERS frame changed the identification: %+v", in.Observation)
	}
	bad := append(append([]byte{}, []byte(h2Preface)...), h2frame(4, 0, 0, []byte{0, 2, 0, 0, 0, 2})...) // ENABLE_PUSH 2
	if in, _ = h2run(t, "", bad); in.Observation.Status != contracts.Malformed {
		t.Fatalf("invalid initial SETTINGS: %s", in.Observation.Status)
	}
}

func TestHTTP2ServerDirectionAndExpect(t *testing.T) {
	server := append(h2frame(4, 0, 0, nil), h2frame(1, 0x4, 1, h2ResponseBlock)...)
	in, fields := h2run(t, "http2-server", server)
	if in.Observation.Scope != "response_headers" || fields["http2_status"] != "200" || fields["http2_content_type"] != "grpc" {
		t.Fatalf("server: %v %+v", fields, in.Observation)
	}
	// Prior knowledge: the expectation only selects the parser; the bytes still have to validate.
	peer, _ := New(contracts.DefaultConfig(), "")
	if !peer.Expect("http2-server", "http2-preface") || peer.Expect("http2-server", "again") {
		t.Fatal("expectation adoption")
	}
	peer.Feed(server)
	if peer.Observation.Status != contracts.Identified {
		t.Fatalf("expected server: %+v", peer.Observation)
	}
	var source string
	for _, e := range peer.Observation.Evidence {
		if e.Field == "candidate_hint" {
			source = e.Source
		}
	}
	if source != "peer:http2-preface" {
		t.Fatalf("hint source %q", source)
	}
	late, _ := New(contracts.DefaultConfig(), "")
	late.Feed([]byte{0})
	if late.Expect("http2-server", "x") {
		t.Fatal("a direction that already carried bytes adopted an expectation")
	}
	refused, _ := New(contracts.DefaultConfig(), "")
	refused.Expect("http2-server", "http2-preface")
	refused.Feed([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if refused.Observation.Status == contracts.Identified {
		t.Fatal("an expectation established identity")
	}
}

func TestH2CUpgradeShiftsIntoHTTP2(t *testing.T) {
	upgrade := "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\n\r\n"
	in, fields := h2run(t, "", []byte(upgrade), h2Preface, h2frame(4, 0, 0, nil), h2frame(1, 0x4, 1, h2RequestBlock))
	if fields["shift"] != "h2c-upgrade" || in.Observation.ApplicationProtocol == nil || *in.Observation.ApplicationProtocol != "http/2" {
		t.Fatalf("client h2c: %v", fields)
	}
	switching := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
	in, fields = h2run(t, "", []byte(switching), h2frame(4, 0, 0, nil), h2frame(1, 0x4, 1, h2ResponseBlock))
	if fields["shift"] != "h2c-upgrade" || fields["http2_status"] != "200" {
		t.Fatalf("server h2c: %v", fields)
	}
}

func TestHTTP2AuthorityHosts(t *testing.T) {
	for authority, want := range map[string]string{"A.Example:8443": "a.example", "192.0.2.1:80": "", "[::1]:443": ""} {
		block := append([]byte{0x82, 0x86, 0x84, 0x01, byte(len(authority))}, authority...)
		stream := append(append(append([]byte{}, []byte(h2Preface)...), h2frame(4, 0, 0, nil)...), h2frame(1, 0x4, 1, block)...)
		in, _ := h2run(t, "", stream)
		got := ""
		if in.Observation.Hostname != nil {
			got = *in.Observation.Hostname
		}
		if got != want || in.Observation.Scope != "request_headers" {
			t.Fatalf("%s: host %q scope %s", authority, got, in.Observation.Scope)
		}
	}
	block := append([]byte{0x82, 0x86, 0x84, 0x01, 11}, "u@a.example"...)
	stream := append(append(append([]byte{}, []byte(h2Preface)...), h2frame(4, 0, 0, nil)...), h2frame(1, 0x4, 1, block)...)
	if in, _ := h2run(t, "", stream); in.Observation.Hostname != nil || strings.Contains(in.Observation.Reason, "HEADERS validated") {
		t.Fatal("userinfo in :authority was accepted")
	}
}

func FuzzHTTP2StaysBounded(f *testing.F) {
	f.Add(append(append(append([]byte{}, []byte(h2Preface)...), h2frame(4, 0, 0, nil)...), h2frame(1, 0x4, 1, h2RequestBlock)...), uint8(3), false)
	f.Add(append(h2frame(4, 0, 0, nil), h2frame(1, 0x4, 1, h2ResponseBlock)...), uint8(1), true)
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8, server bool) {
		cfg := contracts.DefaultConfig()
		cfg.MaxBytes = 2048
		hint := "http2"
		if server {
			hint = "http2-server"
		}
		in, err := New(cfg, hint)
		if err != nil {
			t.Fatal(err)
		}
		step := int(chunk%32) + 1
		for i := 0; i < len(data); i += step {
			end := i + step
			if end > len(data) {
				end = len(data)
			}
			in.Feed(data[i:end])
		}
		in.End("fin")
		if in.Metrics.BytesInspected > cfg.MaxBytes || in.Metrics.BytesReceived != len(data) {
			t.Fatalf("metrics out of bounds: %+v", in.Metrics)
		}
	})
}
