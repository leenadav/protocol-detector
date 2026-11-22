package engine

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// The HTTP/1 continuation (D07, continuation.go in textroute) against the Python reference semantics, plus the
// Codex R3 rule: 1xx, 204 and 304 responses end at the header boundary whatever Content-Length or
// Transfer-Encoding declare.

func continued(t *testing.T, budget int, chunks ...string) (contracts.Observation, map[string]string, *Inspector) {
	t.Helper()
	cfg := contracts.DefaultConfig()
	cfg.Continuation = budget
	in, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chunks {
		in.Feed([]byte(c))
		if in.NotPorted != nil {
			t.Fatalf("not ported: %v", in.NotPorted)
		}
	}
	in.End("fin")
	fields := map[string]string{}
	for _, e := range in.Observation.Evidence {
		if strings.HasSuffix(e.Source, ":continuation") {
			fields[e.Field] = e.Value
		}
	}
	return in.Observation, fields, in
}

func expectFields(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("continuation evidence %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("continuation evidence %v, want %v", got, want)
		}
	}
}

const resp200 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

func TestContinuationNoBodyStatusesEndAtTheHeaders(t *testing.T) {
	// Without R3 the 304's Content-Length would swallow the next response as its body (one message counted).
	for _, c := range []struct{ head, classes string }{
		{"HTTP/1.1 304 Not Modified\r\nContent-Length: 40\r\n\r\n", "3xx,2xx"},
		{"HTTP/1.1 204 No Content\r\nContent-Length: 40\r\n\r\n", "2xx"},
		{"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", "3xx,2xx"},
		{"HTTP/1.1 103 Early Hints\r\nContent-Length: 40\r\n\r\n", "1xx,2xx"},
	} {
		obs, fields, _ := continued(t, 4096, resp200, c.head, resp200)
		if obs.Status != contracts.Identified {
			t.Fatalf("%q: %s", c.head, obs.Status)
		}
		expectFields(t, fields, map[string]string{"http_messages": "3", "http_status_classes": c.classes})
	}
	// The same rule when the no-body response is the identifying message.
	_, fields, _ := continued(t, 4096, "HTTP/1.1 304 Not Modified\r\nContent-Length: 40\r\n\r\n", resp200)
	expectFields(t, fields, map[string]string{"http_messages": "2", "http_status_classes": "2xx"})
}

func TestContinuationFramesBodiesAndCountsMessages(t *testing.T) {
	_, fields, _ := continued(t, 4096,
		"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"POST /b HTTP/1.1\r\nHost: b.example\r\nContent-Length: 5\r\n\r\nhello",
		"PUT /c HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n",
		"BREW /d HTTP/1.1\r\nHost: a.example\r\n\r\n")
	expectFields(t, fields, map[string]string{"http_messages": "4", "http_methods": "POST,PUT,extension", "http_host_variation": "observed"})
}

func TestContinuationEndReasons(t *testing.T) {
	cases := []struct {
		name   string
		budget int
		chunks []string
		want   map[string]string
	}{
		{"close-delimited first response", 4096, []string{"HTTP/1.1 200 OK\r\n\r\nbody"},
			map[string]string{"http_messages": "1", "continuation": "close-delimited"}},
		{"close-delimited later response", 4096, []string{resp200, "HTTP/1.0 200 OK\r\n\r\n"},
			map[string]string{"http_messages": "2", "http_status_classes": "2xx", "continuation": "close-delimited"}},
		{"budget", 10, []string{resp200, resp200},
			map[string]string{"http_messages": "1", "continuation": "budget"}},
		{"framing", 4096, []string{resp200, "garbage\r\n"},
			map[string]string{"http_messages": "1", "continuation": "framing"}},
		{"bad chunk size", 4096, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "zz\r\n"},
			map[string]string{"http_messages": "1", "continuation": "framing"}},
		{"chunk data without CRLF", 4096, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "1\r\naX\r\n"},
			map[string]string{"http_messages": "1", "continuation": "framing"}},
		{"oversized chunk size", 4096, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "11111111111111111\r\n"},
			map[string]string{"http_messages": "1", "continuation": "framing"}},
	}
	for _, c := range cases {
		_, fields, _ := continued(t, c.budget, c.chunks...)
		if len(fields) != len(c.want) {
			t.Fatalf("%s: %v, want %v", c.name, fields, c.want)
		}
		for k, v := range c.want {
			if fields[k] != v {
				t.Fatalf("%s: %v, want %v", c.name, fields, c.want)
			}
		}
	}
}

func TestContinuationMessageCap(t *testing.T) {
	cfg := contracts.DefaultConfig()
	cfg.Continuation, cfg.MaxTransactions = 1<<20, 3
	in, _ := New(cfg, "")
	for i := 0; i < 5; i++ {
		in.Feed([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	}
	in.End("fin")
	found := map[string]string{}
	for _, e := range in.Observation.Evidence {
		if strings.HasSuffix(e.Source, ":continuation") {
			found[e.Field] = e.Value
		}
	}
	expectFields(t, found, map[string]string{"http_messages": "3", "http_methods": "GET", "continuation": "messages"})
	if in.Metrics.BytesInspected > cfg.MaxBytes {
		t.Fatalf("inspected %d beyond the byte budget", in.Metrics.BytesInspected)
	}
}

func TestContinuationLaterConnectShifts(t *testing.T) {
	cfg := contracts.DefaultConfig()
	cfg.Continuation = 4096
	in, _ := New(cfg, "")
	in.Feed([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	in.Feed([]byte("CONNECT b.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n"))
	if in.shift != "http-connect" || in.next == nil {
		t.Fatalf("later CONNECT did not open the tunnel phase (shift %q)", in.shift)
	}
	if in.Observation.Scope != "tunnel_request" {
		t.Fatalf("scope %q", in.Observation.Scope)
	}
	var ended string
	for _, e := range in.Observation.Evidence {
		if e.Field == "continuation" {
			ended = e.Value
		}
	}
	if ended != "shift" {
		t.Fatalf("continuation ended %q", ended)
	}
}

func TestContinuationNeverChangesTheIdentification(t *testing.T) {
	obs, _, in := continued(t, 4096, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: b.example\r\n\r\n")
	if obs.Hostname == nil || *obs.Hostname != "a.example" || obs.ApplicationProtocol == nil || *obs.ApplicationProtocol != "http/1.1" {
		t.Fatalf("identification changed: %+v", obs)
	}
	if in.Metrics.BytesInspected != in.Metrics.BytesReceived {
		t.Fatalf("metrics %+v", in.Metrics)
	}
}

func FuzzHTTPContinuationStaysBounded(f *testing.F) {
	f.Add([]byte(resp200+"HTTP/1.1 304 Not Modified\r\nContent-Length: 4\r\n\r\n"+resp200), uint8(5), uint16(64))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), uint8(1), uint16(9))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8, budget uint16) {
		cfg := contracts.DefaultConfig()
		cfg.MaxBytes, cfg.Continuation, cfg.MaxTransactions = 4096, int(budget)+1, 4
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		step := int(chunk%16) + 1
		for i := 0; i < len(data); i += step {
			end := i + step
			if end > len(data) {
				end = len(data)
			}
			in.Feed(data[i:end])
		}
		in.End("fin")
		if in.Metrics.BytesInspected > in.Metrics.BytesReceived || in.Metrics.BytesReceived != len(data) {
			t.Fatalf("metrics out of bounds: %+v", in.Metrics)
		}
	})
}

// tlsHello is a minimal TLS 1.2 ClientHello record the Go TLS parser identifies.
var tlsHello = func() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}()

func record(kind byte, n int) string {
	return string(append([]byte{kind, 3, 3, byte(n >> 8), byte(n)}, make([]byte, n)...))
}

func TestTLSContinuationCountsRecordsWithoutReadingThem(t *testing.T) {
	_, fields, _ := continued(t, 4096, string(tlsHello), record(20, 1), record(22, 40), record(23, 30), record(23, 12), record(21, 2))
	expectFields(t, fields, map[string]string{"tls_records": "handshake=1,ccs=1,alert=1,application_data=2",
		"tls_application_data": "observed", "tls_alert": "observed"})
	_, fields, _ = continued(t, 4096, string(tlsHello), record(23, 3), "\x18\x03\x03\x00\x01x")
	expectFields(t, fields, map[string]string{"tls_records": "application_data=1", "tls_application_data": "observed", "continuation": "framing"})
	_, fields, _ = continued(t, 13, string(tlsHello), record(23, 3), record(23, 30)) // 8 + one 5-byte header
	expectFields(t, fields, map[string]string{"tls_records": "application_data=2", "tls_application_data": "observed", "continuation": "budget"})
	many := ""
	for i := 0; i < 300; i++ {
		many += record(23, 1)
	}
	_, fields, in := continued(t, 1<<20, string(tlsHello), many)
	expectFields(t, fields, map[string]string{"tls_records": "application_data=256", "tls_application_data": "observed", "continuation": "records"})
	if in.Metrics.BytesInspected != len(tlsHello)+255*6+5 { // the cap ends after the 256th header, its body unread
		t.Fatalf("inspected %d bytes", in.Metrics.BytesInspected)
	}
}
