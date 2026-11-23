package textroute_test

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/textroute"
)

const fixtures = "../../../../migration/fixtures/cases.json"

func fresh(t testing.TB) parsing.Parser {
	p, err := textroute.New(textroute.Options{MaxLine: 8192, MaxHeaders: 128, MaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// First-line routing and the HTTP header rules, at the parser.
func TestRoutesAndHeaderRules(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		wants []string
	}{
		{"http request", "GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n", []string{`error="" done=true`, `family="http"`, `protocol="http/1.1"`, `host="a.example"/true`}},
		{"http response", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", []string{`error="" done=true`, `family="http"`}},
		{"content-length at int64 max", "POST /u HTTP/1.1\r\nHost: a.example\r\nContent-Length: 9223372036854775807\r\n\r\n", []string{`error="" done=true`}},
		{"content-length 21 digits", "POST /u HTTP/1.1\r\nHost: a.example\r\nContent-Length: 100000000000000000000\r\n\r\n", []string{`error="malformed: Invalid or duplicate Content-Length"`}},
		{"duplicate content-length", "POST /u HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", []string{`error="malformed: Invalid or duplicate Content-Length"`}},
		{"bare LF", "GET /a HTTP/1.1\nHost: a.example\n\n", []string{`error="malformed: Expected CRLF line ending"`}},
		{"ssh banner", "SSH-2.0-OpenSSH_9.6\r\n", []string{`error=""`, `family="ssh"`}},
		{"smtp client", "EHLO client.example\r\n", []string{`error=""`, `family="smtp"`}},
		{"220 greeting alone", "220 mail.example ESMTP ready\r\n", []string{`error="ambiguous: `}},
	}
	for _, c := range cases {
		got := parsertest.Drive(fresh(t), []byte(c.data), 0)
		for _, want := range c.wants {
			if !strings.Contains(got, want) {
				t.Errorf("%s: want %s in %s", c.name, want, got)
			}
		}
		if bytewise := parsertest.Drive(fresh(t), []byte(c.data), 1); bytewise != got {
			t.Errorf("%s: byte by byte differs:\n whole %s\n bytes %s", c.name, got, bytewise)
		}
	}
	long := "GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\n\r\n"
	if got := parsertest.Drive(fresh(t), []byte(long), 0); !strings.Contains(got, `error="budget: Line length budget exceeded"`) {
		t.Errorf("long line: %s", got)
	}
}

// Every stream fixture gives the same answer whole, byte by byte and in 7-byte pieces.
func TestFixturesAreSplitInvariant(t *testing.T) {
	streams, err := parsertest.Streams(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	finished := 0
	for _, data := range streams {
		whole := parsertest.Drive(fresh(t), data, 0)
		if strings.HasPrefix(whole, "BROKEN") {
			t.Fatalf("%x: %s", data, whole)
		}
		if strings.Contains(whole, `error="" done=true`) {
			finished++
		}
		for _, step := range []int{1, 7} {
			if got := parsertest.Drive(fresh(t), data, step); got != whole {
				t.Fatalf("%q in %d-byte pieces:\n whole %s\n split %s", data, step, whole, got)
			}
		}
	}
	if finished < 50 {
		t.Fatalf("only %d fixtures finished; the fixture path or labels changed", finished)
	}
}

// FuzzSplitInvariance: arbitrary bytes never panic, never over-consume, and give one answer however they are split.
func FuzzSplitInvariance(f *testing.F) {
	streams, err := parsertest.Streams(fixtures, "http", "ssh", "smtp", "sip", "rtsp", "imap", "pop3", "ftp", "nats")
	if err != nil {
		f.Fatal(err)
	}
	for i, data := range streams {
		f.Add(data, uint8(i))
	}
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		whole := parsertest.Drive(fresh(t), data, 0)
		split := parsertest.Drive(fresh(t), data, int(step%64)+1)
		if strings.HasPrefix(whole, "BROKEN") || whole != split {
			t.Fatalf("step %d:\n whole %s\n split %s", int(step%64)+1, whole, split)
		}
	})
}
