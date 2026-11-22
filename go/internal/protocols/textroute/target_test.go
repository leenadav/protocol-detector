package textroute

import (
	"strings"
	"testing"
)

func evidenceOf(rows []string, field string) string {
	for _, r := range rows {
		if strings.HasPrefix(r, field+"=") {
			return strings.TrimPrefix(r, field+"=")
		}
	}
	return ""
}

// SEC-HTTP-1 (RFC 9112 §3.2.2, §3.2.3): an absolute-form request target carries the authority, and a server
// must ignore the Host header then; a CONNECT target is the authority itself. The hostname used for routing and
// policy is the target's, a Host that names another host is flagged (http_host_mismatch, no second name
// emitted), and the hostname's source says where it came from.
func TestRequestTargetAuthorityIsTheHostname(t *testing.T) {
	for _, c := range []struct {
		name, request, host, source, mismatch string
	}{
		{"absolute-form, Host disagrees", "GET http://www.netflix.test/watch HTTP/1.1\r\nHost: www.youtube.test\r\n\r\n",
			"www.netflix.test", "http_target", "present"},
		{"absolute-form, Host agrees", "GET http://www.netflix.test/ HTTP/1.1\r\nHost: WWW.Netflix.test:80\r\n\r\n",
			"www.netflix.test", "http_host", ""},
		{"absolute-form HTTP/1.0 without Host", "GET http://www.netflix.test/ HTTP/1.0\r\n\r\n",
			"www.netflix.test", "http_target", ""},
		{"absolute-form https with port and userinfo", "GET https://user@api.example.test:8443/x?y HTTP/1.1\r\nHost: api.example.test:8443\r\n\r\n",
			"api.example.test", "http_host", ""},
		{"CONNECT, Host disagrees", "CONNECT tunnel.example.test:443 HTTP/1.1\r\nHost: allowed.example.test:443\r\n\r\n",
			"tunnel.example.test", "http_target", "present"},
		{"CONNECT, Host agrees", "CONNECT tunnel.example.test:443 HTTP/1.1\r\nHost: tunnel.example.test:443\r\n\r\n",
			"tunnel.example.test", "http_host", ""},
		{"CONNECT HTTP/1.0 without Host", "CONNECT tunnel.example.test:443 HTTP/1.0\r\n\r\n",
			"tunnel.example.test", "http_target", ""},
		{"absolute-form IPv4 target, named Host", "GET http://192.0.2.7/ HTTP/1.1\r\nHost: www.youtube.test\r\n\r\n",
			"", "", "present"},
		{"origin-form is unchanged", "GET /watch HTTP/1.1\r\nHost: www.youtube.test\r\n\r\n",
			"www.youtube.test", "http_host", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _ := New(Options{MaxLine: 8192, MaxHeaders: 64, MaxBytes: 65536})
			if _, err := p.Feed([]byte(c.request)); err != nil {
				t.Fatal(err)
			}
			r := p.Result()
			host := ""
			if r.HasHost {
				host = r.Host
			}
			rows := make([]string, 0, len(r.Extra))
			for _, row := range r.Extra {
				rows = append(rows, row.Field+"="+row.Value)
			}
			source := ""
			if r.HasHost {
				source = r.HostSource
			}
			if host != c.host || source != c.source || evidenceOf(rows, "http_host_mismatch") != c.mismatch {
				t.Fatalf("host %q source %q mismatch %q, want %q %q %q (evidence %v)",
					host, source, evidenceOf(rows, "http_host_mismatch"), c.host, c.source, c.mismatch, rows)
			}
			for _, row := range rows {
				if strings.Contains(row, "youtube") || strings.Contains(row, "allowed.example") {
					t.Fatalf("the disagreeing Host name leaked into evidence: %v", rows)
				}
			}
		})
	}
}
