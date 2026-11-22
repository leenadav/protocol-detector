package signatures

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// FuzzDocumentNeverPanics parses arbitrary signature documents (operator files) and matches what parses against
// fixed contexts of every kind the engine produces: text, bytes and integers (contract C16).
func FuzzDocumentNeverPanics(f *testing.F) {
	f.Add([]byte(`[{"name": "a", "conditions": [{"context": "http-req-host-header", "pattern": "example"}]}]`))
	f.Add([]byte(`{"version": 1, "signatures": [{"name": "b", "parent": "ssl", "risk": 4, "conditions": {"or": [` +
		`{"context": "ssl-req-chello-sni", "pattern": "\\.example$", "case_insensitive": true},` +
		`{"context": "dns-req-query-type", "operator": "less-than", "value": 30}]}}]}`))
	f.Add([]byte(`[{"name": "c", "conditions": [{"context": "unknown-req-tcp-payload", "pattern": "[\\x00-\\xff]{0,8}\\x00\\x00"},` +
		`{"context": "unknown-req-tcp-payload-length", "operator": "greater-than", "value": 3}]}]`))
	f.Add([]byte(`{"version": 2}`))
	pack, err := content.Embedded()
	if err != nil {
		f.Fatal(err)
	}
	contexts := map[string]parsing.Contexts{
		"http":        {"http-req-host-header": []byte("www.example.test"), "http-req-method": []byte("GET")},
		"tls":         {"ssl-req-chello-sni": []byte("a.example")},
		"dns":         {"dns-req-query-name": []byte("www.example.com"), "dns-req-query-type": int64(1)},
		"unknown-tcp": {"unknown-req-tcp-payload": []byte("\x00\x00\x00\x00\x00\x00\x00\x00"), "unknown-req-tcp-payload-length": int64(8)},
		"unknown-udp": {"unknown-req-udp-payload": []byte("PROBE-1234"), "unknown-req-udp-payload-length": int64(10)},
		"ssh":         {"ssh-req-banner": []byte("SSH-2.0-OpenSSH_9.6")},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<14 {
			return
		}
		set, err := FromJSON(data, pack)
		if err != nil || set == nil {
			return
		}
		for family, values := range contexts {
			if !set.Wants(family) {
				continue
			}
			if match, evaluated := set.MatchCounted(family, values); evaluated < 0 || (match != nil && set.Get(match.Name) == nil) {
				t.Fatalf("family %s: evaluated %d, match %v", family, evaluated, match)
			}
		}
	})
}
