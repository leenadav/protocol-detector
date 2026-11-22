package analyzer

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

func h2frame(kind, flags byte, stream uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(out, payload...)
}

// With prior knowledge the server's first frame is a bare SETTINGS frame no prefix routes; once the client preface
// identified the connection the server direction expects HTTP/2 (Analyzer._correlate_http2) and still validates.
func TestHTTP2PriorKnowledgeServerIsExpected(t *testing.T) {
	block := []byte{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	clientBytes := append(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), h2frame(4, 0, 0, nil)...), h2frame(1, 0x5, 1, block)...)
	serverBytes := append(h2frame(4, 0, 0, nil), h2frame(1, 0x4, 1, []byte{0x88})...)
	a, _, _ := converse(t, []step{{false, clientBytes}, {true, serverBytes}})
	if a.Tracker.Counts["http2_servers_expected"] != 1 {
		t.Fatalf("counts %v", a.Tracker.Counts)
	}
	if err := a.Tracker.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	protocol, _ := a.Records[0]["server_protocol"].(*string)
	if len(a.Records) != 1 || protocol == nil || *protocol != "http/2" || a.Records[0]["engine_status"] != string(contracts.Identified) {
		t.Fatalf("record %v", a.Records)
	}
}
