package analyzer

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// PM-1 and PM-2 under the UDP flow rule Hermes decided (2026-11-19; research/protocol/udp-flow-decision.md, options
// A + C): a flow is decided on the first datagram of each direction, and the weak families (CoAP, OpenVPN) are
// identified only when two consecutive datagrams of the flow agree. Detection never uses ports. Today every datagram
// of a flow is inspected and the first identification sticks, so one chance match labels a long flow.

var (
	udpClient = transport.Endpoint{Addr: "192.0.2.20", Port: 50500}
	udpServer = transport.Endpoint{Addr: "198.51.100.50", Port: 40000} // no well-known port: ports never decide
)

type datagram struct {
	fromServer bool
	payload    []byte
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// udpFlowRecord feeds the datagrams of one flow and returns its session record.
func udpFlowRecord(t *testing.T, flow []datagram) map[string]interface{} {
	t.Helper()
	a := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	for i, d := range flow {
		src, dst := udpClient, udpServer
		if d.fromServer {
			src, dst = udpServer, udpClient
		}
		a.Process(0.001*float64(i+1), &transport.UDP{Source: src, Destination: dst, Payload: d.payload})
	}
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	if a.NotPorted != nil {
		t.Fatal(a.NotPorted)
	}
	for _, r := range a.Records {
		if r["transport"] == "udp" {
			return r
		}
	}
	t.Fatalf("no UDP record in %v", a.Records)
	return nil
}

func protocolOf(r map[string]interface{}, key string) string {
	switch v := r[key].(type) {
	case string:
		return v
	case *string:
		if v != nil {
			return *v
		}
	}
	return ""
}

// names reports whether the record identifies the family on either side or as its encryption.
func names(r map[string]interface{}, family string) bool {
	for _, key := range []string{"client_protocol", "server_protocol", "encryption"} {
		if p := protocolOf(r, key); p == family || len(p) > len(family) && p[:len(family)+1] == family+"/" {
			return true
		}
	}
	return false
}

// randomFlow is n seeded random datagrams (lengths 24..800), with insert placed at index at.
func randomFlow(n, at int, insert []byte) []datagram {
	rng := rand.New(rand.NewSource(20261119))
	lengths := []int{24, 48, 64, 100, 160, 200, 400, 800}
	out := make([]datagram, 0, n)
	for i := 0; i < n; i++ {
		if i == at {
			out = append(out, datagram{false, insert})
			continue
		}
		b := make([]byte, lengths[i%len(lengths)])
		rng.Read(b)
		b[0] = 0x17 // keep the filler itself outside every UDP family's first-byte probe
		out = append(out, datagram{i%3 == 2, b})
	}
	return out
}

// PM-1, rule C: a lone datagram that only begins like an OpenVPN V3 client hard reset is identified today. Under C
// one weak-family datagram is not enough. The control, a client hard reset answered by the server's reset (two
// consecutive agreeing datagrams, the fixtures OPENVPN and OPENVPN_SERVER), stays identified and is asserted plainly.
func TestPM1_OneOpenVPNLikeDatagramDoesNotDecideTheFlow(t *testing.T) {
	control := udpFlowRecord(t, []datagram{{false, mustHex(t, "3801020304050607080000000000")},
		{true, mustHex(t, "4011121314151617180100000000010203040506070800000000")}})
	if !names(control, "openvpn") {
		t.Fatalf("control: an OpenVPN client and server hard reset are not identified: %v", control)
	}
	lone := udpFlowRecord(t, []datagram{{false, mustHex(t, "508a31075ce219446b0073dd8fdbecc7777382da96302fcd8379a19dcb2f18724d241789cfe3b1a20a98fb65f673a7bd9da6289f03d487100f0930e13d9907c776537097d732843ba34b7f01a91575a7")}})
	pendingItem(t, "PM-1", !names(lone, "openvpn"), "a single OpenVPN-like datagram labels the flow openvpn")
}

// PM-2, rule A: in a long flow, a CoAP-looking datagram that is not the first datagram of its direction labels the
// whole flow today (the first identification sticks). Under A the first datagram decides. The control, two
// consecutive valid CoAP requests opening a flow (rule C satisfied), stays identified and is asserted plainly.
func TestPM2_ALaterCoAPLookingDatagramDoesNotRelabelTheFlow(t *testing.T) {
	get := mustHex(t, "41011234aab773656e736f7273") // the COAP fixture: CON GET /sensors
	control := udpFlowRecord(t, []datagram{{false, get}, {false, mustHex(t, "41011235abb773656e736f7273")}})
	if !names(control, "coap") {
		t.Fatalf("control: two consecutive CoAP requests are not identified: %v", control)
	}
	survivor := mustHex(t, "664520229687271900f39014d9faad71") // an F-ADV-1 random survivor
	long := udpFlowRecord(t, randomFlow(500, 250, survivor))
	pendingItem(t, "PM-2", !names(long, "coap"), "one CoAP-looking datagram at position 250 of 500 labels the flow coap")
}
