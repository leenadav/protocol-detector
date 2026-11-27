package analyzer

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// SR-5: rejected TCP control state publishes a directional retraction visible to event consumers and releases the
// connection. These are the reference's control-path cases (test_control_retractions.cases at python-final): a
// segment past the FIN, a changed FIN, a FIN before data, URG, a missing ACK, a changed server ISN, a bad SYN-ACK
// and a client SYN-ACK, each after an identified direction.
func TestRejectedTCPControlStatePublishesADirectionalRetraction(t *testing.T) {
	a := transport.Endpoint{Addr: "192.0.2.10", Port: 52000}
	b := transport.Endpoint{Addr: "192.0.2.20", Port: 8080}
	req := []byte("DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n := uint32(len(req))
	const psh = 8
	frame := func(src, dst transport.Endpoint, seq, ack uint32, flags byte, payload []byte) *transport.TCP {
		return seg(src, dst, seq, ack, flags, payload)
	}
	handshake := []*transport.TCP{frame(a, b, 999, 0, transport.SYN, nil), frame(b, a, 8999, 1000, transport.SYN|transport.ACK, nil)}
	requestSeg := frame(a, b, 1000, 9000, transport.ACK|psh, req)
	finished := frame(a, b, 1000, 9000, transport.ACK|psh|transport.FIN, req)
	response := frame(b, a, 9000, 1000, transport.ACK|psh, []byte("SSH-2.0-demo\r\n"))
	cases := map[string]struct {
		packets []*transport.TCP
		source  transport.Endpoint
	}{
		"beyond_fin":         {[]*transport.TCP{finished, frame(a, b, 1000+n, 9000, transport.ACK|psh, []byte("X"))}, a},
		"changed_fin":        {[]*transport.TCP{finished, frame(a, b, 1001+n, 9000, transport.ACK|transport.FIN, nil)}, a},
		"fin_before_data":    {[]*transport.TCP{requestSeg, frame(a, b, 1001, 9000, transport.ACK|transport.FIN, nil)}, a},
		"urgent":             {[]*transport.TCP{requestSeg, frame(a, b, 1000, 9000, transport.ACK|psh|transport.URG, nil)}, a},
		"missing_ack":        {[]*transport.TCP{requestSeg, frame(a, b, 1000, 9000, psh, nil)}, a},
		"changed_server_isn": {[]*transport.TCP{response, frame(b, a, 8998, 1000, transport.SYN|transport.ACK, nil)}, b},
		"bad_syn_ack":        {[]*transport.TCP{response, frame(b, a, 8999, 1001, transport.SYN|transport.ACK, nil)}, b},
		"client_syn_ack":     {[]*transport.TCP{requestSeg, frame(a, b, 999, 9000, transport.SYN|transport.ACK, nil)}, a},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			an := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
			packets := append(append([]*transport.TCP{}, handshake...), c.packets...)
			var message string
			for i, p := range packets {
				if i == len(packets)-1 && !identified(an.LastEvents) && an.LastClassification == nil {
					t.Fatalf("the direction was not identified before the control fault")
				}
				message = an.Process(float64(i), p)
			}
			if len(message) < 11 || message[:11] != "INVALIDATED" {
				t.Fatalf("message %q, want an invalidation", message)
			}
			if an.LastClassification == nil || an.LastClassification.Status != contracts.Invalidated ||
				an.LastClassification.ApplicationProtocol != nil {
				t.Fatalf("last classification %+v, want invalidated without a protocol", an.LastClassification)
			}
			if len(an.LastEvents) != 1 || an.LastEvents[0].Revision != 2 || an.LastEvents[0].Observation.Status != contracts.Invalidated {
				t.Fatalf("events %+v, want one revision-2 retraction", an.LastEvents)
			}
			if an.Tracker.Tracked(a, b) != nil || len(an.Tracker.TrackedTCP()) != 0 {
				t.Fatalf("the rejected connection is still tracked")
			}
			an.Process(10, packets[len(packets)-1])
			if len(an.LastEvents) != 0 {
				t.Fatalf("a replayed fault published again: %+v", an.LastEvents)
			}
		})
	}
}
