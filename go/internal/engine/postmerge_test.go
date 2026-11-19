package engine

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Post-merge detection items (migration/POST-MERGE-BACKLOG.md), prepared before the merge (2026-11-19). Each test
// asserts the behaviour the item asks for. While today's behaviour persists it is skipped with the item's reason;
// once the Go fix makes it pass, pending fails, so the marker is removed and the test becomes a plain assertion.
// The reproducers are synthetic: no captured bytes (AGENTS.md). Nothing here changes detection code.

func pending(t *testing.T, item string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now behaves as POST-MERGE-BACKLOG.md asks: remove pending() and assert it plainly", item)
	}
	t.Skipf("%s (migration/POST-MERGE-BACKLOG.md): post-merge, Go-only fix; today %s", item, today)
}

func inspectDatagram(t *testing.T, payload string) contracts.Observation {
	t.Helper()
	data, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDatagram(contracts.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	o, err := d.Inspect(data, "")
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// PM-1: a UDP datagram that only starts like an OpenVPN V3 client hard reset (0x50, a session id, one zero byte at
// the ACK-array offset, then arbitrary bytes) is identified as OpenVPN today. A real V3 reset carries tls-crypt-v2
// material after the session id, not an empty ACK array, so this shape is not one. The Skype captures of the D09
// run (research/d09-iscx-vpn2016.md, section 4.4) showed 13 such sessions.
func TestPM1_UDPOpenVPNNeedsMoreThanTheFirstBytes(t *testing.T) {
	const skypeLike = "508a31075ce219446b0073dd8fdbecc7777382da96302fcd8379a19dcb2f18724d241789cfe3b1a20a98fb65f673a7bd9da6289f03d487100f0930e13d9907c776537097d732843ba34b7f01a91575a7"
	o := inspectDatagram(t, skypeLike)
	pending(t, "PM-1", deref(o.Encryption) != "openvpn", "the datagram is identified as "+deref(o.Encryption)+": "+o.Reason)
}

// PM-2(a): the six seeded random datagrams (F-ADV-1's set: seed 7, 20,000 datagrams) that still pass as CoAP after
// the RFC 7252 tightening. Unhinted, none should.
func TestPM2_RandomDatagramsAreNotCoAP(t *testing.T) {
	survivors := []string{"664520229687271900f39014d9faad71", "4141f1f4fc4492d867aa50b4006ff6c8", "618c15c4033278dc",
		"478378f54b306024a1dfe5bad6b622cb928313c114d7a0a8322ea77df95432d8", "40a0f8419b56e0560b133dccc66e2d36",
		"5802de4bbe18840ebcb86811ff690016"}
	identified := 0
	for _, s := range survivors {
		if deref(inspectDatagram(t, s).ApplicationProtocol) == "coap" {
			identified++
		}
	}
	pending(t, "PM-2(a)", identified == 0, strconv.Itoa(identified)+" of 6 are identified as CoAP")
}

// PM-2(b): a random datagram that the CoAP first-byte probe selected and the profile then refused (F-ADV-1's
// reproducer) is unknown with code profile-unsupported, blaming CoAP; the D09 run saw 1,736 such UDP sessions. The
// item asks for no-dispatch: no supported structure was there.
func TestPM2_RefusedWeakProbeIsNoDispatch(t *testing.T) {
	o := inspectDatagram(t, "655085b84e0ec69b50164b0c53833c26")
	explained := appid.Explain(&o, appid.DirectionFacts{})
	code, _ := explained["code"].(string)
	pending(t, "PM-2(b)", code == "no-dispatch", "the code is "+code+" ("+o.Reason+")")
}

// PM-6: gQUIC (pre-RFC 9000) packets, a Q043 public header and a Q046 long header, end as no-dispatch today, like
// arbitrary bytes. The item asks for an honest reason that names QUIC (a version outside the profile), whether or
// not a gQUIC profile is added.
func TestPM6_GoogleQUICIsReportedAsQUICOutsideTheProfile(t *testing.T) {
	q043 := "0d010203040506070851303433019a687f9bff49" + strings.Repeat("00", 56)
	q046 := "c35130343650010203040506070800000001" + strings.Repeat("9e", 60)
	named := 0
	for _, p := range []string{q043, q046} {
		o := inspectDatagram(t, p)
		if o.Status == contracts.Identified || strings.Contains(o.Reason, "QUIC") {
			named++
		}
	}
	pending(t, "PM-6", named == 2, strconv.Itoa(named)+" of 2 gQUIC packets name QUIC")
}
