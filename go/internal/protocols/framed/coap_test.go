package framed

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// F-ADV-1 (Lee, 2026-11-18): the CoAP profile follows RFC 7252's codes and option formats, as wire.coap does.
// The vectors are protocol_fixtures.COAP_VALID and COAP_INVALID; the first invalid one is the seeded random
// datagram the earlier profile identified as CoAP. Every invalid vector was identified by the earlier profile.
func TestCoAPProfileFollowsRFC7252(t *testing.T) {
	for _, c := range []struct{ name, hex, kind, reason string }{
		{"get-uri", "420130397a013d0173656e736f722e6578616d706c654216334773656e736f72730474656d7046756e69743d632100", "", ""},
		{"content-ack", "624530397a01440badf00d8132213cff7b2274223a32317d", "", ""},
		{"observe", "51010007996056737461747573", "", ""},
		{"block2", "4145100005d10a1a520400ff78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878", "", ""},
		{"not-found", "50840010ff6e6f2073756368207265736f75726365", "", ""},
		{"post", "4002002ab6696e6765737410ff68656c6c6f", "", ""},
		{"unavailable", "40a3002bd1011eff62757379", "", ""},
		{"unknown-elective", "4001002cb161e2fcd00102", "", ""},
		{"f-adv-1-random", "655085b84e0ec69b50164b0c53833c26", "unsupported", "Unsupported CoAP code profile"},
		{"unregistered-code-2.06", "40460001ff78", "unsupported", "Unsupported CoAP code profile"},
		{"reserved-option-0", "400100010178", "malformed", "Reserved CoAP option number"},
		{"reserved-option-128", "40010001d073", "malformed", "Reserved CoAP option number"},
		{"uri-port-too-long", "4001000173001633", "malformed", "CoAP option length outside its format"},
		{"if-none-match-with-value", "400300015178", "malformed", "CoAP option length outside its format"},
		{"uri-host-empty", "4001000130ff78", "malformed", "CoAP option length outside its format"},
		{"content-format-twice", "40020001c000ff78", "malformed", "Repeated non-repeatable CoAP option"},
	} {
		data, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := coapDatagram(data, Limits{})
		if c.kind == "" {
			if err != nil || got == nil || got.Protocol != "coap" {
				t.Errorf("%s: got %+v, %v; want coap", c.name, got, err)
			}
			continue
		}
		var perr *parsing.Error
		if !errors.As(err, &perr) || perr.Kind != c.kind || perr.Message != c.reason {
			t.Errorf("%s: got %+v, %v; want %s %q", c.name, got, err, c.kind, c.reason)
		}
	}
}
