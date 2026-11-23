package framed

import (
	"bytes"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// IKEv2 IKE_SA_INIT (protocol_engine/ikev2.py; RFC 7296/5282/4868): the initiator's offer or the responder's single
// selected proposal, with KE and nonce, optional NAT-detection, cookie and capability notifications, CERTREQ and
// Vendor ID, after an optional non-ESP marker. Plaintext negotiation framing only: no crypto, peer identity or
// IPsec data. Every payload, proposal and transform spends one unit of a min(max_headers, 128) work budget.

var (
	ikeGroupBytes  = map[int]int{14: 256, 15: 384, 16: 512, 17: 768, 18: 1024}
	ikePRFNonceMin = map[int]int{2: 16, 5: 16, 6: 24, 7: 32}
)

func ikeU16(data []byte, at int) int { return int(data[at])<<8 | int(data[at+1]) }

// ikeHeaderAt ports _header_at: version 2.0, exchange 34, message id 0; initiator (flags I, responder SPI zero)
// or responder (flags R, both SPIs nonzero).
func ikeHeaderAt(data []byte, start int) bool {
	if len(data) < start+28 || data[start+17] != 32 || data[start+18] != 34 || !anyIn(data[start+16], 33, 34, 40, 41, 43) ||
		anyNonZero(data, start+20, start+24) {
		return false
	}
	if data[start+19] == 8 {
		return !anyNonZero(data, start+8, start+16)
	}
	return data[start+19] == 0x20 && anyNonZero(data, start+8, start+16)
}

func anyIn(b byte, values ...byte) bool {
	for _, v := range values {
		if b == v {
			return true
		}
	}
	return false
}

type ikeBudget struct{ remaining int }

func (b *ikeBudget) spend(count int) error {
	b.remaining -= count
	if b.remaining < 0 {
		return parsing.Budget("IKE payload/proposal/transform work budget exceeded")
	}
	return nil
}

// ikeSA ports _sa: proposals of IKE transforms; a responder's SA carries exactly one proposal with one transform
// per type. It returns the offered MODP groups and the nonce size the strongest PRF requires.
func ikeSA(data []byte, budget *ikeBudget, single bool) (map[int]bool, int, error) {
	pos, number, nonceMin := 0, 0, 16
	groups := map[int]bool{}
	for pos < len(data) {
		if err := budget.spend(1); err != nil {
			return nil, 0, err
		}
		number++
		if single && number > 1 {
			return nil, 0, parsing.Malformed("IKE responder SA must carry exactly one proposal")
		}
		if len(data)-pos < 8 {
			return nil, 0, parsing.Malformed("Truncated IKE proposal header")
		}
		size := ikeU16(data, pos+2)
		end := pos + size
		if size < 8 || end > len(data) {
			return nil, 0, parsing.Malformed("IKE proposal length outside SA payload")
		}
		want := byte(0)
		if end < len(data) {
			want = 2
		}
		if data[pos] != want || data[pos+1] != 0 {
			return nil, 0, parsing.Malformed("Invalid IKE proposal chaining or reserved byte")
		}
		// Go-only divergence (Codex PRO-17, PRO-201): RFC 7296 3.3.1 has the responder's single proposal carry the
		// number of the initiator's proposal it accepted, so a response may select proposal 2 or later; the Python
		// reference requires 1. Proposal numbers start at one, so 0 stays malformed.
		if single && data[pos+4] == 0 {
			return nil, 0, parsing.Malformed("IKE responder proposal number must be nonzero")
		}
		if !single && int(data[pos+4]) != number {
			return nil, 0, parsing.Malformed("IKE proposal numbers must begin at one and increase")
		}
		if data[pos+5] != 1 || data[pos+6] != 0 {
			return nil, 0, parsing.Unsupported("IKE initial proposal requires IKE protocol and no inner SPI")
		}
		count := int(data[pos+7])
		if count == 0 {
			return nil, 0, parsing.Malformed("Empty IKE transform list")
		}
		if err := budget.spend(count); err != nil {
			return nil, 0, err
		}
		pos += 8
		types := map[int]bool{}
		cbc, aead := false, false
		for index := 0; index < count; index++ {
			if end-pos < 8 {
				return nil, 0, parsing.Malformed("Truncated IKE transform header")
			}
			size := ikeU16(data, pos+2)
			stop := pos + size
			if size < 8 || stop > end {
				return nil, 0, parsing.Malformed("IKE transform length outside proposal")
			}
			chain := byte(0)
			if index+1 < count {
				chain = 3
			}
			if data[pos] != chain || data[pos+1] != 0 || data[pos+5] != 0 {
				return nil, 0, parsing.Malformed("Invalid IKE transform chaining or reserved bytes")
			}
			kind, value := int(data[pos+4]), ikeU16(data, pos+6)
			attributes := data[pos+8 : stop]
			if kind == 1 {
				if value != 12 && value != 18 && value != 19 && value != 20 {
					return nil, 0, parsing.Unsupported("IKE encryption offer outside AES-CBC/GCM profile")
				}
				if len(attributes) != 4 || attributes[0] != 0x80 || attributes[1] != 0x0e {
					return nil, 0, parsing.Malformed("IKE AES requires one TV key-length attribute (128/192/256)")
				}
				if bits := ikeU16(attributes, 2); bits != 128 && bits != 192 && bits != 256 {
					return nil, 0, parsing.Malformed("IKE AES requires one TV key-length attribute (128/192/256)")
				}
				if value == 12 {
					cbc = true
				} else {
					aead = true
				}
			} else {
				if len(attributes) > 0 {
					return nil, 0, parsing.Unsupported("IKE profile excludes attributes on non-encryption transforms")
				}
				switch kind {
				case 2:
					need, ok := ikePRFNonceMin[value]
					if !ok {
						return nil, 0, parsing.Unsupported("IKE PRF offer outside HMAC-SHA profile")
					}
					if need > nonceMin {
						nonceMin = need
					}
				case 3:
					if value != 2 && value != 12 && value != 13 && value != 14 {
						return nil, 0, parsing.Unsupported("IKE integrity offer outside HMAC-SHA profile")
					}
				case 4:
					if _, ok := ikeGroupBytes[value]; !ok {
						return nil, 0, parsing.Unsupported("IKE DH offer outside MODP groups14..18")
					}
					groups[value] = true
				default:
					return nil, 0, parsing.Unsupported("IKE transform type outside supported initial profile")
				}
			}
			types[kind] = true
			pos = stop
		}
		if pos != end {
			return nil, 0, parsing.Malformed("Trailing bytes or wrong transform count in IKE proposal")
		}
		if !types[1] || !types[2] || !types[4] {
			return nil, 0, parsing.Malformed("IKE proposal missing encryption, PRF or DH offers")
		}
		if single && count != len(types) {
			return nil, 0, parsing.Malformed("IKE responder proposal must select one transform per type")
		}
		if cbc == aead {
			return nil, 0, parsing.Unsupported("Mixed CBC/AEAD in one IKE proposal is outside this profile")
		}
		if cbc != types[3] {
			return nil, 0, parsing.Malformed("IKE CBC needs integrity; AEAD-only proposals must omit it")
		}
	}
	if number == 0 {
		return nil, 0, parsing.Malformed("Empty IKE SA proposal list")
	}
	return groups, nonceMin, nil
}

func init() { datagramValidators["ikev2"] = ikev2Datagram }

// ikev2Datagram ports ikev2.ikev2.
func ikev2Datagram(data []byte, limits Limits) (*Datagram, error) {
	start := 0
	switch {
	case ikeHeaderAt(data, 0):
	case len(data) >= 4 && bytes.Equal(data[:4], make([]byte, 4)) && ikeHeaderAt(data, 4):
		start = 4
	default:
		return nil, parsing.Unsupported("Outside IKEv2 initial initiator header profile")
	}
	if !anyNonZero(data, start, start+8) {
		return nil, parsing.Malformed("IKE initiator SPI must be nonzero")
	}
	response := data[start+19] == 0x20
	size := be(data[start+24 : start+28])
	if size+start > limits.MaxBytes {
		return nil, parsing.Budget("Declared IKE message exceeds byte budget")
	}
	if size < 28 || size != len(data)-start {
		return nil, parsing.Malformed("IKE message length must exactly occupy datagram after optional marker")
	}
	budget := &ikeBudget{remaining: minInt(limits.MaxHeaders, 128)}
	kind, pos := int(data[start+16]), start+28
	seen := map[int]bool{}
	var groups map[int]bool
	nonceMin, group, nonceSize, payloadNumber := 16, -1, -1, 0
	for kind != 0 {
		if err := budget.spend(1); err != nil {
			return nil, err
		}
		payloadNumber++
		if len(data)-pos < 4 {
			return nil, parsing.Malformed("Truncated IKE generic payload header")
		}
		next, flags, size := int(data[pos]), data[pos+1], ikeU16(data, pos+2)
		end := pos + size
		if size < 4 || end > len(data) {
			return nil, parsing.Malformed("IKE payload length exceeds message")
		}
		if flags&0x7f != 0 {
			return nil, parsing.Malformed("IKE profile requires zero reserved payload bits")
		}
		body := data[pos+4 : end]
		if kind == 33 || kind == 34 || kind == 40 {
			if seen[kind] {
				return nil, parsing.Malformed("Duplicate required IKE payload")
			}
			seen[kind] = true
		}
		switch {
		case kind == 33:
			var err error
			if groups, nonceMin, err = ikeSA(body, budget, response); err != nil {
				return nil, err
			}
		case kind == 34:
			if len(body) < 4 || body[2] != 0 || body[3] != 0 {
				return nil, parsing.Malformed("Invalid IKE key-exchange header")
			}
			group = ikeU16(body, 0)
			width, ok := ikeGroupBytes[group]
			if !ok {
				return nil, parsing.Unsupported("IKE KE group outside supported MODP profile")
			}
			if len(body)-4 != width {
				return nil, parsing.Malformed("IKE public value width disagrees with MODP group")
			}
		case kind == 40:
			nonceSize = len(body)
			if nonceSize < 16 || nonceSize > 256 {
				return nil, parsing.Malformed("IKE nonce must contain16..256 bytes")
			}
		case kind == 41:
			if len(body) < 4 || body[0] != 0 || body[1] != 0 {
				return nil, parsing.Malformed("IKE initial notify requires zero protocol and SPI size")
			}
			switch notification := ikeU16(body, 2); {
			case notification == 16388 || notification == 16389:
				if len(body) != 24 {
					return nil, parsing.Malformed("IKE NAT-detection hash must contain20 bytes")
				}
			case notification == 16390:
				if response || payloadNumber != 1 || len(body)-4 < 1 || len(body)-4 > 64 {
					return nil, parsing.Malformed("IKE cookie must be first and contain1..64 bytes")
				}
			case notification >= 16404 && notification <= 16407 && response:
				if len(body) != 4 {
					return nil, parsing.Malformed("IKE responder capability notifications carry no data")
				}
			default:
				return nil, parsing.Unsupported("IKE notification outside NAT-detection/cookie profile")
			}
		case kind == 38 && response:
			if len(body) == 0 || !anyIn(body[0], 4, 12, 13) || (body[0] == 4 && (len(body)-1)%20 != 0) {
				return nil, parsing.Malformed("IKE CERTREQ requires a supported encoding and SHA-1 hash list")
			}
			if len(body) > limits.MaxLine {
				return nil, parsing.Budget("IKE CERTREQ exceeds opaque field budget")
			}
		case kind == 43:
			if len(body) == 0 {
				return nil, parsing.Malformed("Empty IKE Vendor ID")
			}
			if len(body) > limits.MaxLine {
				return nil, parsing.Budget("IKE Vendor ID exceeds opaque field budget")
			}
		default:
			return nil, parsing.Unsupported("IKE payload type outside SA_INIT request profile")
		}
		kind, pos = next, end
	}
	if pos != len(data) {
		return nil, parsing.Malformed("Bytes remain after IKE payload chain terminates")
	}
	if len(seen) != 3 {
		return nil, parsing.Malformed("IKE initial message requires SA, KE and nonce")
	}
	if !groups[group] || nonceSize < nonceMin {
		return nil, parsing.Malformed("IKE KE/nonce disagrees with algorithm proposals")
	}
	if response {
		return &Datagram{Protocol: "ikev2", Evidence: []parsing.Row{row("application_protocol", "ikev2", "wire", "structural"),
			row("exchange", "ike_sa_init_response", "wire", "structural"), row("selected_dh_group", strconv.Itoa(group), "ike_responder", "asserted")},
			Reason: "IKEv2 initial response (single proposal, KE, nonce) structure validated; selection unauthenticated, no established IPsec claim"}, nil
	}
	return &Datagram{Protocol: "ikev2", Evidence: []parsing.Row{row("application_protocol", "ikev2", "wire", "structural"),
		row("exchange", "ike_sa_init_request", "wire", "structural"), row("offered_dh_group", strconv.Itoa(group), "ike_initiator", "asserted")},
		Reason: "IKEv2 initial proposal/KE/nonce structure validated; offers unauthenticated, no established IPsec or encrypted payload claim"}, nil
}
