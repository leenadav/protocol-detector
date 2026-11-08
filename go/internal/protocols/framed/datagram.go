package framed

import (
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Datagram is one UDP validator's success. Simple ports a Python (protocol, reason) tuple: the inspector adds the
// application_protocol row itself. Otherwise it ports a DatagramMatch, whose Evidence rows carry their final
// provenance (no "wire:" prefix is added).
type Datagram struct {
	Protocol, Encryption, Reason string
	Evidence                     []parsing.Row
	Simple                       bool
}

// DatagramValidator validates one complete UDP payload.
type DatagramValidator func(data []byte, maxBytes int) (*Datagram, error)

// DatagramValidators are the ported entries of protocol_engine/datagram.VALIDATORS (the DNS layout stays in dnsx).
var DatagramValidators = map[string]DatagramValidator{
	"syslog":    syslogDatagram,
	"onc-rpc":   rpcDatagram,
	"openvpn":   openvpnDatagram,
	"wireguard": wireguardDatagram,
	"bacnet":    bacnetDatagram,
}

func syslogDatagram(data []byte, _ int) (*Datagram, error) {
	reason, err := syslogMessage(data)
	if err != nil {
		return nil, err
	}
	return &Datagram{Protocol: "syslog/5424", Reason: reason, Simple: true}, nil
}

func rpcDatagram(data []byte, _ int) (*Datagram, error) {
	if len(data) < 20 {
		return nil, parsing.Malformed("RPC datagram too short for a message")
	}
	m, err := rpcParse(data)
	if err != nil {
		return nil, err
	}
	if m.end != len(data) && !m.trailingAllowed {
		return nil, parsing.Malformed("Bytes after an RPC message that carries no results")
	}
	evidence := []parsing.Row{row("application_protocol", "onc-rpc/2", "wire", "structural")}
	for _, r := range m.rows {
		evidence = append(evidence, row(r.Field, r.Value, "wire:"+r.Provenance, r.Strength))
	}
	return &Datagram{Protocol: "onc-rpc/2", Reason: m.reason, Evidence: evidence}, nil
}

func openvpnDatagram(data []byte, _ int) (*Datagram, error) {
	width, role, err := openvpnControl(data)
	if err != nil {
		return nil, err
	}
	auth := "absent"
	if width > 0 {
		auth = "present"
	}
	return &Datagram{Encryption: "openvpn", Evidence: []parsing.Row{row("encryption", "openvpn", "wire", "structural"),
		row("tls_auth", auth, "wire", "structural"), row("openvpn_control", role+"-hard-reset", "wire", "structural")},
		Reason: "OpenVPN " + role + " hard-reset control packet validated; no key exchange or tunnel claim"}, nil
}

var wireguardMessages = map[byte]struct {
	size int
	kind string
}{1: {148, "handshake_initiation"}, 2: {92, "handshake_response"}, 3: {64, "cookie_reply"}}

func wireguardDatagram(data []byte, _ int) (*Datagram, error) {
	message, ok := wireguardMessages[0]
	if len(data) >= 4 {
		message, ok = wireguardMessages[data[0]]
	}
	if len(data) < 4 || !allZero(data[1:4]) || !ok || len(data) != message.size {
		return nil, parsing.Unsupported("Outside WireGuard handshake message sizes")
	}
	if data[0] == 1 && allZero(data[4:8]) {
		return nil, parsing.Malformed("WireGuard sender index must be nonzero")
	}
	return &Datagram{Encryption: "wireguard", Evidence: []parsing.Row{row("encryption", "wireguard", "wire", "structural"),
		row("message_type", message.kind, "wire", "structural")},
		Reason: "WireGuard handshake message size and reserved bytes validated; keys and MACs unverified, no tunnel claim"}, nil
}

// bacnetDatagram ports ics.bacnet: BVLC framing with NPDU version 1 for NPDU-carrying functions.
func bacnetDatagram(data []byte, _ int) (*Datagram, error) {
	if !(len(data) >= 4 && data[0] == 0x81 && data[1] <= 0x0c && be(data[2:4]) == len(data)) {
		return nil, parsing.Unsupported("Outside BACnet/IP BVLC framing")
	}
	switch function := data[1]; function {
	case 0x0a, 0x0b, 0x04, 0x09:
		offset := 10
		if function == 0x0a || function == 0x0b {
			offset = 4
		}
		if len(data) < offset+2 || data[offset] != 1 {
			return nil, parsing.Malformed("BACnet NPDU version must be 1")
		}
		control := data[offset+1]
		if control&0x50 != 0 {
			return nil, parsing.Malformed("BACnet NPDU reserved control bits set")
		}
		pos := offset + 2
		for _, present := range []bool{control&0x20 != 0, control&0x08 != 0} {
			if present {
				if pos+3 > len(data) {
					return nil, parsing.Malformed("Truncated BACnet NPDU address")
				}
				pos += 3 + int(data[pos+2])
			}
		}
		if control&0x20 != 0 {
			pos++ // hop count follows a destination specifier
		}
		switch {
		case control&0x80 != 0:
			if pos+1 > len(data) {
				return nil, parsing.Malformed("Truncated BACnet network message type")
			}
		case pos >= len(data):
			return nil, parsing.Malformed("BACnet NPDU without APDU")
		case data[pos]>>4 > 7:
			return nil, parsing.Malformed("BACnet APDU type reserved")
		}
	case 0x00, 0x03, 0x06, 0x08:
		if len(data) != 6 && function != 0x08 {
			return nil, parsing.Malformed("BACnet BVLC result/entry length invalid")
		}
	}
	return &Datagram{Protocol: "bacnet", Reason: "BACnet/IP BVLC and NPDU framing validated; objects and services not decoded", Simple: true}, nil
}
