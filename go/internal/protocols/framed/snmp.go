package framed

import (
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

func init() {
	DatagramValidators["snmp"] = snmpDatagram
	DatagramValidators["rtp"] = rtpDatagram
}

// --- BER helpers (framing.ber_length / ber_field) ---------------------------------------------------------

func berLength(data []byte, pos, limit int) (int, int, error) {
	if pos >= limit {
		return 0, 0, parsing.Malformed("Truncated BER length")
	}
	first := int(data[pos])
	pos++
	if first < 128 {
		return first, pos, nil
	}
	width := first & 127
	if width < 1 || width > 4 || pos+width > limit {
		return 0, 0, parsing.Malformed("Unsupported indefinite or truncated BER length")
	}
	return be(data[pos : pos+width]), pos + width, nil
}

func berField(data []byte, pos, limit int, expected byte) ([]byte, int, error) {
	if pos >= limit || data[pos] != expected {
		return nil, 0, parsing.Malformed("Unexpected BER field tag")
	}
	size, start, err := berLength(data, pos+1, limit)
	if err != nil {
		return nil, 0, err
	}
	if start+size > limit {
		return nil, 0, parsing.Malformed("BER field exceeds enclosing length")
	}
	return data[start : start+size], start + size, nil
}

// --- SNMP v1/v2c/v3 (network.snmp) ---------------------------------------------------------------------------

func snmpInteger(data []byte, pos int) (int, int, error) {
	value, end, err := berField(data, pos, len(data), 2)
	if err != nil {
		return 0, 0, err
	}
	if len(value) < 1 || len(value) > 4 {
		return 0, 0, parsing.Malformed("SNMP integer outside signed 32-bit profile")
	}
	n := int64(int8(value[0]))
	for _, b := range value[1:] {
		n = n<<8 | int64(b)
	}
	return int(n), end, nil
}

func snmpOID(value []byte) error {
	if len(value) == 0 {
		return parsing.Malformed("Empty SNMP object identifier")
	}
	var number uint64
	count, beginning := 0, true
	for _, b := range value {
		if beginning && b == 128 {
			return parsing.Malformed("Nonminimal SNMP OID subidentifier")
		}
		number = number<<7 | uint64(b&127)
		limit := uint64(0xffffffff)
		if count == 0 {
			limit += 80
		}
		if number > limit {
			return parsing.Malformed("SNMP OID subidentifier too large")
		}
		beginning = b&128 == 0
		if beginning {
			count++
			number = 0
			if count > 127 {
				return parsing.Budget("SNMP OID exceeds 128 arcs")
			}
		}
	}
	if !beginning {
		return parsing.Malformed("Truncated SNMP OID subidentifier")
	}
	return nil
}

var snmpPDUNames = map[byte]string{0xa0: "get", 0xa1: "get-next", 0xa2: "response", 0xa3: "set", 0xa4: "trap", 0xa5: "get-bulk",
	0xa6: "inform", 0xa7: "trap", 0xa8: "report"}
var snmpV1Kinds = map[byte]bool{0xa0: true, 0xa1: true, 0xa2: true, 0xa3: true, 0xa4: true}
var snmpV2Kinds = map[byte]bool{0xa0: true, 0xa1: true, 0xa2: true, 0xa3: true, 0xa5: true, 0xa6: true, 0xa7: true, 0xa8: true}
var snmpValueTags = map[byte]bool{0x02: true, 0x04: true, 0x05: true, 0x06: true, 0x40: true, 0x41: true, 0x42: true, 0x43: true, 0x44: true,
	0x46: true, 0x80: true, 0x81: true, 0x82: true}

func snmpBindings(bindings []byte, readOnly bool) error {
	pos, count := 0, 0
	for pos < len(bindings) {
		count++
		if count > 128 {
			return parsing.Budget("SNMP variable binding count exceeds limit")
		}
		binding, next, err := berField(bindings, pos, len(bindings), 0x30)
		if err != nil {
			return err
		}
		pos = next
		oid, cursor, err := berField(binding, 0, len(binding), 6)
		if err != nil {
			return err
		}
		if err := snmpOID(oid); err != nil {
			return err
		}
		if cursor >= len(binding) {
			return parsing.Malformed("SNMP binding without a value")
		}
		tag := binding[cursor]
		if readOnly {
			var null []byte
			if null, cursor, err = berField(binding, cursor, len(binding), 5); err != nil {
				return err
			}
			if len(null) > 0 {
				return parsing.Malformed("SNMP read binding must contain NULL value")
			}
		} else {
			if !snmpValueTags[tag] {
				return parsing.Malformed("SNMP binding value tag outside the SMI profile")
			}
			var value []byte
			if value, cursor, err = berField(binding, cursor, len(binding), tag); err != nil {
				return err
			}
			n := len(value)
			bad := (tag == 0x40 && n != 4) || ((tag == 0x80 || tag == 0x81 || tag == 0x82) && n > 0) || (tag == 0x05 && n > 0) ||
				((tag == 0x02 || tag == 0x41 || tag == 0x42 || tag == 0x43) && (n < 1 || n > 5)) || (tag == 0x46 && (n < 1 || n > 9))
			if bad {
				return parsing.Malformed("SNMP binding value length outside its type")
			}
		}
		if cursor != len(binding) {
			return parsing.Malformed("Trailing SNMP binding data")
		}
	}
	return nil
}

func snmpPDU(pdu []byte, kind byte) (string, error) {
	if kind == 0xa4 {
		enterprise, pos, err := berField(pdu, 0, len(pdu), 6)
		if err != nil {
			return "", err
		}
		if err := snmpOID(enterprise); err != nil {
			return "", err
		}
		agent, pos, err := berField(pdu, pos, len(pdu), 0x40)
		if err != nil {
			return "", err
		}
		if len(agent) != 4 {
			return "", parsing.Malformed("SNMPv1 trap agent address must be four bytes")
		}
		generic, pos, err := snmpInteger(pdu, pos)
		if err != nil {
			return "", err
		}
		specific, pos, err := snmpInteger(pdu, pos)
		if err != nil {
			return "", err
		}
		if generic < 0 || generic > 6 || specific < 0 {
			return "", parsing.Malformed("SNMPv1 trap codes outside their ranges")
		}
		ticks, pos, err := berField(pdu, pos, len(pdu), 0x43)
		if err != nil {
			return "", err
		}
		if len(ticks) < 1 || len(ticks) > 5 {
			return "", parsing.Malformed("SNMPv1 trap time stamp length invalid")
		}
		bindings, pos, err := berField(pdu, pos, len(pdu), 0x30)
		if err != nil {
			return "", err
		}
		if pos != len(pdu) {
			return "", parsing.Malformed("Trailing SNMPv1 trap fields")
		}
		return "trap", snmpBindings(bindings, false)
	}
	_, pos, err := snmpInteger(pdu, 0)
	if err != nil {
		return "", err
	}
	first, pos, err := snmpInteger(pdu, pos)
	if err != nil {
		return "", err
	}
	second, pos, err := snmpInteger(pdu, pos)
	if err != nil {
		return "", err
	}
	if first < 0 || second < 0 {
		return "", parsing.Malformed("Invalid SNMP request status/index or bulk counts")
	}
	switch kind {
	case 0xa0, 0xa1, 0xa3, 0xa6, 0xa7:
		if first != 0 || second != 0 {
			return "", parsing.Malformed("SNMP request error-status and error-index must be zero")
		}
	case 0xa2:
		if first > 18 {
			return "", parsing.Malformed("SNMP response error-status outside RFC 3416")
		}
	}
	bindings, pos, err := berField(pdu, pos, len(pdu), 0x30)
	if err != nil {
		return "", err
	}
	if pos != len(pdu) {
		return "", parsing.Malformed("Trailing SNMP request fields")
	}
	return snmpPDUNames[kind], snmpBindings(bindings, kind == 0xa0 || kind == 0xa1 || kind == 0xa5)
}

func snmpV3(message []byte, pos int) (*Datagram, error) {
	header, pos, err := berField(message, pos, len(message), 0x30)
	if err != nil {
		return nil, err
	}
	messageID, cursor, err := snmpInteger(header, 0)
	if err != nil {
		return nil, err
	}
	maxSize, cursor, err := snmpInteger(header, cursor)
	if err != nil {
		return nil, err
	}
	flags, cursor, err := berField(header, cursor, len(header), 4)
	if err != nil {
		return nil, err
	}
	model, cursor, err := snmpInteger(header, cursor)
	if err != nil {
		return nil, err
	}
	if cursor != len(header) {
		return nil, parsing.Malformed("Trailing SNMPv3 header data")
	}
	if messageID < 0 || maxSize < 484 || model < 1 {
		return nil, parsing.Malformed("SNMPv3 header values outside RFC 3412 ranges")
	}
	if len(flags) != 1 || flags[0]&0xf8 != 0 {
		return nil, parsing.Malformed("SNMPv3 msgFlags must be one byte with reserved bits clear")
	}
	auth, priv, reportable := flags[0]&1 != 0, flags[0]&2 != 0, flags[0]&4 != 0
	if priv && !auth {
		return nil, parsing.Malformed("SNMPv3 privacy without authentication is invalid")
	}
	params, pos, err := berField(message, pos, len(message), 4)
	if err != nil {
		return nil, err
	}
	security, discovery := "model-"+strconv.Itoa(model), false
	if model == 3 {
		usm, end, err := berField(params, 0, len(params), 0x30)
		if err != nil {
			return nil, err
		}
		if end != len(params) {
			return nil, parsing.Malformed("Trailing USM security parameter data")
		}
		var engineID, user, authParams, privParams []byte
		var boots, clock int
		c := 0
		if engineID, c, err = berField(usm, c, len(usm), 4); err != nil {
			return nil, err
		}
		if boots, c, err = snmpInteger(usm, c); err != nil {
			return nil, err
		}
		if clock, c, err = snmpInteger(usm, c); err != nil {
			return nil, err
		}
		for _, target := range []*[]byte{&user, &authParams, &privParams} {
			if *target, c, err = berField(usm, c, len(usm), 4); err != nil {
				return nil, err
			}
		}
		if c != len(usm) || len(engineID) > 32 || len(user) > 32 || len(authParams) > 64 || len(privParams) > 32 || boots < 0 || clock < 0 {
			return nil, parsing.Malformed("USM security parameters outside profile")
		}
		if auth && len(authParams) == 0 {
			return nil, parsing.Malformed("SNMPv3 authentication flag without authentication parameters")
		}
		if priv && len(privParams) == 0 {
			return nil, parsing.Malformed("SNMPv3 privacy flag without privacy parameters")
		}
		security = "usm"
		discovery = !auth && len(engineID) == 0
	} else if len(params) > 256 {
		return nil, parsing.Malformed("SNMPv3 security parameters exceed profile")
	}
	if pos >= len(message) {
		return nil, parsing.Malformed("SNMPv3 message without scoped PDU")
	}
	scope, name := "encrypted", "encrypted"
	if priv {
		encrypted, end, err := berField(message, pos, len(message), 4)
		if err != nil {
			return nil, err
		}
		if len(encrypted) == 0 || end != len(message) {
			return nil, parsing.Malformed("SNMPv3 encrypted scoped PDU framing invalid")
		}
	} else {
		scoped, end, err := berField(message, pos, len(message), 0x30)
		if err != nil {
			return nil, err
		}
		if end != len(message) {
			return nil, parsing.Malformed("Trailing SNMPv3 message data")
		}
		contextEngine, c, err := berField(scoped, 0, len(scoped), 4)
		if err != nil {
			return nil, err
		}
		contextName, c, err := berField(scoped, c, len(scoped), 4)
		if err != nil {
			return nil, err
		}
		if len(contextEngine) > 32 || len(contextName) > 32 || c >= len(scoped) {
			return nil, parsing.Malformed("SNMPv3 scoped PDU context outside profile")
		}
		kind := scoped[c]
		if !snmpV2Kinds[kind] {
			return nil, parsing.Unsupported("SNMPv3 scoped PDU kind outside the SNMPv2 PDU set")
		}
		pdu, c, err := berField(scoped, c, len(scoped), kind)
		if err != nil {
			return nil, err
		}
		if c != len(scoped) {
			return nil, parsing.Malformed("Trailing SNMPv3 scoped PDU data")
		}
		if name, err = snmpPDU(pdu, kind); err != nil {
			return nil, err
		}
		scope = "plaintext"
	}
	flagNames := ""
	for _, f := range []struct {
		on   bool
		name string
	}{{auth, "auth"}, {priv, "priv"}, {reportable, "reportable"}} {
		if f.on {
			flagNames += f.name
		}
	}
	if flagNames == "" {
		flagNames = "none"
	}
	level := "no-auth-no-priv"
	if priv {
		level = "auth-priv"
	} else if auth {
		level = "auth-no-priv"
	}
	evidence := []parsing.Row{row("application_protocol", "snmp/3", "wire", "structural"), row("snmp_pdu", name, "wire", "structural"),
		row("snmp_security", security, "wire", "structural"), row("snmp_scoped_pdu", scope, "wire", "structural"),
		row("snmp_flags", flagNames, "wire", "structural"), row("snmp_security_level", level, "wire", "structural")}
	if discovery {
		evidence = append(evidence, row("snmp_usm_discovery", "request", "wire", "structural"))
	}
	return &Datagram{Protocol: "snmp/3", Evidence: evidence,
		Reason: "SNMPv3 header, security parameter and " + scope + " scoped PDU framing validated; user, engine, keys and values unverified and never emitted"}, nil
}

func snmpDatagram(data []byte, _ Limits) (*Datagram, error) {
	message, end, err := berField(data, 0, len(data), 0x30)
	if err != nil {
		return nil, err
	}
	if end != len(data) {
		return nil, parsing.Malformed("Trailing SNMP datagram data")
	}
	version, pos, err := snmpInteger(message, 0)
	if err != nil {
		return nil, err
	}
	if version == 3 {
		return snmpV3(message, pos)
	}
	if version != 0 && version != 1 {
		return nil, parsing.Unsupported("Only SNMPv1, v2c and v3 messages are supported")
	}
	if _, pos, err = berField(message, pos, len(message), 4); err != nil { // never expose community
		return nil, err
	}
	kinds := snmpV2Kinds
	if version == 0 {
		kinds = snmpV1Kinds
	}
	if pos >= len(message) || !kinds[message[pos]] {
		return nil, parsing.Unsupported("SNMP PDU kind outside the version's PDU set")
	}
	kind := message[pos]
	pdu, pos, err := berField(message, pos, len(message), kind)
	if err != nil {
		return nil, err
	}
	if pos != len(message) {
		return nil, parsing.Malformed("Trailing SNMP PDU data")
	}
	name, err := snmpPDU(pdu, kind)
	if err != nil {
		return nil, err
	}
	protocol := "snmp/2c"
	if version == 0 {
		protocol = "snmp/1"
	}
	return wireMatch(protocol, "SNMP "+name+" BER/PDU/OID framing validated; community and values unverified and never emitted", "snmp_pdu", name), nil
}

// --- RTP fixed header (datainfra.rtp; hint only) ------------------------------------------------------------

func rtpDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 12 {
		return nil, parsing.Malformed("RTP header shorter than 12 bytes")
	}
	if data[0]>>6 != 2 {
		return nil, parsing.Unsupported("RTP profile requires version 2")
	}
	if pt := data[1] & 127; pt >= 72 && pt <= 76 {
		return nil, parsing.Unsupported("Payload type collides with RTCP packet types")
	}
	pos := 12 + 4*int(data[0]&15)
	if pos > len(data) {
		return nil, parsing.Malformed("RTP CSRC list exceeds datagram")
	}
	if data[0]&0x10 != 0 {
		if pos+4 > len(data) {
			return nil, parsing.Malformed("Truncated RTP header extension")
		}
		pos += 4 + 4*be(data[pos+2:pos+4])
		if pos > len(data) {
			return nil, parsing.Malformed("RTP header extension exceeds datagram")
		}
	}
	if data[0]&0x20 != 0 {
		last := int(data[len(data)-1])
		if pos >= len(data) || last == 0 || last > len(data)-pos {
			return nil, parsing.Malformed("RTP padding count invalid")
		}
	}
	return &Datagram{Protocol: "rtp", Simple: true,
		Reason: "RTP fixed header, CSRC and extension framing validated with a candidate hint; media not decoded"}, nil
}
