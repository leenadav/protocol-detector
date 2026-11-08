package framed

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- Modbus/TCP (ics.ModbusParser) ---------------------------------------------------------------------

var modbusFixed = map[byte]int{1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 0, 8: 4, 11: 0, 12: 0, 17: 0}
var modbusExceptions = map[byte]string{1: "illegal-function", 2: "illegal-data-address", 3: "illegal-data-value", 4: "server-device-failure",
	5: "acknowledge", 6: "server-device-busy", 8: "memory-parity-error", 10: "gateway-path-unavailable", 11: "gateway-target-failed-to-respond"}

func modbusProbe(p []byte) bool {
	if len(p) < 8 || p[2] != 0 || p[3] != 0 {
		return false
	}
	length := be(p[4:6])
	return length >= 2 && length <= 254 && p[7]&0x7f >= 1
}

func modbusPublic(function byte) bool {
	if _, ok := modbusFixed[function]; ok {
		return true
	}
	switch function {
	case 15, 16, 20, 21, 22, 23, 24, 43:
		return true
	}
	return false
}

// NewModbus creates the MBAP request/response/exception parser.
func NewModbus(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if !modbusProbe(h) {
				return 0, parsing.Malformed("Invalid Modbus/TCP MBAP header")
			}
			return 6 + be(h[4:6]), nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			function, pdu := d[7], d[8:]
			if function&0x80 != 0 {
				return modbusException(function&0x7f, pdu)
			}
			if (function >= 1 && function <= 4 && len(pdu) >= 1 && len(pdu) != 4) ||
				((function == 7 || function == 11 || function == 12 || function == 17) && len(pdu) > 0) {
				return modbusResponse(function, pdu)
			}
			if fixed, ok := modbusFixed[function]; ok {
				if len(pdu) != fixed {
					return nil, parsing.Malformed("Modbus request PDU length does not match the function code")
				}
				if function >= 1 && function <= 4 {
					quantity, limit := be(pdu[2:4]), 125
					if function <= 2 {
						limit = 2000
					}
					if quantity < 1 || quantity > limit {
						return nil, parsing.Malformed("Modbus read quantity outside specification")
					}
				}
				if function == 5 && !((pdu[2] == 0 && pdu[3] == 0) || (pdu[2] == 0xff && pdu[3] == 0)) {
					return nil, parsing.Malformed("Modbus write-single-coil value must be 0x0000 or 0xff00")
				}
			} else {
				switch function {
				case 15, 16:
					if len(pdu) < 5 || len(pdu) != 5+int(pdu[4]) {
						return nil, parsing.Malformed("Modbus multiple-write byte count disagrees with PDU")
					}
				case 20, 21, 22, 23, 24, 43:
					if len(pdu) == 0 {
						return nil, parsing.Malformed("Modbus request PDU empty")
					}
				default:
					return nil, parsing.Unsupported("Modbus function code outside the public function profile")
				}
			}
			return &parsing.Result{ProtocolName: "modbus", Scope: "request_header", Extra: []parsing.Row{row("modbus_pdu", "request", "mbap", "structural")},
				Reason: "Modbus/TCP MBAP header and request PDU shape validated; register semantics unverified"}, nil
		}})
}

func modbusResponse(function byte, pdu []byte) (*parsing.Result, error) {
	switch function {
	case 1, 2, 3, 4, 12, 17:
		count := int(pdu[0])
		if len(pdu) != 1+count || count == 0 {
			return nil, parsing.Malformed("Modbus response byte count disagrees with the PDU")
		}
		if (function == 3 || function == 4) && (count%2 != 0 || count > 250) {
			return nil, parsing.Malformed("Modbus register response needs an even byte count of at most 250")
		}
		if (function == 1 || function == 2) && count > 250 {
			return nil, parsing.Malformed("Modbus coil response exceeds 250 bytes")
		}
	case 7:
		if len(pdu) != 1 {
			return nil, parsing.Malformed("Modbus exception-status response carries one byte")
		}
	default:
		if len(pdu) != 4 {
			return nil, parsing.Malformed("Modbus comm-event-counter response carries four bytes")
		}
	}
	return &parsing.Result{ProtocolName: "modbus", Scope: "response_header", Extra: []parsing.Row{row("modbus_pdu", "response", "mbap", "structural")},
		Reason: "Modbus/TCP MBAP header and response PDU shape validated; values not emitted, request unverified"}, nil
}

func modbusException(function byte, pdu []byte) (*parsing.Result, error) {
	if !modbusPublic(function) {
		return nil, parsing.Unsupported("Modbus exception for a function code outside the public profile")
	}
	if len(pdu) != 1 || pdu[0] < 1 || pdu[0] > 11 || pdu[0] == 9 {
		return nil, parsing.Malformed("Modbus exception response carries one exception code 1..11")
	}
	label, ok := modbusExceptions[pdu[0]]
	if !ok {
		label = "other"
	}
	return &parsing.Result{ProtocolName: "modbus", Scope: "response_header", Extra: []parsing.Row{row("modbus_pdu", "exception", "mbap", "structural"),
		row("modbus_exception", label, "mbap", "asserted")}, Reason: "Modbus/TCP exception response validated; exception code reported, request unverified"}, nil
}

// --- DNP3 link frame (ics.DNP3Parser) -------------------------------------------------------------------

func dnp3CRC(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// NewDNP3 creates the data-link frame parser with header and block CRCs.
func NewDNP3(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 10,
		size: func(h []byte) (int, error) {
			if h[0] != 0x05 || h[1] != 0x64 {
				return 0, parsing.Malformed("Invalid DNP3 start bytes")
			}
			length := int(h[2])
			if length < 5 {
				return 0, parsing.Malformed("DNP3 length below header size")
			}
			if dnp3CRC(h[:8]) != binary.LittleEndian.Uint16(h[8:10]) {
				return 0, parsing.Malformed("DNP3 header CRC mismatch")
			}
			user := length - 5
			return 10 + user + 2*((user+15)/16), nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			switch d[3] & 0x0f {
			case 0, 1, 2, 3, 4, 9, 11, 0x0f:
			default:
				return nil, parsing.Unsupported("DNP3 link function code outside profile")
			}
			pos, remaining := 10, int(d[2])-5
			for remaining > 0 {
				chunk := remaining
				if chunk > 16 {
					chunk = 16
				}
				if dnp3CRC(d[pos:pos+chunk]) != binary.LittleEndian.Uint16(d[pos+chunk:pos+chunk+2]) {
					return nil, parsing.Malformed("DNP3 data block CRC mismatch")
				}
				pos += chunk + 2
				remaining -= chunk
			}
			return &parsing.Result{ProtocolName: "dnp3", Scope: "protocol_header", Reason: "DNP3 link frame header and block CRCs validated; application fragments not decoded"}, nil
		}})
}

// --- EtherNet/IP encapsulation (ics.ENIPParser) ------------------------------------------------------------

var enipCommands = map[int]string{0x0004: "list_services", 0x0063: "list_identity", 0x0064: "list_interfaces", 0x0065: "register_session",
	0x0066: "unregister_session", 0x006f: "send_rr_data", 0x0070: "send_unit_data"}

// NewENIP creates the encapsulation-header parser.
func NewENIP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 24,
		size: func(h []byte) (int, error) {
			command, length := le16(h[0:2]), le16(h[2:4])
			session, status := binary.LittleEndian.Uint32(h[4:8]), binary.LittleEndian.Uint32(h[8:12])
			if _, ok := enipCommands[command]; !ok {
				return 0, parsing.Unsupported("EtherNet/IP command outside profile")
			}
			if status != 0 || !allZero(h[20:24]) {
				return 0, parsing.Malformed("EtherNet/IP request requires zero status and options")
			}
			if command == 0x0065 && (length != 4 || session != 0) {
				return 0, parsing.Malformed("EtherNet/IP RegisterSession requires a four-byte body and zero session handle")
			}
			if (command == 0x0004 || command == 0x0063 || command == 0x0064) && length != 0 {
				return 0, parsing.Malformed("EtherNet/IP list requests carry no data")
			}
			if (command == 0x006f || command == 0x0070) && (length < 6 || session == 0) {
				return 0, parsing.Malformed("EtherNet/IP data commands require a session handle and CPF body")
			}
			if length > 65511 {
				return 0, parsing.Malformed("EtherNet/IP length outside encapsulation limit")
			}
			return 24 + length, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			command := le16(d[:2])
			if command == 0x0065 && !bytes.Equal(d[24:28], []byte{1, 0, 0, 0}) {
				return nil, parsing.Malformed("EtherNet/IP RegisterSession protocol version must be 1 with zero options")
			}
			return &parsing.Result{ProtocolName: "ethernet-ip", Scope: "protocol_header",
				Extra:  []parsing.Row{row("enip_command", enipCommands[command], "encapsulation_header", "structural")},
				Reason: "EtherNet/IP encapsulation header validated; CIP payload not decoded"}, nil
		}})
}

// --- IEC 60870-5-104 APCI (ics.IEC104Parser) ---------------------------------------------------------------

// NewIEC104 creates the APCI parser.
func NewIEC104(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 6,
		size: func(h []byte) (int, error) {
			if h[0] != 0x68 {
				return 0, parsing.Malformed("Invalid IEC 104 start byte")
			}
			length := int(h[1])
			if length < 4 || length > 253 {
				return 0, parsing.Malformed("IEC 104 APDU length outside 4..253")
			}
			control := h[2]
			switch control & 3 {
			case 3:
				if length != 4 || h[3] != 0 || h[4] != 0 || h[5] != 0 {
					return 0, parsing.Malformed("IEC 104 U-format frame must be four bytes with zero reserved octets")
				}
				if bits.OnesCount8(control>>2) != 1 {
					return 0, parsing.Malformed("IEC 104 U-format must carry exactly one function bit")
				}
			case 1:
				if length != 4 || h[3] != 0 {
					return 0, parsing.Malformed("IEC 104 S-format frame invalid")
				}
			default:
				if length < 6 {
					return 0, parsing.Malformed("IEC 104 I-format frame requires an ASDU")
				}
			}
			return 2 + length, nil
		},
		validate: func([]byte) (*parsing.Result, error) {
			return &parsing.Result{ProtocolName: "iec-104", Scope: "protocol_header", Reason: "IEC 60870-5-104 APCI validated; ASDU contents not decoded"}, nil
		}})
}

// --- S7comm over COTP data TPDUs (s7.py; hint or the cotp-connect shift only) ----------------------------------

var s7Rosctr = map[byte]string{1: "job", 2: "ack", 3: "ack_data", 7: "userdata"}
var s7Functions = map[byte]string{0x00: "cpu_services", 0x04: "read_var", 0x05: "write_var", 0x1a: "request_download", 0x1b: "download_block",
	0x1c: "download_ended", 0x1d: "start_upload", 0x1e: "upload", 0x1f: "end_upload", 0x28: "plc_control", 0x29: "plc_stop", 0xf0: "setup_communication"}
var s7PDUSizes = map[int]bool{240: true, 480: true, 960: true, 1920: true, 2048: true, 4096: true, 8192: true}

// NewS7 creates the S7comm PDU parser.
func NewS7(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 7,
		size: func(h []byte) (int, error) {
			if h[0] != 3 || h[1] != 0 {
				return 0, parsing.Malformed("Invalid TPKT header before S7 PDU")
			}
			size := be(h[2:4])
			if h[4] != 0x02 || h[5] != 0xf0 || h[6] != 0x80 {
				return 0, parsing.Unsupported("S7comm requires a COTP data TPDU (class 0, single TPDU) after the connection")
			}
			if size < 17 || size > 8192 {
				return 0, parsing.Malformed("TPKT length outside the S7 PDU profile")
			}
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			pdu := d[7:]
			if pdu[0] != 0x32 {
				return nil, parsing.Unsupported("S7 protocol id must be 0x32")
			}
			rosctr := pdu[1]
			label, ok := s7Rosctr[rosctr]
			if !ok {
				return nil, parsing.Malformed("S7 ROSCTR outside job/ack/ack-data/userdata")
			}
			if pdu[2] != 0 || pdu[3] != 0 {
				return nil, parsing.Malformed("S7 reserved field must be zero")
			}
			parameters, payload := be(pdu[6:8]), be(pdu[8:10])
			header := 10
			if rosctr == 2 || rosctr == 3 {
				header = 12
			}
			if header+parameters+payload != len(pdu) {
				return nil, parsing.Malformed("S7 parameter and data lengths disagree with the PDU")
			}
			evidence := []parsing.Row{row("s7_rosctr", label, "s7_header", "structural")}
			switch {
			case rosctr == 1 || rosctr == 3:
				if parameters < 1 {
					return nil, parsing.Malformed("S7 job/ack-data requires a parameter block")
				}
				function := pdu[header]
				name, known := s7Functions[function]
				if !known {
					return nil, parsing.Unsupported("S7 function code outside the public profile")
				}
				if function == 0xf0 {
					if parameters != 8 || pdu[header+1] != 0 {
						return nil, parsing.Malformed("S7 setup communication parameter must be eight bytes")
					}
					calling, called, length := be(pdu[header+2:header+4]), be(pdu[header+4:header+6]), be(pdu[header+6:header+8])
					if calling < 1 || calling > 255 || called < 1 || called > 255 || !s7PDUSizes[length] {
						return nil, parsing.Malformed("S7 setup communication queues or PDU length outside profile")
					}
				}
				if rosctr == 3 && pdu[10] > 0x8f {
					return nil, parsing.Malformed("S7 error class outside profile")
				}
				evidence = append(evidence, row("s7_function", name, "s7_header", "structural"))
			case rosctr == 7 && parameters < 8:
				return nil, parsing.Malformed("S7 userdata parameter block too short")
			}
			return &parsing.Result{ProtocolName: "s7comm", Scope: "protocol_header", Extra: evidence,
				Reason: "S7comm PDU header and parameter framing validated; addresses, values and blocks not decoded"}, nil
		}})
}

// --- OPC UA TCP connection messages (opcua.py) ---------------------------------------------------------------

const opcuaMaxString = 4096
const opcuaMaxMessage = 8 + 4 + opcuaMaxString + 4 + opcuaMaxString

var opcuaKinds = map[string]string{"HEL": "hello", "ACK": "acknowledge", "ERR": "error", "RHE": "reverse-hello"}

func opcuaProbe(p []byte) bool {
	if len(p) < 8 || p[3] != 'F' || p[6] != 0 || p[7] != 0 {
		return false
	}
	if _, ok := opcuaKinds[string(p[:3])]; !ok {
		return false
	}
	size := int(binary.LittleEndian.Uint32(p[4:8]))
	return size >= 8 && size <= opcuaMaxMessage
}

func opcuaString(d []byte, pos int, what string, scheme string) (int, error) {
	if pos+4 > len(d) {
		return 0, parsing.Malformed(what + " length field truncated")
	}
	length := int(int32(binary.LittleEndian.Uint32(d[pos : pos+4])))
	pos += 4
	if length == -1 {
		if scheme != "" {
			return 0, parsing.Malformed(what + " must not be null")
		}
		return pos, nil
	}
	if length < 0 || length > opcuaMaxString || pos+length > len(d) {
		return 0, parsing.Malformed(what + " length outside the message or the 4096-byte bound")
	}
	text := d[pos : pos+length]
	if !printableASCII(text, 0x20) {
		return 0, parsing.Malformed(what + " is not printable ASCII")
	}
	if scheme != "" && !bytes.HasPrefix(text, []byte(scheme)) {
		return 0, parsing.Unsupported(what + " does not use the opc.tcp scheme")
	}
	return pos + length, nil
}

// NewOPCUA creates the HEL/ACK/ERR/RHE parser.
func NewOPCUA(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if !opcuaProbe(h) {
				return 0, parsing.Malformed("OPC UA connection message header invalid")
			}
			return int(binary.LittleEndian.Uint32(h[4:8])), nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			kind := opcuaKinds[string(d[:3])]
			r := &parsing.Result{ProtocolName: "opcua", Scope: "negotiation_request", Extra: []parsing.Row{row("opcua_message", kind, "header", "structural")}}
			var end int
			var err error
			switch kind {
			case "hello", "acknowledge":
				if len(d) < 28 {
					return nil, parsing.Malformed("OPC UA hello/acknowledge shorter than its fixed fields")
				}
				version := binary.LittleEndian.Uint32(d[8:12])
				receive, send := binary.LittleEndian.Uint32(d[12:16]), binary.LittleEndian.Uint32(d[16:20])
				if receive < 8192 || send < 8192 {
					return nil, parsing.Malformed("OPC UA buffer sizes must be at least 8192 bytes")
				}
				if kind == "hello" {
					if end, err = opcuaString(d, 28, "OPC UA endpoint URL", "opc.tcp://"); err != nil {
						return nil, err
					}
					r.Reason = "OPC UA Hello validated; endpoint URL not emitted, secure channel unverified"
				} else {
					end = 28
					r.Scope = "negotiation_response"
					r.Reason = "OPC UA Acknowledge validated; negotiated limits unauthenticated"
				}
				r.Extra = append(r.Extra, row("opcua_protocol_version", strconv.FormatUint(uint64(version), 10), "header", "asserted"))
			case "error":
				if len(d) < 16 {
					return nil, parsing.Malformed("OPC UA error shorter than its fixed fields")
				}
				if d[11]&0x80 == 0 {
					return nil, parsing.Malformed("OPC UA error message must carry a Bad status code")
				}
				if end, err = opcuaString(d, 12, "OPC UA error reason", ""); err != nil {
					return nil, err
				}
				r.Scope = "negotiation_response"
				r.Reason = "OPC UA Error validated; status code and reason not emitted"
			default:
				if end, err = opcuaString(d, 8, "OPC UA server URI", ""); err != nil {
					return nil, err
				}
				if end, err = opcuaString(d, end, "OPC UA endpoint URL", "opc.tcp://"); err != nil {
					return nil, err
				}
				r.Reason = "OPC UA ReverseHello validated; server URI and endpoint URL not emitted"
			}
			if end != len(d) {
				return nil, parsing.Malformed("OPC UA message size disagrees with its fields")
			}
			return r, nil
		}})
}
