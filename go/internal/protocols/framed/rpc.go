package framed

import (
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- ONC RPC v2 over TCP record marking (rpc.py) ---------------------------------------------------------

var rpcPrograms = map[int]string{100000: "portmap", 100003: "nfs", 100005: "mount", 100021: "nlm", 100024: "nsm", 100227: "nfs-acl", 100011: "rquota"}
var rpcProgramVersions = map[int][]int{100000: {2, 3, 4}, 100003: {2, 3, 4}, 100005: {1, 2, 3}, 100021: {1, 2, 3, 4}, 100024: {1}, 100227: {2, 3}, 100011: {1, 2}}
var rpcAccept = []string{"success", "prog-unavail", "prog-mismatch", "proc-unavail", "garbage-args", "system-err"}
var rpcFlavors = map[int]string{0: "auth-none", 1: "auth-sys", 2: "auth-short", 3: "auth-dh", 6: "rpcsec-gss"}

func rpcU32(d []byte, pos int) (int, int, error) {
	if pos+4 > len(d) {
		return 0, 0, parsing.Malformed("Truncated RPC message")
	}
	return be(d[pos : pos+4]), pos + 4, nil
}

func rpcAuthSys(body []byte) error {
	length, pos, err := rpcU32(body, 4) // after the stamp
	if err != nil {
		return err
	}
	if length > 255 {
		return parsing.Malformed("AUTH_SYS machine name too long")
	}
	padded := (length + 3) &^ 3
	if pos+padded > len(body) {
		return parsing.Malformed("Truncated AUTH_SYS machine name")
	}
	name := body[pos : pos+padded]
	if !printable(name[:length]) || !allZero(name[length:]) {
		return parsing.Malformed("AUTH_SYS machine name must be printable with zero padding")
	}
	pos += padded + 8 // uid, gid
	count, pos, err := rpcU32(body, pos)
	if err != nil {
		return err
	}
	if count > 16 {
		return parsing.Malformed("AUTH_SYS gid list exceeds the specification limit")
	}
	if pos+4*count != len(body) {
		return parsing.Malformed("AUTH_SYS body length disagrees with its gid count")
	}
	return nil
}

func rpcOpaqueAuth(d []byte, pos int, verifier bool) (int, int, error) {
	flavor, pos, err := rpcU32(d, pos)
	if err != nil {
		return 0, 0, err
	}
	length, pos, err := rpcU32(d, pos)
	if err != nil {
		return 0, 0, err
	}
	if _, ok := rpcFlavors[flavor]; !ok || (verifier && flavor == 1) {
		return 0, 0, parsing.Unsupported("RPC authentication flavor outside the profile")
	}
	if length > 400 || length%4 != 0 {
		return 0, 0, parsing.Malformed("RPC opaque_auth length outside the specification")
	}
	if pos+length > len(d) {
		return 0, 0, parsing.Malformed("Truncated RPC opaque_auth")
	}
	if flavor == 0 && length > 0 {
		return 0, 0, parsing.Malformed("AUTH_NONE carries no body")
	}
	if flavor == 1 {
		if err := rpcAuthSys(d[pos : pos+length]); err != nil {
			return 0, 0, err
		}
	}
	return flavor, pos + length, nil
}

type rpcMessage struct {
	end             int
	rows            []parsing.Row
	reason, scope   string
	trailingAllowed bool
}

// rpcParse ports rpc.message: one RPC message; the end of its header and what it reports.
func rpcParse(d []byte) (*rpcMessage, error) {
	if len(d) < 12 {
		return nil, parsing.Malformed("RPC message shorter than its header")
	}
	kind, pos, _ := rpcU32(d, 4)
	var err error
	if kind == 0 {
		var version, program, programVersion, procedure int
		for _, target := range []*int{&version, &program, &programVersion, &procedure} {
			if *target, pos, err = rpcU32(d, pos); err != nil {
				return nil, err
			}
			if target == &version && version != 2 {
				return nil, parsing.Unsupported("Only RPC version 2 is supported")
			}
		}
		name, known := rpcPrograms[program]
		if known {
			found := false
			for _, v := range rpcProgramVersions[program] {
				if v == programVersion {
					found = true
				}
			}
			if !found {
				return nil, parsing.Unsupported("RPC program version outside the known range")
			}
		} else if program == 0 || programVersion > 255 {
			return nil, parsing.Malformed("RPC program or version outside the profile")
		}
		if procedure > 65535 {
			return nil, parsing.Malformed("RPC procedure number outside the profile")
		}
		credential, next, err := rpcOpaqueAuth(d, pos, false)
		if err != nil {
			return nil, err
		}
		if _, pos, err = rpcOpaqueAuth(d, next, true); err != nil {
			return nil, err
		}
		if !known {
			name = "other"
		}
		return &rpcMessage{end: pos, rows: []parsing.Row{row("rpc_message", "call", "rpc_header", "structural"),
			row("rpc_program", name, "rpc_header", "structural"), row("rpc_program_version", strconv.Itoa(programVersion), "rpc_header", "structural"),
			row("rpc_credential", rpcFlavors[credential], "rpc_header", "asserted")},
			reason: "ONC RPC v2 call header and authentication structures validated; arguments not decoded", scope: "initial_message", trailingAllowed: true}, nil
	}
	if kind != 1 {
		return nil, parsing.Unsupported("RPC message type outside CALL/REPLY")
	}
	status, pos, err := rpcU32(d, pos)
	if err != nil {
		return nil, err
	}
	versionRange := func() error {
		var low, high int
		if low, pos, err = rpcU32(d, pos); err != nil {
			return err
		}
		if high, pos, err = rpcU32(d, pos); err != nil {
			return err
		}
		if low > high {
			return parsing.Malformed("RPC version range inverted")
		}
		return nil
	}
	if status == 0 {
		if _, pos, err = rpcOpaqueAuth(d, pos, true); err != nil {
			return nil, err
		}
		accepted := 0
		if accepted, pos, err = rpcU32(d, pos); err != nil {
			return nil, err
		}
		if accepted > 5 {
			return nil, parsing.Malformed("RPC accept status outside the specification")
		}
		if accepted == 2 {
			if err := versionRange(); err != nil {
				return nil, err
			}
		}
		return &rpcMessage{end: pos, rows: []parsing.Row{row("rpc_message", "reply", "rpc_header", "structural"), row("rpc_reply", "accepted", "rpc_header", "structural"),
			row("rpc_accept_status", rpcAccept[accepted], "rpc_header", "structural")},
			reason: "ONC RPC v2 accepted reply validated; results not decoded", scope: "response_header", trailingAllowed: accepted == 0}, nil
	}
	if status != 1 {
		return nil, parsing.Malformed("RPC reply status outside the specification")
	}
	rejected := 0
	if rejected, pos, err = rpcU32(d, pos); err != nil {
		return nil, err
	}
	label := "rpc-mismatch"
	switch rejected {
	case 0:
		if err := versionRange(); err != nil {
			return nil, err
		}
	case 1:
		authStatus := 0
		if authStatus, pos, err = rpcU32(d, pos); err != nil {
			return nil, err
		}
		if authStatus < 1 || authStatus > 14 {
			return nil, parsing.Malformed("RPC authentication status outside the specification")
		}
		label = "auth-error"
	default:
		return nil, parsing.Malformed("RPC reject status outside the specification")
	}
	return &rpcMessage{end: pos, rows: []parsing.Row{row("rpc_message", "reply", "rpc_header", "structural"), row("rpc_reply", "denied", "rpc_header", "structural"),
		row("rpc_reject_status", label, "rpc_header", "structural")}, reason: "ONC RPC v2 denied reply validated", scope: "response_header"}, nil
}

// NewRPC creates the TCP record-marking parser (one last-fragment record).
func NewRPC(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			mark := be(h[:4])
			if mark&0x80000000 == 0 {
				return 0, parsing.Unsupported("Multi-fragment RPC records are outside the profile")
			}
			size := mark & 0x7fffffff
			if size < 20 {
				return 0, parsing.Malformed("RPC record too short for a message")
			}
			return 4 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			body := d[4:]
			m, err := rpcParse(body)
			if err != nil {
				return nil, err
			}
			if m.end != len(body) && !m.trailingAllowed {
				return nil, parsing.Malformed("Bytes after an RPC message that carries no results")
			}
			return &parsing.Result{ProtocolName: "onc-rpc/2", Scope: m.scope, Extra: m.rows, Reason: m.reason}, nil
		}})
}

// --- Diameter capabilities exchange (diameter.py) ----------------------------------------------------------

const (
	diameterOriginHost  = 264
	diameterOriginRealm = 296
	diameterHostIP      = 257
	diameterVendorID    = 266
	diameterProductName = 269
	diameterResultCode  = 268
)

var diameterUnsigned32 = map[int]bool{258: true, 259: true, 265: true, 266: true, 267: true, 268: true, 278: true, 299: true}
var diameterOnce = map[int]bool{264: true, 296: true, 266: true, 269: true, 268: true, 267: true, 278: true}
var diameterRequired = []int{diameterOriginHost, diameterOriginRealm, diameterHostIP, diameterVendorID, diameterProductName}

func diameterResultClass(code int) string {
	if code < 1000 || code > 5999 {
		return "other"
	}
	switch code / 1000 {
	case 1:
		return "informational"
	case 2:
		return "success"
	case 3:
		return "protocol-error"
	case 4:
		return "transient-failure"
	}
	return "permanent-failure"
}

func diameterAVP(code int, flags byte, value []byte, result int) (int, error) {
	switch {
	case diameterUnsigned32[code]:
		if len(value) != 4 {
			return 0, parsing.Malformed("Diameter Unsigned32 AVP with the wrong length")
		}
		if code == diameterResultCode {
			result = be(value)
			if diameterResultClass(result) == "other" {
				return 0, parsing.Malformed("Diameter Result-Code outside the specification ranges")
			}
		}
	case code == diameterOriginHost || code == diameterOriginRealm || code == diameterProductName:
		bad := len(value) < 1 || len(value) > 255
		space := false
		for _, b := range value {
			if b < 0x20 || b == 0x7f {
				bad = true
			}
			if b == 0x20 {
				space = true
			}
		}
		if bad {
			return 0, parsing.Malformed("Diameter identity or name outside the profile")
		}
		if code != diameterProductName && space {
			return 0, parsing.Malformed("DiameterIdentity must not contain spaces")
		}
	case code == diameterHostIP:
		family := 0
		if len(value) >= 2 {
			family = be(value[:2])
		}
		if !(family == 1 && len(value) == 6) && !(family == 2 && len(value) == 18) {
			return 0, parsing.Malformed("Host-IP-Address must be an IPv4 or IPv6 Address AVP")
		}
	}
	if (code == diameterOriginHost || code == diameterOriginRealm || code == diameterVendorID || code == diameterProductName) && flags&0x40 == 0 {
		return 0, parsing.Malformed("Mandatory Diameter AVP without the M flag")
	}
	return result, nil
}

// NewDiameter creates the CER/CEA parser.
func NewDiameter(maxBytes, maxHeaders int) *Parser {
	var request bool
	budget := maxHeaders
	if budget > 128 {
		budget = 128
	}
	return newParser(maxBytes, spec{header: 20,
		size: func(h []byte) (int, error) {
			if h[0] != 1 {
				return 0, parsing.Unsupported("Diameter profile requires protocol version 1")
			}
			size, flags := be(h[1:4]), h[4]
			if size < 20 || size%4 != 0 {
				return 0, parsing.Malformed("Diameter message length must be a multiple of four, at least the header")
			}
			if flags&0x0f != 0 {
				return 0, parsing.Malformed("Reserved Diameter command flags set")
			}
			if be(h[5:8]) != 257 || !allZero(h[8:12]) {
				return 0, parsing.Unsupported("Diameter profile covers the capabilities exchange on the base application only")
			}
			if flags&0x40 != 0 {
				return 0, parsing.Malformed("Capabilities exchange messages are never proxiable")
			}
			if flags&0x80 != 0 && flags&0x20 != 0 {
				return 0, parsing.Malformed("Diameter request with the error flag")
			}
			if flags&0x10 != 0 && flags&0x80 == 0 {
				return 0, parsing.Malformed("Diameter answer with the retransmission flag")
			}
			request = flags&0x80 != 0
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			pos, seen, result := 20, 0, 0
			codes := map[int]bool{}
			for pos < len(d) {
				if len(d)-pos < 8 {
					return nil, parsing.Malformed("Truncated Diameter AVP header")
				}
				code, flags, length := be(d[pos:pos+4]), d[pos+4], be(d[pos+5:pos+8])
				if flags&0x1f != 0 {
					return nil, parsing.Malformed("Reserved Diameter AVP flags set")
				}
				header := 8
				if flags&0x80 != 0 {
					header = 12
				}
				padded := (length + 3) &^ 3
				if length < header || pos+padded > len(d) {
					return nil, parsing.Malformed("Diameter AVP length outside its message")
				}
				if !allZero(d[pos+length : pos+padded]) {
					return nil, parsing.Malformed("Diameter AVP padding must be zero")
				}
				seen++
				if seen > budget {
					return nil, parsing.Budget("Diameter AVP count exceeds budget")
				}
				if flags&0x80 == 0 {
					if diameterOnce[code] && codes[code] {
						return nil, parsing.Malformed("Repeated Diameter AVP that may appear once")
					}
					var err error
					if result, err = diameterAVP(code, flags, d[pos+header:pos+length], result); err != nil {
						return nil, err
					}
					codes[code] = true
				}
				pos += padded
			}
			missing := false
			for _, code := range diameterRequired {
				if !codes[code] {
					missing = true
				}
			}
			if missing || (!request && !codes[diameterResultCode]) {
				return nil, parsing.Malformed("Diameter capabilities exchange lacks a mandatory AVP")
			}
			if request {
				return &parsing.Result{ProtocolName: "diameter", Scope: "negotiation_request", Extra: []parsing.Row{row("diameter_message", "cer", "header", "structural")},
					Reason: "Diameter CER header and mandatory AVPs validated; identities, addresses and product name not emitted"}, nil
			}
			return &parsing.Result{ProtocolName: "diameter", Scope: "negotiation_response", Extra: []parsing.Row{row("diameter_message", "cea", "header", "structural"),
				row("diameter_result", diameterResultClass(result), "avp", "structural")},
				Reason: "Diameter CEA header, result code and mandatory AVPs validated; identities, addresses and product name not emitted"}, nil
		}})
}
