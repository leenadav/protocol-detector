package framed

import (
	"bytes"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// TPKT (RFC 1006) connection requests and confirms: RDP (remote.RDPParser, MS-RDPBCGR 2.2.1.1/2.2.1.2) and ISO-TSAP
// (ics.COTPParser, X.224 with TSAP parameters, shifting to S7comm). The automatic route (ics.TPKTParser) frames
// with the TPKT bound of 11..1024 bytes and lets the bytes after the X.224 header choose; an explicit rdp hint
// frames with RDP's own 11..260. Only closed labels and counts are emitted; cookies and correlation ids are not.

var (
	rdpSecurity = [5]struct {
		bit   int
		label string
	}{{0x01, "tls"}, {0x02, "credssp"}, {0x04, "rdstls"}, {0x08, "credssp-early-user-auth"}, {0x10, "aad"}}
	rdpCredentialMode = [2]struct {
		bit   int
		label string
	}{{0x01, "restricted-admin"}, {0x02, "remote-credential-guard"}}
	rdpServerSupports = [4]struct {
		bit   int
		label string
	}{{0x01, "extended-client-data"}, {0x02, "gfx-pipeline"}, {0x08, "restricted-admin"}, {0x10, "remote-credential-guard"}}
	rdpFailures = map[int]string{1: "ssl-required", 2: "ssl-not-allowed", 3: "ssl-certificate-missing", 4: "inconsistent-flags",
		5: "hybrid-required", 6: "ssl-with-user-auth-required"}
	rdpCookie = []byte("Cookie: mstshash=")
)

func tpktSize(h []byte, max int, version, length string) (int, error) {
	if h[0] != 3 || h[1] != 0 {
		return 0, parsing.Malformed(version)
	}
	size := be(h[2:4])
	if size < 11 || size > max {
		return 0, parsing.Malformed(length)
	}
	return size, nil
}

// NewTPKT ports TPKTParser: the automatic route that resolves to rdp or iso-tsap (Result.Family).
func NewTPKT(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			return tpktSize(h, 1024, "Invalid TPKT version or reserved byte", "TPKT length outside connection request profile")
		},
		validate: func(data []byte) (*parsing.Result, error) {
			rest := data[11:]
			negotiation := len(rest) == 8 && (rest[0] == 2 || rest[0] == 3) && rest[2] == 8 && rest[3] == 0
			rdp := bytes.HasPrefix(rest, rdpCookie) || (len(rest) > 0 && rest[0] == 1) || len(rest) == 0 || (data[5] == 0xd0 && negotiation)
			var r *parsing.Result
			var err error
			if rdp {
				r, err = rdpValidate(data)
			} else {
				r, err = cotpValidate(data)
			}
			if err != nil {
				return nil, err
			}
			r.Family = r.ProtocolName
			return r, nil
		}})
}

// NewRDP ports RDPParser for an explicit rdp hint.
func NewRDP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			return tpktSize(h, 260, "Invalid TPKT version or reserved byte", "TPKT length outside X.224 connection request profile")
		},
		validate: rdpValidate})
}

// NewCOTP ports COTPParser for an explicit iso-tsap hint.
func NewCOTP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			return tpktSize(h, 1024, "Invalid TPKT version", "TPKT length outside connection request profile")
		},
		validate: cotpValidate})
}

func rdpValidate(data []byte) (*parsing.Result, error) {
	if int(data[4]) == len(data)-5 && data[5] == 0xd0 {
		return rdpConfirm(data)
	}
	if int(data[4]) != len(data)-5 || data[5] != 0xe0 || data[6] != 0 || data[7] != 0 || data[10] != 0 {
		return nil, parsing.Malformed("Invalid X.224 class-zero connection request")
	}
	pos := 11
	if bytes.HasPrefix(data[pos:], rdpCookie) {
		end := bytes.Index(data[pos:], []byte("\r\n"))
		if end < 0 {
			return nil, parsing.Malformed("Invalid RDP cookie framing")
		}
		end += pos
		for _, c := range data[pos:end] {
			if c < 32 || c == 127 {
				return nil, parsing.Malformed("Invalid RDP cookie framing")
			}
		}
		pos = end + 2
	}
	if pos == len(data) {
		return nil, parsing.Unsupported("X.224 request alone does not identify RDP; negotiation required")
	}
	if data[pos] != 1 {
		return nil, parsing.Unsupported("Unsupported X.224 routing token or negotiation type")
	}
	neg := data[pos:minInt(len(data), pos+8)]
	if len(neg) != 8 || neg[1]&^0x0b != 0 || neg[2] != 8 || neg[3] != 0 {
		return nil, parsing.Malformed("Invalid RDP negotiation header")
	}
	offered := le(neg, 4, 4)
	if offered&^0x1f != 0 {
		return nil, parsing.Unsupported("Unsupported RDP security offer flags")
	}
	pos += 8
	if neg[1]&8 != 0 {
		correlation := data[pos:minInt(len(data), pos+36)]
		if len(correlation) != 36 || !bytes.Equal(correlation[:4], []byte{6, 0, 0x24, 0}) || anyNonZero(correlation, 20, 36) {
			return nil, parsing.Malformed("Invalid RDP correlation structure")
		}
		pos += 36
	}
	if pos != len(data) {
		return nil, parsing.Malformed("Unexpected bytes after RDP negotiation")
	}
	rows := []parsing.Row{row("rdp_security_flags", strconv.Itoa(offered), "negotiation_request", "offered")}
	for _, s := range rdpSecurity {
		if offered&s.bit != 0 {
			rows = append(rows, row("rdp_offered_security", s.label, "negotiation_request", "offered"))
		}
	}
	if offered == 0 {
		rows = append(rows, row("rdp_offered_security", "standard-rdp", "negotiation_request", "offered"))
	}
	for _, m := range rdpCredentialMode {
		if int(neg[1])&3&m.bit != 0 {
			rows = append(rows, row("rdp_credential_mode", m.label, "negotiation_request", "offered"))
		}
	}
	r := &parsing.Result{ProtocolName: "rdp", Scope: "negotiation_request", Extra: rows,
		Reason: "RDP connection request and security offers validated; selected security and session unverified"}
	if offered != 0 {
		// Every offered protocol other than standard RDP security starts with TLS once the server confirms.
		r.Shift = &parsing.Shift{Boundary: "rdp-negotiation", Expected: "tls"}
	}
	return r, nil
}

// rdpConfirm: the server's X.224 Connection Confirm with RDP_NEG_RSP or RDP_NEG_FAILURE.
func rdpConfirm(data []byte) (*parsing.Result, error) {
	if (data[6] == 0 && data[7] == 0) || data[10] != 0 {
		return nil, parsing.Malformed("Invalid X.224 connection confirm")
	}
	neg := data[11:]
	if len(neg) == 0 {
		return nil, parsing.Unsupported("X.224 confirm alone does not identify RDP; negotiation response required")
	}
	if len(neg) != 8 || neg[2] != 8 || neg[3] != 0 {
		return nil, parsing.Malformed("Invalid RDP negotiation response header")
	}
	switch neg[0] {
	case 2:
		if neg[1]&^0x1f != 0 {
			return nil, parsing.Malformed("Invalid RDP negotiation response flags")
		}
		selected := le(neg, 4, 4)
		label := map[int]string{0: "standard-rdp", 1: "tls", 2: "credssp", 4: "rdstls", 8: "credssp-early-user-auth", 16: "aad"}
		name, ok := label[selected]
		if !ok {
			return nil, parsing.Malformed("RDP server must select exactly one security protocol")
		}
		rows := []parsing.Row{row("rdp_selected_protocol", strconv.Itoa(selected), "negotiation_response", "asserted"),
			row("rdp_selected_security", name, "negotiation_response", "asserted")}
		for _, s := range rdpServerSupports {
			if int(neg[1])&s.bit != 0 {
				rows = append(rows, row("rdp_server_supports", s.label, "negotiation_response", "asserted"))
			}
		}
		r := &parsing.Result{ProtocolName: "rdp", Scope: "negotiation_response", Extra: rows,
			Reason: "RDP connection confirm and selected security protocol validated; session unverified"}
		if selected != 0 {
			r.Shift = &parsing.Shift{Boundary: "rdp-negotiation", Expected: "tls"}
		}
		return r, nil
	case 3:
		code := le(neg, 4, 4)
		failure, ok := rdpFailures[code]
		if neg[1] != 0 || !ok {
			return nil, parsing.Malformed("Invalid RDP negotiation failure")
		}
		return &parsing.Result{ProtocolName: "rdp", Scope: "negotiation_response",
			Reason: "RDP connection confirm with negotiation failure validated",
			Extra: []parsing.Row{row("rdp_negotiation", "failure", "negotiation_response", "structural"),
				row("rdp_failure", failure, "negotiation_response", "structural")}}, nil
	}
	return nil, parsing.Unsupported("Unsupported X.224 confirm negotiation type")
}

func cotpValidate(data []byte) (*parsing.Result, error) {
	confirm := data[5] == 0xd0
	class := data[10] & 0xf0
	if int(data[4]) != len(data)-5 || (data[5] != 0xe0 && data[5] != 0xd0) || class > 0x40 {
		return nil, parsing.Malformed("Invalid X.224 connection request header")
	}
	scope := "negotiation_request"
	if confirm {
		if data[6] == 0 && data[7] == 0 {
			return nil, parsing.Malformed("X.224 connection confirm requires a nonzero destination reference")
		}
		scope = "negotiation_response"
	} else if data[6] != 0 || data[7] != 0 {
		return nil, parsing.Malformed("X.224 connection request requires a zero destination reference")
	}
	pos := 11
	codes := map[byte]bool{}
	for pos < len(data) {
		if pos+2 > len(data) {
			return nil, parsing.Malformed("Truncated X.224 parameter")
		}
		code, size := data[pos], int(data[pos+1])
		if pos+2+size > len(data) {
			return nil, parsing.Malformed("X.224 parameter exceeds request")
		}
		if codes[code] {
			return nil, parsing.Malformed("Duplicate X.224 parameter")
		}
		codes[code] = true
		if code == 0xc0 && (size != 1 || data[pos+2] < 7 || data[pos+2] > 13) {
			return nil, parsing.Malformed("X.224 TPDU size parameter invalid")
		}
		if (code == 0xc1 || code == 0xc2) && (size < 1 || size > 32) {
			return nil, parsing.Malformed("X.224 TSAP parameter length outside profile")
		}
		pos += 2 + size
	}
	if !confirm && !codes[0xc1] && !codes[0xc2] {
		return nil, parsing.Unsupported("X.224 request without TSAP parameters is outside the ISO-TSAP profile")
	}
	if confirm && len(codes) == 0 {
		return nil, parsing.Unsupported("X.224 confirm without parameters is outside the ISO-TSAP profile")
	}
	reason := "TPKT/X.224 connection request with TSAP parameters validated; the upper protocol (S7comm) follows in the shifted phase"
	if confirm {
		reason = "TPKT/X.224 connection confirm validated; the upper protocol (S7comm) follows in the shifted phase"
	}
	// After the COTP connection both sides exchange S7 PDUs in COTP data TPDUs.
	return &parsing.Result{ProtocolName: "iso-tsap", Scope: scope, Reason: reason,
		Shift: &parsing.Shift{Boundary: "cotp-connect", Expected: "s7comm"}}, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
