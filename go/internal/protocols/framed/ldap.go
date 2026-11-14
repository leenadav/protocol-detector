package framed

import (
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// LDAPv3 initial messages (binary.LDAPParser; RFC 4511): BindRequest (simple or SASL), BindResponse, ExtendedRequest
// and ExtendedResponse. A GSS-SPNEGO bind's credentials go through classifyToken, which contributes closed mechanism
// labels only. A named StartTLS success response announces the ldap-starttls shift; the client direction and an
// unnamed success are opened by host correlation on the message id, which the Go host does not carry yet.
// DNs, diagnostic text, credentials and extended values are never emitted.

var (
	ldapExtended = map[string]string{"1.3.6.1.4.1.1466.20037": "starttls", "1.3.6.1.4.1.4203.1.11.3": "whoami",
		"1.3.6.1.4.1.4203.1.11.1": "password-modify", "1.3.6.1.1.8": "cancel", "1.3.6.1.4.1.1466.20036": "notice-of-disconnection"}
	ldapSASL = map[string]string{"GSSAPI": "sasl-gssapi", "GSS-SPNEGO": "sasl-gss-spnego", "PLAIN": "sasl-plain",
		"DIGEST-MD5": "sasl-digest-md5", "CRAM-MD5": "sasl-cram-md5", "EXTERNAL": "sasl-external", "NTLM": "sasl-ntlm",
		"SCRAM-SHA-1": "sasl-scram", "SCRAM-SHA-256": "sasl-scram"}
	ldapResults = map[int]string{0: "success", 1: "operations-error", 2: "protocol-error", 7: "auth-method-not-supported",
		8: "stronger-auth-required", 14: "sasl-bind-in-progress", 32: "no-such-object", 34: "invalid-dn-syntax",
		48: "inappropriate-authentication", 49: "invalid-credentials", 50: "insufficient-access-rights", 51: "busy",
		52: "unavailable", 53: "unwilling-to-perform"}
)

// ldapOID ports the full match of [0-2](?:\.(?:0|[1-9][0-9]{0,9})){1,30}.
func ldapOID(name []byte) bool {
	if len(name) == 0 || name[0] < '0' || name[0] > '2' {
		return false
	}
	arcs, i := 0, 1
	for i < len(name) {
		if name[i] != '.' {
			return false
		}
		start := i + 1
		for i = start; i < len(name) && isDigit(name[i]); i++ {
		}
		digits := i - start
		if digits == 0 || digits > 10 || (digits > 1 && name[start] == '0') {
			return false
		}
		if arcs++; arcs > 30 {
			return false
		}
	}
	return arcs >= 1
}

// ldapSASLName ports the full match of [A-Z0-9_-]{1,20}.
func ldapSASLName(name []byte) bool {
	if len(name) < 1 || len(name) > 20 {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z') && !isDigit(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func ldapOperation(name []byte) string {
	if operation, ok := ldapExtended[string(name)]; ok {
		return operation
	}
	return "other"
}

func ldapResultName(code int) string {
	if name, ok := ldapResults[code]; ok {
		return name
	}
	return "other"
}

// NewLDAP ports LDAPParser: six header bytes are enough for a definite BER length of up to four bytes.
func NewLDAP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 6,
		size: func(h []byte) (int, error) {
			if h[0] != 0x30 {
				return 0, parsing.Malformed("LDAP requires a BER SEQUENCE")
			}
			size, start, err := berLength(h, 1, len(h))
			if err != nil {
				return 0, err
			}
			return start + size, nil
		},
		validate: ldapMessage})
}

// ldapMessage validates one message and records its message id for host correlation (never as evidence).
func ldapMessage(data []byte) (*parsing.Result, error) {
	r, id, err := ldapMessageBody(data)
	if r != nil {
		r.LDAPMessageID, r.HasLDAPMessageID = id, true
	}
	return r, err
}

func ldapMessageBody(data []byte) (*parsing.Result, int, error) {
	message, end, err := berField(data, 0, len(data), 0x30)
	if err != nil {
		return nil, 0, err
	}
	if end != len(data) {
		return nil, 0, parsing.Malformed("Trailing LDAP data")
	}
	identifier, pos, err := berField(message, 0, len(message), 2)
	if err != nil {
		return nil, 0, err
	}
	if len(identifier) < 1 || len(identifier) > 4 || identifier[0]&128 != 0 || be(identifier) == 0 {
		return nil, 0, parsing.Malformed("Invalid LDAP request message ID")
	}
	if pos < len(message) {
		switch message[pos] {
		case 0x61:
			r, err := ldapBindResponse(message, pos)
			return r, be(identifier), err
		case 0x77:
			r, err := ldapExtendedRequest(message, pos)
			return r, be(identifier), err
		case 0x78:
			r, err := ldapExtendedResponse(message, pos)
			return r, be(identifier), err
		}
	}
	if pos >= len(message) || message[pos] != 0x60 {
		return nil, 0, parsing.Unsupported("Only the initial LDAP BindRequest, BindResponse, ExtendedRequest and ExtendedResponse are supported")
	}
	bind, pos, err := berField(message, pos, len(message), 0x60)
	if err != nil {
		return nil, 0, err
	}
	if pos != len(message) {
		return nil, 0, parsing.Unsupported("LDAP controls are outside the initial bind profile")
	}
	version, cursor, err := berField(bind, 0, len(bind), 2)
	if err != nil {
		return nil, 0, err
	}
	if len(version) != 1 || version[0] != 3 {
		return nil, 0, parsing.Unsupported("Only LDAP v3 bind is supported")
	}
	dn, cursor, err := berField(bind, cursor, len(bind), 4)
	if err != nil {
		return nil, 0, err
	}
	if !utf8.Valid(dn) {
		return nil, 0, parsing.Malformed("Invalid LDAP DN UTF-8")
	}
	if cursor >= len(bind) {
		return nil, 0, parsing.Malformed("LDAP bind missing authentication field")
	}
	rows := []parsing.Row{row("ldap_message", "bind_request", "ldap_message", "structural")}
	switch bind[cursor] {
	case 0x80:
		if _, cursor, err = berField(bind, cursor, len(bind), 0x80); err != nil {
			return nil, 0, err
		}
		rows = append(rows, row("ldap_bind", "simple", "bind_request", "structural"))
	case 0xa3:
		var sasl []byte
		if sasl, cursor, err = berField(bind, cursor, len(bind), 0xa3); err != nil {
			return nil, 0, err
		}
		mechanism, off, err := berField(sasl, 0, len(sasl), 4)
		if err != nil {
			return nil, 0, err
		}
		if len(mechanism) > 0 && !ldapSASLName(mechanism) {
			return nil, 0, parsing.Malformed("Invalid LDAP SASL mechanism")
		}
		var credentials []byte
		if off < len(sasl) {
			if credentials, off, err = berField(sasl, off, len(sasl), 4); err != nil {
				return nil, 0, err
			}
		}
		if off != len(sasl) {
			return nil, 0, parsing.Malformed("Trailing LDAP SASL fields")
		}
		label, ok := ldapSASL[string(mechanism)]
		if !ok {
			label = "sasl-other"
		}
		rows = append(rows, row("ldap_bind", label, "bind_request", "structural"))
		if string(mechanism) == "GSS-SPNEGO" && len(credentials) > 0 {
			token, err := classifyToken(credentials) // the SPNEGO token names the inner mechanism; closed labels only
			if err != nil {
				return nil, 0, err
			}
			rows = append(rows, row("gss_mechanism", token.Mechanism, "bind_request", "asserted"))
			if token.NTLMMessage != "" {
				rows = append(rows, row("ntlm_message", token.NTLMMessage, "bind_request", "asserted"))
			}
		}
	default:
		return nil, 0, parsing.Unsupported("Unsupported LDAP authentication choice")
	}
	if cursor != len(bind) {
		return nil, 0, parsing.Malformed("Trailing LDAP bind fields")
	}
	return &parsing.Result{ProtocolName: "ldap/3", Extra: rows,
		Reason: "LDAPv3 BindRequest BER fields validated; credentials, DN semantics and authentication unverified"}, be(identifier), nil
}

// ldapExtendedRequest: ExtendedRequest (RFC 4511 4.12) is a requestName OID and an optional requestValue; StartTLS
// (4.14.1) carries no value. The request announces nothing by itself: the client waits for the server's answer.
func ldapExtendedRequest(message []byte, pos int) (*parsing.Result, error) {
	request, pos, err := berField(message, pos, len(message), 0x77)
	if err != nil {
		return nil, err
	}
	if pos != len(message) {
		return nil, parsing.Unsupported("LDAP controls are outside the initial extended-operation profile")
	}
	name, cursor, err := berField(request, 0, len(request), 0x80)
	if err != nil {
		return nil, err
	}
	if !ldapOID(name) {
		return nil, parsing.Malformed("LDAP requestName is not a numeric OID")
	}
	if cursor < len(request) {
		if _, cursor, err = berField(request, cursor, len(request), 0x81); err != nil {
			return nil, err
		}
	}
	if cursor != len(request) {
		return nil, parsing.Malformed("Trailing LDAP ExtendedRequest fields")
	}
	operation := ldapOperation(name)
	if operation == "starttls" && len(request) != len(name)+2 {
		return nil, parsing.Malformed("StartTLS request carries no requestValue")
	}
	reason := "LDAPv3 ExtendedRequest BER fields validated; request name class reported, value not inspected"
	if operation == "starttls" {
		reason = "LDAPv3 StartTLS ExtendedRequest validated; TLS follows only after the server's success response"
	}
	return &parsing.Result{ProtocolName: "ldap", Reason: reason, Extra: []parsing.Row{
		row("ldap_message", "extended_request", "ldap_message", "structural"),
		row("ldap_extended", operation, "ldap_message", "structural")}}, nil
}

// ldapExtendedResponse: ExtendedResponse (RFC 4511 4.12) is an LDAPResult, an optional responseName OID and an
// optional responseValue. A named StartTLS success is structural: the server's next bytes are its ServerHello.
func ldapExtendedResponse(message []byte, pos int) (*parsing.Result, error) {
	response, pos, err := berField(message, pos, len(message), 0x78)
	if err != nil {
		return nil, err
	}
	if pos != len(message) {
		return nil, parsing.Unsupported("LDAP controls are outside the initial extended-operation profile")
	}
	code, cursor, err := ldapResult(response)
	if err != nil {
		return nil, err
	}
	operation := "unnamed"
	if cursor < len(response) && response[cursor] == 0x8a {
		var name []byte
		if name, cursor, err = berField(response, cursor, len(response), 0x8a); err != nil {
			return nil, err
		}
		if !ldapOID(name) {
			return nil, parsing.Malformed("LDAP responseName is not a numeric OID")
		}
		operation = ldapOperation(name)
	}
	if cursor < len(response) && response[cursor] == 0x8b {
		if operation == "starttls" {
			return nil, parsing.Malformed("StartTLS response carries no responseValue")
		}
		if _, cursor, err = berField(response, cursor, len(response), 0x8b); err != nil {
			return nil, err
		}
	}
	if cursor != len(response) {
		return nil, parsing.Malformed("Trailing LDAP ExtendedResponse fields")
	}
	result := &parsing.Result{ProtocolName: "ldap", Scope: "negotiation_response",
		Reason: "LDAPv3 ExtendedResponse LDAPResult validated; result code and response name class reported, value not inspected",
		Extra: []parsing.Row{row("ldap_message", "extended_response", "ldap_message", "structural"),
			row("ldap_extended", operation, "ldap_message", "structural"),
			row("ldap_result", ldapResultName(code), "ldap_message", "asserted")}}
	if operation == "starttls" && code == 0 {
		result.Shift = &parsing.Shift{Boundary: "ldap-starttls", Expected: "tls"}
		result.Reason = "LDAPv3 StartTLS ExtendedResponse success validated; the TLS handshake follows"
	}
	return result, nil
}

// ldapResult: LDAPResult (RFC 4511 4.1.9) is resultCode, matchedDN, diagnosticMessage and an optional referral of
// at most 16 non-empty URLs. Returns the code and the cursor after it.
func ldapResult(response []byte) (int, int, error) {
	code, cursor, err := berField(response, 0, len(response), 0x0a)
	if err != nil {
		return 0, 0, err
	}
	if len(code) != 1 || code[0] > 123 {
		return 0, 0, parsing.Malformed("LDAP resultCode outside RFC 4511")
	}
	matched, cursor, err := berField(response, cursor, len(response), 4)
	if err != nil {
		return 0, 0, err
	}
	diagnostic, cursor, err := berField(response, cursor, len(response), 4)
	if err != nil {
		return 0, 0, err
	}
	if !utf8.Valid(matched) || !utf8.Valid(diagnostic) {
		return 0, 0, parsing.Malformed("Invalid LDAP result text UTF-8")
	}
	if cursor < len(response) && response[cursor] == 0xa3 {
		var referral []byte
		if referral, cursor, err = berField(response, cursor, len(response), 0xa3); err != nil {
			return 0, 0, err
		}
		count, inner := 0, 0
		for inner < len(referral) {
			if count++; count > 16 {
				return 0, 0, parsing.Budget("LDAP referral count exceeds limit")
			}
			var url []byte
			if url, inner, err = berField(referral, inner, len(referral), 4); err != nil {
				return 0, 0, err
			}
			if len(url) == 0 {
				return 0, 0, parsing.Malformed("Empty LDAP referral URL")
			}
		}
	}
	return int(code[0]), cursor, nil
}

// ldapBindResponse: BindResponse (RFC 4511 4.2.2) is the LDAPResult fields and an optional serverSaslCreds.
func ldapBindResponse(message []byte, pos int) (*parsing.Result, error) {
	response, pos, err := berField(message, pos, len(message), 0x61)
	if err != nil {
		return nil, err
	}
	if pos != len(message) {
		return nil, parsing.Unsupported("LDAP controls are outside the initial bind profile")
	}
	code, cursor, err := ldapResult(response)
	if err != nil {
		return nil, err
	}
	if cursor < len(response) && response[cursor] == 0x87 {
		if _, cursor, err = berField(response, cursor, len(response), 0x87); err != nil {
			return nil, err
		}
	}
	if cursor != len(response) {
		return nil, parsing.Malformed("Trailing LDAP BindResponse fields")
	}
	return &parsing.Result{ProtocolName: "ldap", Scope: "negotiation_response",
		Reason: "LDAP BindResponse validated; result code reported, DN, diagnostic text and SASL credentials not emitted",
		Extra: []parsing.Row{row("ldap_message", "bind_response", "ldap_message", "structural"),
			row("ldap_result", ldapResultName(code), "bind_response", "asserted")}}, nil
}
