package framed

import (
	"bytes"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Bounded classification of GSS-API, SPNEGO and NTLMSSP tokens (protocol_engine/gss.py; RFC 2743 3.1, RFC 4178,
// MS-NLMP). Authentication blobs carried by LDAP SASL binds and SMB session setup name their mechanism in a few DER
// fields. Only the closed mechanism and message labels leave this file; principal names, domains, challenges, MICs
// and ticket bytes are never decoded. Error sentences are the Python ones.

const (
	gssMaxToken          = 4096
	gssMaxMechanisms     = 8
	gssMaxPrincipalParts = 8
)

var (
	oidSPNEGO        = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmsspSignature = []byte("NTLMSSP\x00")
	gssMechanisms    = map[string]string{
		"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02":     "kerberos", // Kerberos 5
		"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02":     "kerberos", // the Microsoft Kerberos 5 OID
		"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03": "kerberos", // user-to-user
		"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a": "ntlm",
		"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e": "negoex",
	}
	ntlmMessages = map[int]string{1: "negotiate", 2: "challenge", 3: "authenticate"}
	negStates    = [4]string{"accept-completed", "accept-incomplete", "reject", "request-mic"}
)

// gssToken mirrors gss.GssToken. Kind: ntlmssp | kerberos | spnego-init | spnego-response | gss-other; Mechanism:
// kerberos | ntlm | negoex | spnego-other | other; NTLMMessage and State are "" when absent.
type gssToken struct{ Kind, Mechanism, NTLMMessage, State string }

func gssMechanism(oid []byte, fallback string) string {
	if name, ok := gssMechanisms[string(oid)]; ok {
		return name
	}
	return fallback
}

func ntlmMessage(blob []byte) (string, error) {
	if len(blob) < 12 {
		return "", parsing.Malformed("NTLMSSP message shorter than its signature and type")
	}
	kind := int(blob[8]) | int(blob[9])<<8 | int(blob[10])<<16 | int(blob[11])<<24
	name, ok := ntlmMessages[kind]
	if !ok {
		return "", parsing.Malformed("NTLMSSP message type outside NEGOTIATE, CHALLENGE and AUTHENTICATE")
	}
	return name, nil
}

// gssFields ports gss._fields: the context-tagged fields [n] of a Kerberos SEQUENCE, strictly increasing (so at
// most len(allowed) iterations). allowed is the count of field numbers 0..allowed-1; required is a bit set.
func gssFields(sequence []byte, allowed int, required uint, what string) (map[int][]byte, error) {
	pos, last := 0, -1
	found := map[int][]byte{}
	var seen uint
	for pos < len(sequence) {
		tag := sequence[pos]
		number := int(tag & 0x1f)
		if tag&0xe0 != 0xa0 || number <= last || number >= allowed {
			return nil, parsing.Malformed(what + " fields out of order or outside the message definition")
		}
		value, end, err := berField(sequence, pos, len(sequence), tag)
		if err != nil {
			return nil, err
		}
		found[number], pos, last = value, end, number
		seen |= 1 << uint(number)
	}
	if seen&required != required {
		return nil, parsing.Malformed(what + " lacks a required field")
	}
	return found, nil
}

// gssOnly ports gss._only: the single element of an explicitly tagged field, which must fill it.
func gssOnly(value []byte, tag byte, what string) ([]byte, error) {
	inner, end, err := berField(value, 0, len(value), tag)
	if err != nil {
		return nil, err
	}
	if end != len(value) {
		return nil, parsing.Malformed(what + " framing invalid")
	}
	return inner, nil
}

// gssSmallInteger ports gss._small_integer; expected < 0 means any value.
func gssSmallInteger(value []byte, what string, expected, width int) error {
	number, err := gssOnly(value, 0x02, what)
	if err != nil {
		return err
	}
	if len(number) < 1 || len(number) > width || (expected >= 0 && (len(number) != 1 || int(number[0]) != expected)) {
		return parsing.Malformed(what + " outside the Kerberos profile")
	}
	return nil
}

// gssEncryptedData: EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }.
func gssEncryptedData(value []byte, what string) error {
	sequence, err := gssOnly(value, 0x30, what)
	if err != nil {
		return err
	}
	found, err := gssFields(sequence, 3, 0b101, what)
	if err != nil {
		return err
	}
	if err := gssSmallInteger(found[0], what+" etype", -1, 4); err != nil {
		return err
	}
	if kvno, ok := found[1]; ok {
		if err := gssSmallInteger(kvno, what+" kvno", -1, 5); err != nil {
			return err
		}
	}
	cipher, err := gssOnly(found[2], 0x04, what+" cipher")
	if err != nil {
		return err
	}
	if len(cipher) == 0 {
		return parsing.Malformed(what + " cipher must not be empty")
	}
	return nil
}

// gssPrincipal: PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString };
// framing only, at most gssMaxPrincipalParts components.
func gssPrincipal(value []byte, what string) error {
	sequence, err := gssOnly(value, 0x30, what)
	if err != nil {
		return err
	}
	found, err := gssFields(sequence, 2, 0b11, what)
	if err != nil {
		return err
	}
	if err := gssSmallInteger(found[0], what+" name-type", -1, 4); err != nil {
		return err
	}
	names, err := gssOnly(found[1], 0x30, what)
	if err != nil {
		return err
	}
	pos, count := 0, 0
	for pos < len(names) {
		if count++; count > gssMaxPrincipalParts {
			return parsing.Malformed(what + " exceeds the name component budget")
		}
		if _, pos, err = berField(names, pos, len(names), 0x1b); err != nil {
			return err
		}
	}
	if count == 0 {
		return parsing.Malformed(what + " has no name component")
	}
	return nil
}

func gssRealm(value []byte, what string) error {
	realm, err := gssOnly(value, 0x1b, what)
	if err != nil {
		return err
	}
	if len(realm) == 0 {
		return parsing.Malformed(what + " must be a non-empty GeneralString")
	}
	return nil
}

// gssTicket: Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0] 5, realm [1], sname [2], enc-part [3] EncryptedData }.
func gssTicket(value []byte) error {
	outer, err := gssOnly(value, 0x61, "Ticket")
	if err != nil {
		return err
	}
	sequence, err := gssOnly(outer, 0x30, "Ticket")
	if err != nil {
		return err
	}
	found, err := gssFields(sequence, 4, 0b1111, "Ticket")
	if err != nil {
		return err
	}
	if err := gssSmallInteger(found[0], "Ticket tkt-vno", 5, 4); err != nil {
		return err
	}
	if err := gssRealm(found[1], "Ticket realm"); err != nil {
		return err
	}
	if err := gssPrincipal(found[2], "Ticket sname"); err != nil {
		return err
	}
	return gssEncryptedData(found[3], "Ticket enc-part")
}

// gssKerberosFlags: KerberosFlags ::= BIT STRING (SIZE (32..MAX)) under DER: at least 32 significant bits, an
// unused-bit count of 0..7 and zero padding bits.
func gssKerberosFlags(bits []byte, what string) error {
	unused := 8
	if len(bits) > 0 {
		unused = int(bits[0])
	}
	if unused > 7 || (len(bits)-1)*8-unused < 32 || (unused != 0 && bits[len(bits)-1]&byte(1<<uint(unused)-1) != 0) {
		return parsing.Malformed(what + " must be a DER KerberosFlags BIT STRING of at least 32 bits")
	}
	return nil
}

// gssKerberosMessage ports gss._kerberos_message: RFC 4120 5.5.1 AP-REQ, 5.5.2 AP-REP, 5.9.1 KRB-ERROR and the
// user-to-user TGT-REQ as bounded envelopes; nothing is kept.
func gssKerberosMessage(message []byte, tag byte) error {
	if tag == 0x7e { // the Kerberos family's KRB-ERROR profile; it reads no configured budget
		_, _, err := kerberosBody(message, 0)
		return err
	}
	body, err := gssOnly(message, tag, "Kerberos message")
	if err != nil {
		return err
	}
	if tag == 0x30 { // KERB-TGT-REQUEST: pvno, msg-type 16, optional server-name and realm
		found, err := gssFields(body, 4, 0b11, "TGT-REQ")
		if err != nil {
			return err
		}
		if err := gssSmallInteger(found[0], "TGT-REQ pvno", 5, 4); err != nil {
			return err
		}
		if err := gssSmallInteger(found[1], "TGT-REQ msg-type", 16, 4); err != nil {
			return err
		}
		if name, ok := found[2]; ok {
			if err := gssPrincipal(name, "TGT-REQ server-name"); err != nil {
				return err
			}
		}
		if realm, ok := found[3]; ok {
			return gssRealm(realm, "TGT-REQ realm")
		}
		return nil
	}
	sequence, err := gssOnly(body, 0x30, "Kerberos message")
	if err != nil {
		return err
	}
	if tag == 0x6e {
		found, err := gssFields(sequence, 5, 0b11111, "AP-REQ")
		if err != nil {
			return err
		}
		if err := gssSmallInteger(found[0], "AP-REQ pvno", 5, 4); err != nil {
			return err
		}
		if err := gssSmallInteger(found[1], "AP-REQ msg-type", 14, 4); err != nil {
			return err
		}
		options, err := gssOnly(found[2], 0x03, "AP-REQ ap-options")
		if err != nil {
			return err
		}
		if err := gssKerberosFlags(options, "AP-REQ ap-options"); err != nil {
			return err
		}
		if err := gssTicket(found[3]); err != nil {
			return err
		}
		return gssEncryptedData(found[4], "AP-REQ authenticator")
	}
	found, err := gssFields(sequence, 3, 0b111, "AP-REP")
	if err != nil {
		return err
	}
	if err := gssSmallInteger(found[0], "AP-REP pvno", 5, 4); err != nil {
		return err
	}
	if err := gssSmallInteger(found[1], "AP-REP msg-type", 15, 4); err != nil {
		return err
	}
	return gssEncryptedData(found[2], "AP-REP enc-part")
}

// gssKerberosToken ports gss._kerberos_token: after a Kerberos mechanism OID, a known TOK_ID (RFC 4121 4.1 /
// RFC 1964 1.1) and then exactly the Kerberos message it names.
func gssKerberosToken(blob []byte, pos, limit int) error {
	var expected byte
	if pos+2 <= len(blob) && blob[pos+1] == 0 {
		switch blob[pos] {
		case 1:
			expected = 0x6e // AP-REQ
		case 2:
			expected = 0x6f // AP-REP
		case 3:
			expected = 0x7e // KRB-ERROR
		case 4:
			expected = 0x30 // user-to-user TGT-REQ
		}
	}
	if expected == 0 {
		return parsing.Malformed("Kerberos GSS token needs a known TOK_ID")
	}
	_, end, err := berField(blob, pos+2, limit, expected)
	if err != nil {
		return err
	}
	if end != limit {
		return parsing.Malformed("Kerberos GSS token has bytes after its message")
	}
	return gssKerberosMessage(blob[pos+2:limit], expected)
}

// gssInner ports gss._inner: the mechanism of a mechToken/responseToken (ntlm with its message, kerberos, or
// other). A token that names a Kerberos OID must pass the same validator as a direct Kerberos token.
func gssInner(blob []byte) (string, string, error) {
	limit := len(blob)
	if bytes.HasPrefix(blob, ntlmsspSignature) {
		message, err := ntlmMessage(blob)
		return "ntlm", message, err
	}
	if limit > 0 && blob[0] == 0x60 {
		size, start, err := berLength(blob, 1, limit)
		if err != nil {
			return "", "", err
		}
		if start+size == limit && start < limit && blob[start] == 0x06 {
			oid, pos, err := berField(blob, start, limit, 0x06)
			if err != nil {
				return "", "", err
			}
			if gssMechanism(oid, "") == "kerberos" {
				if err := gssKerberosToken(blob, pos, limit); err != nil {
					return "", "", err
				}
				return "kerberos", "", nil
			}
		}
	}
	return "other", "", nil
}

// classifyToken ports gss.classify_token: a gssToken for an authentication blob, or an error when it is none of
// the known layouts.
func classifyToken(blob []byte) (gssToken, error) {
	limit := len(blob)
	if limit > gssMaxToken {
		return gssToken{}, parsing.Budget("Authentication token exceeds the inspection limit")
	}
	if limit == 0 {
		return gssToken{}, parsing.Malformed("Empty authentication token")
	}
	if bytes.HasPrefix(blob, ntlmsspSignature) {
		message, err := ntlmMessage(blob)
		if err != nil {
			return gssToken{}, err
		}
		return gssToken{Kind: "ntlmssp", Mechanism: "ntlm", NTLMMessage: message}, nil
	}
	switch blob[0] {
	case 0x60:
		size, start, err := berLength(blob, 1, limit)
		if err != nil {
			return gssToken{}, err
		}
		if start+size != limit {
			return gssToken{}, parsing.Malformed("GSS-API token length disagrees with the blob")
		}
		oid, pos, err := berField(blob, start, limit, 0x06)
		if err != nil {
			return gssToken{}, err
		}
		if bytes.Equal(oid, oidSPNEGO) {
			if pos >= limit || blob[pos] != 0xa0 {
				return gssToken{}, parsing.Malformed("SPNEGO initial token requires NegTokenInit")
			}
			return negTokenInit(blob, pos, limit)
		}
		if gssMechanism(oid, "") == "kerberos" {
			if err := gssKerberosToken(blob, pos, limit); err != nil {
				return gssToken{}, err
			}
			return gssToken{Kind: "kerberos", Mechanism: "kerberos"}, nil
		}
		return gssToken{Kind: "gss-other", Mechanism: "other"}, nil
	case 0xa1:
		return negTokenResp(blob, limit)
	}
	return gssToken{}, parsing.Malformed("Authentication token is neither GSS-API, SPNEGO nor NTLMSSP")
}

// negBody unwraps the [0]/[1] wrapper and the SEQUENCE of a NegTokenInit or NegTokenResp.
func negBody(blob []byte, pos, limit int, tag byte, name string) ([]byte, error) {
	wrapper, end, err := berField(blob, pos, limit, tag)
	if err != nil {
		return nil, err
	}
	if end != limit {
		return nil, parsing.Malformed("Trailing bytes after " + name)
	}
	body, end, err := berField(wrapper, 0, len(wrapper), 0x30)
	if err != nil {
		return nil, err
	}
	if end != len(wrapper) {
		return nil, parsing.Malformed("Trailing bytes after the " + name + " sequence")
	}
	return body, nil
}

// negCarried reads the [2] mechToken/responseToken at cursor and classifies a non-empty one.
func negCarried(body []byte, cursor int, what string) (string, string, int, error) {
	holder, cursor, err := berField(body, cursor, len(body), 0xa2)
	if err != nil {
		return "", "", 0, err
	}
	token, inner, err := berField(holder, 0, len(holder), 0x04)
	if err != nil {
		return "", "", 0, err
	}
	if inner != len(holder) {
		return "", "", 0, parsing.Malformed("Trailing bytes after the SPNEGO " + what)
	}
	if len(token) == 0 {
		return "other", "", cursor, nil
	}
	carried, ntlm, err := gssInner(token)
	return carried, ntlm, cursor, err
}

func negTokenInit(blob []byte, pos, limit int) (gssToken, error) {
	body, err := negBody(blob, pos, limit, 0xa0, "NegTokenInit")
	if err != nil {
		return gssToken{}, err
	}
	cursor, mechanism, ntlm := 0, "spnego-other", ""
	if cursor < len(body) && body[cursor] == 0xa0 {
		var mechs []byte
		if mechs, cursor, err = berField(body, cursor, len(body), 0xa0); err != nil {
			return gssToken{}, err
		}
		listed, inner, err := berField(mechs, 0, len(mechs), 0x30)
		if err != nil {
			return gssToken{}, err
		}
		if inner != len(mechs) {
			return gssToken{}, parsing.Malformed("Trailing bytes after the mechType list")
		}
		var preferred []byte
		offset, count := 0, 0
		for offset < len(listed) {
			var oid []byte
			if oid, offset, err = berField(listed, offset, len(listed), 0x06); err != nil {
				return gssToken{}, err
			}
			if count++; count > gssMaxMechanisms {
				return gssToken{}, parsing.Budget("SPNEGO mechType list exceeds the inspection limit")
			}
			if count == 1 {
				preferred = oid
			}
		}
		if count == 0 {
			return gssToken{}, parsing.Malformed("Empty SPNEGO mechType list")
		}
		mechanism = gssMechanism(preferred, "spnego-other")
	}
	if cursor < len(body) && body[cursor] == 0xa1 {
		if _, cursor, err = berField(body, cursor, len(body), 0xa1); err != nil {
			return gssToken{}, err
		}
	}
	if cursor < len(body) && body[cursor] == 0xa2 {
		var carried string
		if carried, ntlm, cursor, err = negCarried(body, cursor, "mechToken"); err != nil {
			return gssToken{}, err
		}
		if carried != "other" {
			mechanism = carried
		}
	}
	if cursor < len(body) && body[cursor] == 0xa3 {
		if _, cursor, err = berField(body, cursor, len(body), 0xa3); err != nil {
			return gssToken{}, err
		}
	}
	if cursor != len(body) {
		return gssToken{}, parsing.Malformed("Unexpected NegTokenInit field order")
	}
	return gssToken{Kind: "spnego-init", Mechanism: mechanism, NTLMMessage: ntlm}, nil
}

func negTokenResp(blob []byte, limit int) (gssToken, error) {
	body, err := negBody(blob, 0, limit, 0xa1, "NegTokenResp")
	if err != nil {
		return gssToken{}, err
	}
	cursor, state, mechanism, ntlm := 0, "", "spnego-other", ""
	if cursor < len(body) && body[cursor] == 0xa0 {
		var holder []byte
		if holder, cursor, err = berField(body, cursor, len(body), 0xa0); err != nil {
			return gssToken{}, err
		}
		value, inner, err := berField(holder, 0, len(holder), 0x0a)
		if err != nil {
			return gssToken{}, err
		}
		if inner != len(holder) || len(value) != 1 || value[0] > 3 {
			return gssToken{}, parsing.Malformed("Invalid SPNEGO negState")
		}
		state = negStates[value[0]]
	}
	if cursor < len(body) && body[cursor] == 0xa1 {
		var holder []byte
		if holder, cursor, err = berField(body, cursor, len(body), 0xa1); err != nil {
			return gssToken{}, err
		}
		oid, inner, err := berField(holder, 0, len(holder), 0x06)
		if err != nil {
			return gssToken{}, err
		}
		if inner != len(holder) {
			return gssToken{}, parsing.Malformed("Trailing bytes after the supportedMech")
		}
		mechanism = gssMechanism(oid, "spnego-other")
	}
	if cursor < len(body) && body[cursor] == 0xa2 {
		var carried string
		if carried, ntlm, cursor, err = negCarried(body, cursor, "responseToken"); err != nil {
			return gssToken{}, err
		}
		if carried != "other" {
			mechanism = carried
		}
	}
	if cursor < len(body) && body[cursor] == 0xa3 {
		if _, cursor, err = berField(body, cursor, len(body), 0xa3); err != nil {
			return gssToken{}, err
		}
	}
	if cursor != len(body) {
		return gssToken{}, parsing.Malformed("Unexpected NegTokenResp field order")
	}
	if state == "" && mechanism == "spnego-other" && ntlm == "" {
		return gssToken{}, parsing.Malformed("Empty NegTokenResp")
	}
	return gssToken{Kind: "spnego-response", Mechanism: mechanism, NTLMMessage: ntlm, State: state}, nil
}
