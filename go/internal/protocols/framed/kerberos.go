package framed

import (
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Kerberos KDC messages (windows.py _kerberos_body): AS/TGS-REQ, AS/TGS-REP and KRB-ERROR as ASN.1 DER, over
// TCP (4-byte record marking) and UDP. Field walks, error sentences and evidence rows are the Python ones; the
// etype helpers return "no row" on any error, as the Python helpers swallow every ParseError (BudgetError and
// UnsupportedPrefix included). Principals, realms, tickets and pre-authentication data are never emitted.

var krbTags = map[byte]struct {
	name    string
	msgType byte
}{0x6a: {"as-req", 0x0a}, 0x6c: {"tgs-req", 0x0c}, 0x6b: {"as-rep", 0x0b}, 0x6d: {"tgs-rep", 0x0d}, 0x7e: {"error", 0x1e}}

// IANA Kerberos encryption type numbers as closed classes (windows.ETYPE_CLASSES).
var etypeClasses = map[int64]string{1: "des", 2: "des", 3: "des", 5: "des3", 7: "des3", 16: "des3", 17: "aes-sha1", 18: "aes-sha1",
	19: "aes-sha2", 20: "aes-sha2", 23: "rc4", 24: "rc4", 25: "camellia", 26: "camellia"}

const krbMaxEtypes = 32

func signedBE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	n := int64(int8(b[0]))
	for _, c := range b[1:] {
		n = n<<8 | int64(c)
	}
	return n
}

func allowedField(allowed []int, n int) bool {
	for _, a := range allowed {
		if a == n {
			return true
		}
	}
	return false
}

// krbFields ports _kerberos_fields: context-specific constructed fields with strictly increasing numbers, each
// handed to visit before the next is read (the Python generator interleaves checks the same way).
func krbFields(sequence []byte, allowed []int, budget int, visit func(number int, value []byte) error) error {
	pos, last, count := 0, -1, 0
	for pos < len(sequence) {
		count++
		if count > budget {
			return parsing.Budget("Kerberos field count exceeds profile")
		}
		tag := sequence[pos]
		if tag&0xe0 != 0xa0 {
			return parsing.Malformed("Kerberos fields must be context-specific constructed")
		}
		value, next, err := berField(sequence, pos, len(sequence), tag)
		if err != nil {
			return err
		}
		pos = next
		number := int(tag & 0x1f)
		if number <= last || !allowedField(allowed, number) {
			return parsing.Malformed("Kerberos fields out of order or outside the message definition")
		}
		last = number
		if err := visit(number, value); err != nil {
			return err
		}
	}
	return nil
}

// krbInner ports _krb_inner: exactly one TLV of the expected tag fills value.
func krbInner(value []byte, tag byte, what string) ([]byte, error) {
	inner, end, err := berField(value, 0, len(value), tag)
	if err != nil {
		return nil, err
	}
	if end != len(value) {
		return nil, parsing.Malformed("Kerberos " + what + " framing invalid")
	}
	return inner, nil
}

// krbFieldMap ports _field_map (tag and order are checked before the field is read).
func krbFieldMap(sequence []byte, allowed []int) (map[int][]byte, error) {
	fields, pos, last := map[int][]byte{}, 0, -1
	for pos < len(sequence) {
		tag := sequence[pos]
		number := int(tag & 0x1f)
		if tag&0xe0 != 0xa0 || number <= last || !allowedField(allowed, number) {
			return nil, parsing.Malformed("Kerberos fields out of order or outside the message definition")
		}
		value, next, err := berField(sequence, pos, len(sequence), tag)
		if err != nil {
			return nil, err
		}
		fields[number], pos, last = value, next, number
	}
	return fields, nil
}

// krbEtype ports _etype: a minimally encoded Int32 as its class.
func krbEtype(raw []byte) (string, error) {
	if len(raw) < 1 || len(raw) > 4 || (len(raw) > 1 && ((raw[0] == 0 && raw[1] < 0x80) || (raw[0] == 0xff && raw[1] >= 0x80))) {
		return "", parsing.Malformed("Kerberos etype must be a minimally encoded Int32")
	}
	if label, ok := etypeClasses[signedBE(raw)]; ok {
		return label, nil
	}
	return "other", nil
}

var reqBodyFields = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

// krbRequestEtypes ports _request_etypes: offered etype rows, or none unless the whole body walks cleanly.
func krbRequestEtypes(body []byte) []parsing.Row {
	fields, err := krbFieldMap(body, reqBodyFields)
	if err != nil {
		return nil
	}
	for _, required := range []int{0, 2, 5, 7, 8} {
		if _, ok := fields[required]; !ok {
			return nil
		}
	}
	listed, err := krbInner(fields[8], 0x30, "etype")
	if err != nil {
		return nil
	}
	var offered []string
	for pos := 0; pos < len(listed); {
		if len(offered) == krbMaxEtypes {
			return nil // BudgetError, swallowed with every ParseError
		}
		raw, next, err := berField(listed, pos, len(listed), 2)
		if err != nil {
			return nil
		}
		label, err := krbEtype(raw)
		if err != nil {
			return nil
		}
		offered, pos = append(offered, label), next
	}
	if len(offered) == 0 {
		return nil
	}
	rows := []parsing.Row{row("kerberos_etype_preferred", offered[0], "req_body", "offered")}
	seen := map[string]bool{}
	for _, label := range offered {
		if !seen[label] {
			seen[label] = true
			rows = append(rows, row("kerberos_etype_offered", label, "req_body", "offered"))
		}
	}
	return rows
}

// krbEncryptedEtype ports _encrypted_etype; ok is false where Python returns None.
func krbEncryptedEtype(encrypted []byte) (string, bool) {
	fields, err := krbFieldMap(encrypted, []int{0, 1, 2})
	if err != nil {
		return "", false
	}
	if _, ok := fields[0]; !ok {
		return "", false
	}
	if _, ok := fields[2]; !ok {
		return "", false
	}
	if cipher, err := krbInner(fields[2], 4, "cipher"); err != nil || len(cipher) == 0 {
		return "", false
	}
	if kvno, ok := fields[1]; ok {
		if _, err := krbInner(kvno, 2, "kvno"); err != nil {
			return "", false
		}
	}
	raw, err := krbInner(fields[0], 2, "etype")
	if err != nil {
		return "", false
	}
	label, err := krbEtype(raw)
	return label, err == nil
}

// krbTicketEtype ports _ticket_etype.
func krbTicketEtype(ticket []byte) (string, bool) {
	inner, err := krbInner(ticket, 0x30, "ticket")
	if err != nil {
		return "", false
	}
	fields, err := krbFieldMap(inner, []int{0, 1, 2, 3})
	if err != nil || len(fields) != 4 {
		return "", false
	}
	encPart, err := krbInner(fields[3], 0x30, "ticket enc-part")
	if err != nil {
		return "", false
	}
	return krbEncryptedEtype(encPart)
}

func krbPadata(value []byte, maxHeaders int) error {
	padata, err := krbInner(value, 0x30, "padata")
	if err != nil {
		return err
	}
	limit := maxHeaders
	if limit > 32 {
		limit = 32
	}
	count := 0
	for inner := 0; inner < len(padata); {
		count++
		if count > limit {
			return parsing.Budget("Kerberos padata count exceeds budget")
		}
		_, next, err := berField(padata, inner, len(padata), 0x30)
		if err != nil {
			return err
		}
		inner = next
	}
	return nil
}

func krbExpect(value []byte, tag byte, what string, want byte) (bool, error) {
	inner, err := krbInner(value, tag, what)
	if err != nil {
		return false, err
	}
	return len(inner) == 1 && inner[0] == want, nil
}

func hasAll(seen map[int]bool, required ...int) bool {
	for _, n := range required {
		if !seen[n] {
			return false
		}
	}
	return true
}

// kerberosBody ports _kerberos_body: validate one KDC message and return its reason and evidence rows (with
// their Python provenance, without the "wire:" prefix the datagram path adds).
func kerberosBody(data []byte, maxHeaders int) (string, []parsing.Row, error) {
	if len(data) == 0 {
		return "", nil, parsing.Malformed("Truncated BER length")
	}
	tag := data[0]
	kind, ok := krbTags[tag]
	if !ok {
		return "", nil, parsing.Unsupported("Kerberos profile covers KDC requests, replies and KRB-ERROR")
	}
	outer, end, err := berField(data, 0, len(data), tag)
	if err != nil {
		return "", nil, err
	}
	if end != len(data) {
		return "", nil, parsing.Malformed("Trailing bytes after Kerberos message")
	}
	sequence, end, err := berField(outer, 0, len(outer), 0x30)
	if err != nil {
		return "", nil, err
	}
	if end != len(outer) {
		return "", nil, parsing.Malformed("Kerberos wrapper must contain one SEQUENCE")
	}
	evidence := []parsing.Row{row("kerberos_message", kind.name, "message", "structural")}
	seen := map[int]bool{}
	pvno := func(value []byte) error {
		if ok, err := krbExpect(value, 2, "pvno", 5); err != nil {
			return err
		} else if !ok {
			return parsing.Unsupported("Kerberos pvno outside version 5")
		}
		return nil
	}
	msgType := func(value []byte) error {
		if ok, err := krbExpect(value, 2, "msg-type", kind.msgType); err != nil {
			return err
		} else if !ok {
			return parsing.Malformed("Kerberos msg-type disagrees with application tag")
		}
		return nil
	}
	switch kind.name {
	case "as-req", "tgs-req":
		var etypeRows []parsing.Row
		err := krbFields(sequence, []int{1, 2, 3, 4}, 5, func(number int, value []byte) error {
			seen[number] = true
			switch number {
			case 1:
				return pvno(value)
			case 2:
				return msgType(value)
			case 3:
				return krbPadata(value, maxHeaders)
			case 4:
				body, err := krbInner(value, 0x30, "req-body")
				if err != nil {
					return err
				}
				if len(body) == 0 {
					return parsing.Malformed("Kerberos req-body framing invalid")
				}
				etypeRows = krbRequestEtypes(body)
			}
			return nil
		})
		if err != nil {
			return "", nil, err
		}
		if !hasAll(seen, 1, 2, 4) {
			return "", nil, parsing.Malformed("Kerberos request requires pvno, msg-type and req-body")
		}
		return "Kerberos KDC request ASN.1 framing validated; principals, pre-authentication and tickets unverified", append(evidence, etypeRows...), nil
	case "as-rep", "tgs-rep":
		var replyEtype, ticketEtype string
		var hasReply, hasTicket bool
		err := krbFields(sequence, []int{0, 1, 2, 3, 4, 5, 6}, 8, func(number int, value []byte) error {
			seen[number] = true
			switch number {
			case 0:
				return pvno(value)
			case 1:
				return msgType(value)
			case 2:
				return krbPadata(value, maxHeaders)
			case 3:
				crealm, err := krbInner(value, 0x1b, "crealm")
				if err != nil {
					return err
				}
				if len(crealm) == 0 {
					return parsing.Malformed("Kerberos crealm must be a non-empty GeneralString")
				}
			case 4:
				cname, err := krbInner(value, 0x30, "cname")
				if err != nil {
					return err
				}
				if len(cname) == 0 {
					return parsing.Malformed("Kerberos cname framing invalid")
				}
			case 5:
				ticket, err := krbInner(value, 0x61, "ticket")
				if err != nil {
					return err
				}
				if len(ticket) == 0 {
					return parsing.Malformed("Kerberos ticket framing invalid")
				}
				ticketEtype, hasTicket = krbTicketEtype(ticket)
			case 6:
				encPart, err := krbInner(value, 0x30, "enc-part")
				if err != nil {
					return err
				}
				if len(encPart) == 0 {
					return parsing.Malformed("Kerberos enc-part framing invalid")
				}
				replyEtype, hasReply = krbEncryptedEtype(encPart)
			}
			return nil
		})
		if err != nil {
			return "", nil, err
		}
		if !hasAll(seen, 0, 1, 3, 4, 5, 6) {
			return "", nil, parsing.Malformed("Kerberos reply requires pvno, msg-type, crealm, cname, ticket and enc-part")
		}
		if hasReply {
			evidence = append(evidence, row("kerberos_reply_etype", replyEtype, "enc_part", "asserted"))
		}
		if hasTicket {
			evidence = append(evidence, row("kerberos_ticket_etype", ticketEtype, "ticket", "asserted"))
		}
		return "Kerberos KDC reply ASN.1 framing validated; ticket and encrypted part opaque, principals not emitted", evidence, nil
	}
	var code int64
	err = krbFields(sequence, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 14, func(number int, value []byte) error {
		seen[number] = true
		switch number {
		case 0:
			return pvno(value)
		case 1:
			return msgType(value)
		case 2, 4:
			stamp, err := krbInner(value, 0x18, "time")
			if err != nil {
				return err
			}
			if len(stamp) != 15 || !isDigits(stamp[:14]) || stamp[14] != 'Z' {
				return parsing.Malformed("Kerberos time must be a GeneralizedTime in UTC")
			}
		case 3, 5:
			usec, err := krbInner(value, 2, "microseconds")
			if err != nil {
				return err
			}
			if v := signedBE(usec); len(usec) < 1 || len(usec) > 3 || v < 0 || v > 999999 {
				return parsing.Malformed("Kerberos microseconds outside range")
			}
		case 6:
			raw, err := krbInner(value, 2, "error-code")
			if err != nil {
				return err
			}
			code = signedBE(raw)
			if len(raw) < 1 || len(raw) > 2 || code < 0 || code > 127 {
				return parsing.Malformed("Kerberos error-code outside RFC 4120 range")
			}
		case 7, 9:
			realm, err := krbInner(value, 0x1b, "realm")
			if err != nil {
				return err
			}
			if len(realm) == 0 {
				return parsing.Malformed("Kerberos realm must be a non-empty GeneralString")
			}
		case 8, 10:
			principal, err := krbInner(value, 0x30, "principal")
			if err != nil {
				return err
			}
			if len(principal) == 0 {
				return parsing.Malformed("Kerberos principal framing invalid")
			}
		case 11:
			_, err := krbInner(value, 0x1b, "e-text")
			return err
		case 12:
			_, err := krbInner(value, 4, "e-data")
			return err
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if !hasAll(seen, 0, 1, 4, 5, 6, 9, 10) {
		return "", nil, parsing.Malformed("KRB-ERROR requires pvno, msg-type, stime, susec, error-code, realm and sname")
	}
	evidence = append(evidence, row("kerberos_error", strconv.FormatInt(code, 10), "message", "structural"))
	return "KRB-ERROR ASN.1 framing validated; error code reported, principals and text not emitted", evidence, nil
}

// NewKerberos ports KerberosParser: a 4-byte record length (high bit clear) then one KDC message.
func NewKerberos(maxBytes, maxHeaders int) *Parser {
	return newParser(maxBytes, spec{header: 5,
		size: func(h []byte) (int, error) {
			size := be(h[:4])
			if h[0]&0x80 != 0 {
				return 0, parsing.Unsupported("Kerberos TCP extension bit outside profile")
			}
			if size < 40 {
				return 0, parsing.Malformed("Kerberos TCP length too short for a KDC request")
			}
			return 4 + size, nil
		},
		validate: func(frame []byte) (*parsing.Result, error) {
			reason, rows, err := kerberosBody(frame[4:], maxHeaders)
			if err != nil {
				return nil, err
			}
			r := &parsing.Result{ProtocolName: "kerberos", Reason: reason, Extra: rows}
			if name := rows[0].Value; name == "as-rep" || name == "tgs-rep" || name == "error" {
				r.Scope = "negotiation_response"
			}
			return r, nil
		}})
}

func init() { DatagramValidators["kerberos"] = kerberosDatagram }

// kerberosDatagram ports windows.kerberos.
func kerberosDatagram(data []byte, limits Limits) (*Datagram, error) {
	if len(data) < 40 {
		return nil, parsing.Malformed("Kerberos datagram too short for a KDC message")
	}
	reason, rows, err := kerberosBody(data, limits.MaxHeaders)
	if err != nil {
		return nil, err
	}
	evidence := []parsing.Row{row("application_protocol", "kerberos", "wire", "structural")}
	for _, r := range rows {
		evidence = append(evidence, row(r.Field, r.Value, "wire:"+r.Provenance, r.Strength))
	}
	return &Datagram{Protocol: "kerberos", Reason: reason, Evidence: evidence}, nil
}
