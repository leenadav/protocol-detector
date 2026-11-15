package textroute

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// NATS and IMAP server first lines (service_text.py), the SIP/RTSP control headers (control.py).

var (
	natsStart       = regexp.MustCompile(`(?i)^(INFO|CONNECT)[ \t]+(.+)$`)
	imapGreeting    = regexp.MustCompile(`(?i)^\* (?:OK|PREAUTH) \[CAPABILITY ([^\]]+)\] (.+)$`)
	imapCapability  = regexp.MustCompile(`(?i)^\* CAPABILITY (.+)$`)
	imapAtom        = regexp.MustCompile(`^[^\x00-\x20\x7f-\xff(){%*"\\\]]+$`)
	controlStartRE  = regexp.MustCompile(`^(?:[A-Z_]+ [\x21-\x7e]+ (?:SIP/2\.0|RTSP/[12]\.0)|(?:SIP/2\.0|RTSP/[12]\.0) [1-6][0-9]{2} [\x20-\x7e]*)$`)
	sipVia          = regexp.MustCompile(`^SIP/2\.0/[A-Z]+ [\x21-\x7e]+$`)
	sipCSeq         = regexp.MustCompile(`^([0-9]{1,10}) ([A-Z_]+)$`)
	rtspCSeq        = regexp.MustCompile(`^[0-9]{1,10}$`)
	maxForwardsRE   = regexp.MustCompile(`^[0-9]{1,3}$`)
	contentLengthRE = regexp.MustCompile(`^[0-9]{1,20}$`)
	nonStandardJSON = regexp.MustCompile(`(?:^|[^A-Za-z0-9_"])(?:NaN|Infinity|-Infinity)(?:$|[^A-Za-z0-9_"])`)
)

const (
	natsReason    = "NATS INFO/CONNECT JSON structure validated; authentication and later messages unverified"
	imapSrvReason = "IMAP server capability syntax validated; revision capabilities, authentication and later messages unverified"
	controlReason = "SIP/RTSP start-line and required header framing validated; URI semantics, body and dialogue unverified"
)

// --- bounded JSON (service_text.bounded_json) ---------------------------------------------------

type jsonInt struct{ value *big.Int }
type jsonFloat float64

func boundedJSON(data []byte, maxFields int) (map[string]interface{}, error) {
	depth, tokens := 0, 0
	quoted, escaped := false, false
	for _, b := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
		} else if b == '"' {
			quoted = true
		} else if b == '[' || b == '{' {
			depth++
			tokens++
			if depth > 16 {
				return nil, parsing.Budget("JSON nesting exceeds 16 levels")
			}
		} else if b == ']' || b == '}' {
			depth--
		} else if b == ',' || b == ':' {
			tokens++
		}
		if tokens > maxFields*4 {
			return nil, parsing.Budget("JSON structure exceeds field budget")
		}
	}
	if !utf8.Valid(data) {
		return nil, parsing.Malformed("Invalid UTF-8 JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err == nil {
		if _, trailing := dec.Token(); trailing == nil {
			err = errSyntax
		}
	}
	if err != nil {
		if pe, ok := err.(*parsing.Error); ok {
			return nil, pe
		}
		if nonStandardJSON.Match(data) {
			return nil, parsing.Malformed("Non-standard JSON constant")
		}
		return nil, parsing.Malformed("Invalid UTF-8 JSON object")
	}
	obj, ok := value.(map[string]interface{})
	if !ok {
		return nil, parsing.Malformed("Expected JSON object")
	}
	pending := []interface{}{obj}
	nodes := 0
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		nodes++
		if nodes > maxFields*4 {
			return nil, parsing.Budget("JSON values exceed field budget")
		}
		switch n := node.(type) {
		case map[string]interface{}:
			if len(n) > maxFields {
				return nil, parsing.Budget("JSON member count exceeds field budget")
			}
			for k, v := range n {
				pending = append(pending, k, v)
			}
		case []interface{}:
			pending = append(pending, n...)
		case string:
			if !utf8.ValidString(n) || strings.ContainsRune(n, utf8.RuneError) && hasLoneSurrogate(data) {
				return nil, parsing.Malformed("Unpaired surrogate in JSON string")
			}
		}
	}
	return obj, nil
}

var errSyntax = &syntaxError{}

type syntaxError struct{}

func (*syntaxError) Error() string { return "json syntax" }

// hasLoneSurrogate reports a \uD800-\uDFFF escape that does not form a pair (Python keeps it; Go replaces it).
func hasLoneSurrogate(data []byte) bool {
	s := string(data)
	for i := 0; i+6 <= len(s); i++ {
		if s[i] != '\\' || s[i+1] != 'u' {
			continue
		}
		v, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
		if err != nil {
			continue
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
				if w, err := strconv.ParseUint(s[i+8:i+12], 16, 32); err == nil && w >= 0xdc00 && w <= 0xdfff {
					i += 11
					continue
				}
			}
			return true
		}
		if v >= 0xdc00 && v <= 0xdfff {
			return true
		}
	}
	return false
}

func decodeValue(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errSyntax
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]interface{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, errSyntax
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errSyntax
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, dup := obj[key]; dup {
					return nil, parsing.Malformed("Duplicate JSON member")
				}
				obj[key] = val
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errSyntax
			}
			return obj, nil
		case '[':
			var list []interface{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, val)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errSyntax
			}
			if list == nil {
				list = []interface{}{}
			}
			return list, nil
		}
		return nil, errSyntax
	case json.Number:
		text := string(t)
		if strings.ContainsAny(text, ".eE") {
			f, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, parsing.Malformed("Non-finite JSON number")
			}
			return jsonFloat(f), nil
		}
		if len(strings.TrimPrefix(text, "-")) > 20 {
			return nil, parsing.Budget("JSON integer exceeds 20-digit profile")
		}
		n, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return nil, errSyntax
		}
		return jsonInt{n}, nil
	default:
		return tok, nil // string, bool, nil
	}
}

func isInt(v interface{}) (*big.Int, bool) {
	i, ok := v.(jsonInt)
	if !ok {
		return nil, false
	}
	return i.value, true
}

// natsHandshake ports service_text.nats.
func natsHandshake(command string, data []byte, maxHeaders int) error {
	limit := maxHeaders
	if limit > 128 {
		limit = 128
	}
	obj, err := boundedJSON(data, limit)
	if err != nil {
		return err
	}
	type req struct {
		key  string
		kind string
	}
	var required []req
	if command == "INFO" {
		required = []req{{"server_id", "str"}, {"version", "str"}, {"go", "str"}, {"host", "str"}, {"port", "int"}, {"max_payload", "int"}}
	} else {
		required = []req{{"verbose", "bool"}, {"pedantic", "bool"}, {"tls_required", "bool"}, {"lang", "str"}, {"version", "str"}}
	}
	for _, r := range required {
		v, ok := obj[r.key]
		if !ok {
			return parsing.Malformed("Missing or invalid NATS handshake field")
		}
		switch r.kind {
		case "str":
			s, ok := v.(string)
			if !ok || s == "" {
				return parsing.Malformed("Missing or invalid NATS handshake field")
			}
		case "int":
			if _, ok := isInt(v); !ok {
				return parsing.Malformed("Missing or invalid NATS handshake field")
			}
		case "bool":
			if _, ok := v.(bool); !ok {
				return parsing.Malformed("Missing or invalid NATS handshake field")
			}
		}
	}
	if command == "INFO" {
		port, _ := isInt(obj["port"])
		payload, _ := isInt(obj["max_payload"])
		if port.Sign() <= 0 || port.Cmp(big.NewInt(65535)) > 0 || payload.Sign() <= 0 || payload.Cmp(big.NewInt(math.MaxInt64)) > 0 {
			return parsing.Malformed("NATS server limits outside supported range")
		}
	}
	for _, key := range []string{"verbose", "pedantic", "tls_required", "auth_required", "tls_verify", "tls_available", "echo", "headers", "no_responders", "ldm", "jetstream"} {
		if v, ok := obj[key]; ok {
			if _, isBool := v.(bool); !isBool {
				return parsing.Malformed("Invalid NATS boolean field")
			}
		}
	}
	for _, key := range []string{"proto", "protocol"} {
		if v, ok := obj[key]; ok {
			n, isInt := isInt(v)
			if !isInt || (n.Sign() != 0 && n.Cmp(big.NewInt(1)) != 0) {
				return parsing.Malformed("Unsupported NATS protocol level")
			}
		}
	}
	for _, key := range []string{"server_id", "server_name", "version", "go", "host", "lang", "name", "user", "pass", "auth_token", "sig", "jwt", "nkey", "nonce", "cluster", "domain"} {
		if v, ok := obj[key]; ok {
			if _, isStr := v.(string); !isStr {
				return parsing.Malformed("Invalid NATS string field")
			}
		}
	}
	for _, key := range []string{"connect_urls", "ws_connect_urls"} {
		if v, ok := obj[key]; ok {
			list, isList := v.([]interface{})
			if !isList {
				return parsing.Malformed("Invalid NATS endpoint list")
			}
			for _, item := range list {
				if _, isStr := item.(string); !isStr {
					return parsing.Malformed("Invalid NATS endpoint list")
				}
			}
		}
	}
	return nil
}

// imapServerCapability ports service_text.imap_capability.
func imapServerCapability(line []byte, maxHeaders int) (bool, error) {
	m := imapGreeting.FindSubmatch(line)
	greeting := m != nil
	if m == nil {
		m = imapCapability.FindSubmatch(line)
	}
	if m == nil {
		return false, nil
	}
	caps := bytes.Split(m[1], []byte(" "))
	limit := maxHeaders
	if limit > 128 {
		limit = 128
	}
	if len(caps) > limit {
		return false, parsing.Budget("IMAP capability count exceeds budget")
	}
	for _, c := range caps {
		if !imapAtom.Match(c) {
			return false, parsing.Malformed("Invalid IMAP capability atom")
		}
	}
	if greeting {
		text := m[2]
		for _, b := range text {
			if b < 32 || b == 127 {
				return false, parsing.Malformed("Invalid IMAP greeting text")
			}
		}
		if !utf8.Valid(text) {
			return false, parsing.Malformed("Invalid IMAP greeting encoding")
		}
	}
	for _, c := range caps {
		u := strings.ToUpper(string(c))
		if u == "IMAP4REV1" || u == "IMAP4REV2" {
			return true, nil
		}
	}
	return false, nil
}

// --- SIP / RTSP control headers ------------------------------------------------------------------

type controlHeaders struct {
	maxHeaders   int
	request      bool
	method       []byte
	protocolName string
	family       string
	fields       map[string][]byte
	count        int
	done         bool
	reason       string
}

func newControlHeaders(line []byte, maxHeaders int) (*controlHeaders, error) {
	c := &controlHeaders{maxHeaders: maxHeaders, fields: map[string][]byte{}, reason: "Waiting for control-protocol headers"}
	c.request = !(bytes.HasPrefix(line, []byte("SIP/")) || bytes.HasPrefix(line, []byte("RTSP/")))
	var version []byte
	if c.request {
		c.method, _, _ = bytes.Cut(line, []byte(" "))
		version = line[bytes.LastIndexByte(line, ' ')+1:]
	} else {
		version, _, _ = bytes.Cut(line, []byte(" "))
	}
	c.protocolName = strings.ToLower(string(version))
	if bytes.HasPrefix(version, []byte("SIP")) {
		c.family = "sip"
	} else {
		c.family = "rtsp"
	}
	if !c.request && c.family == "rtsp" {
		parts := bytes.SplitN(line, []byte(" "), 3)
		status, _ := strconv.Atoi(string(parts[1]))
		if status >= 600 {
			return nil, parsing.Malformed("Invalid RTSP response status class")
		}
	}
	return c, nil
}

func (c *controlHeaders) consume(line []byte) error {
	if len(line) == 0 {
		f := c.fields
		if c.family == "sip" {
			required := []string{"via", "from", "to", "call-id", "cseq"}
			if c.request {
				required = append(required, "max-forwards")
			}
			for _, r := range required {
				if _, ok := f[r]; !ok {
					return parsing.Malformed("SIP required headers missing")
				}
			}
			if !sipVia.Match(f["via"]) {
				return parsing.Malformed("Invalid SIP Via framing")
			}
			m := sipCSeq.FindSubmatch(f["cseq"])
			if m == nil {
				return parsing.Malformed("Invalid SIP CSeq or request-method mismatch")
			}
			n, _ := strconv.ParseInt(string(m[1]), 10, 64)
			if n >= 1<<31 || (c.request && !bytes.Equal(m[2], c.method)) {
				return parsing.Malformed("Invalid SIP CSeq or request-method mismatch")
			}
			if c.request {
				mf := f["max-forwards"]
				v, _ := strconv.Atoi(string(mf))
				if !maxForwardsRE.Match(mf) || v > 255 {
					return parsing.Malformed("Invalid SIP Max-Forwards")
				}
			}
		} else {
			cseq, ok := f["cseq"]
			n, _ := strconv.ParseInt(string(cseq), 10, 64)
			if !ok || !rtspCSeq.Match(cseq) || n >= 1<<31 {
				return parsing.Malformed("RTSP requires a valid CSeq")
			}
		}
		c.done = true
		c.reason = controlReason
		return nil
	}
	c.count++
	if c.count > c.maxHeaders {
		return parsing.Budget("Control-protocol header count exceeded")
	}
	nameB, value, hasColon := bytes.Cut(line, []byte(":"))
	if !hasColon || !headerName.Match(nameB) {
		return parsing.Malformed("Invalid control-protocol header")
	}
	for _, ch := range value {
		if (ch < 32 && ch != 9) || ch == 127 {
			return parsing.Malformed("Invalid control-protocol header")
		}
	}
	name := strings.ToLower(string(nameB))
	value = bytes.Trim(value, " \t")
	if c.family == "sip" {
		if full, ok := map[string]string{"v": "via", "f": "from", "t": "to", "i": "call-id", "l": "content-length"}[name]; ok {
			name = full
		}
	}
	switch name {
	case "via", "from", "to", "call-id", "cseq", "max-forwards", "content-length":
		_, seen := c.fields[name]
		if len(value) == 0 || (seen && name != "via") {
			return parsing.Malformed("Empty or duplicate singleton control header")
		}
		if name == "content-length" && !contentLengthRE.Match(value) {
			return parsing.Malformed("Invalid control-protocol Content-Length")
		}
		if !seen {
			c.fields[name] = value
		}
	}
	return nil
}
