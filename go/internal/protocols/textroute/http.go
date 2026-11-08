// Package httpx ports the text route (protocol_engine/extended.py TextParser) and the HTTP/1 start-line
// and header profile (parsers.py LineParser for protocol "http", media.py classes). Only HTTP is
// recognized here: the other text families the Python route resolves (SSH, SMTP, NATS, IMAP, POP3, FTP,
// IRC, SIP/RTSP control headers) end in NotPorted, except the exact ambiguity sentences that need no
// family parser. Header values are classified, never emitted.
package textroute

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Options mirrors the Config fields the parser reads.
type Options struct {
	MaxLine      int
	MaxHeaders   int
	MaxBytes     int
	Continuation int
}

const token = `[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+`

var (
	requestLine    = regexp.MustCompile(`^` + token + ` [\x21-\x7e]+ HTTP/1\.[01]$`)
	responseStrict = regexp.MustCompile(`^HTTP/1\.[01] [1-5][0-9]{2} [\x09\x20-\x7e\x80-\xff]*$`)
	responseLoose  = regexp.MustCompile(`^HTTP/1\.[01] [1-5][0-9]{2} .*$`)
	headerName     = regexp.MustCompile(`^` + token + `$`)
	contentLength  = regexp.MustCompile(`^[0-9]{1,20}$`)
	upgradeValue   = regexp.MustCompile(`^[\x21-\x7e]{1,64}(?:, *[\x21-\x7e]{1,64}){0,7}$`)
	wsKey          = regexp.MustCompile(`^[A-Za-z0-9+/]{22}==$`)
	wsAccept       = regexp.MustCompile(`^[A-Za-z0-9+/]{27}=$`)
	connectTarget  = regexp.MustCompile(`^(?:[A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]):[0-9]{1,5}$`)
	greeting220    = regexp.MustCompile(`^220(?:[ -]|$)`)
	imapTag        = regexp.MustCompile(`^[A-Za-z0-9.\-_]{1,32}$`)
	cmdVerb        = regexp.MustCompile(`^[A-Z]{3,4}$`)
	listElement    = regexp.MustCompile(`(?:"(?:[^"\\]|\\.)*"?|[^,"])+`)
	elementHead    = regexp.MustCompile(`^[ \t]*(` + token[:len(token)-1] + `*)[ \t]*(=?)`)
)

var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true, "UNLOCK": true, "REPORT": true, "SEARCH": true,
	"RPC_CONNECT": true, "RPC_IN_DATA": true, "RPC_OUT_DATA": true}

var authSchemes = map[string]string{"basic": "basic", "bearer": "bearer", "digest": "digest", "negotiate": "negotiate", "ntlm": "ntlm"}

var smtpCommands = map[string]bool{"EHLO": true, "HELO": true}
var smtpVerbs = set("EHLO HELO MAIL RCPT DATA RSET NOOP QUIT VRFY EXPN HELP AUTH BDAT STARTTLS")

var imapCommands = map[string]bool{"CAPABILITY": true, "NOOP": true, "LOGOUT": true, "STARTTLS": true, "AUTHENTICATE": true, "LOGIN": true, "ID": true, "ENABLE": true, "SELECT": true,
	"EXAMINE": true, "CREATE": true, "DELETE": true, "RENAME": true, "SUBSCRIBE": true, "UNSUBSCRIBE": true, "LIST": true, "LSUB": true, "NAMESPACE": true,
	"STATUS": true, "APPEND": true, "IDLE": true, "CHECK": true, "CLOSE": true, "UNSELECT": true, "EXPUNGE": true, "SEARCH": true, "FETCH": true, "STORE": true,
	"COPY": true, "MOVE": true, "UID": true, "XLIST": true, "GETQUOTAROOT": true, "COMPRESS": true}

var ftpOnly = set("ACCT CWD CDUP SMNT REIN PORT PASV TYPE STRU MODE STOR STOU APPE ALLO REST RNFR RNTO ABOR RMD MKD PWD NLST SITE SYST HELP FEAT OPTS PBSZ PROT EPSV EPRT MLSD MLST SIZE MDTM CCC CLNT XPWD XCWD XMKD XRMD")
var pop3Only = set("APOP CAPA STLS UIDL TOP RSET")
var shared = set("USER PASS QUIT NOOP STAT LIST RETR DELE AUTH")
var noArgument = set("QUIT NOOP STAT PWD XPWD SYST FEAT PASV EPSV CDUP REIN ABOR CAPA STLS UIDL RSET LIST NLST MLSD CCC")

func set(words string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(words) {
		out[w] = true
	}
	return out
}

type contentClass struct {
	prefix   string
	label    string
	isPrefix bool
}

var classes = []contentClass{
	{"application/grpc-web", "grpc-web", true}, {"application/grpc", "grpc", false}, {"application/grpc+", "grpc", true},
	{"application/dns-message", "dns", false}, {"application/ipp", "ipp", false}, {"application/ocsp-request", "ocsp", false},
	{"application/ocsp-response", "ocsp", false}, {"application/soap+xml", "soap", false}, {"application/json", "json", false},
	{"application/xml", "xml", false}, {"text/xml", "xml", false}, {"application/x-www-form-urlencoded", "form", false},
	{"multipart/", "multipart", true}, {"application/x-protobuf", "protobuf", false}, {"application/protobuf", "protobuf", false},
	{"application/vnd.google.protobuf", "protobuf", false}, {"application/octet-stream", "binary", false}, {"text/", "text", true},
}

// ContentTypeClass is the closed class of one media type (parameters ignored).
func ContentTypeClass(value []byte) string {
	media := value
	if i := bytes.IndexByte(media, ';'); i >= 0 {
		media = media[:i]
	}
	m := strings.ToLower(string(bytes.TrimSpace(media)))
	for _, c := range classes {
		if (c.isPrefix && strings.HasPrefix(m, c.prefix)) || (!c.isPrefix && m == c.prefix) {
			return c.label
		}
	}
	if strings.HasSuffix(m, "+json") {
		return "json"
	}
	if strings.HasSuffix(m, "+xml") {
		return "xml"
	}
	return "other"
}

func acceptClass(value []byte) string {
	first := value
	if i := bytes.IndexByte(first, ','); i >= 0 {
		first = first[:i]
	}
	return ContentTypeClass(first)
}

func authSchemeClass(value []byte) string {
	scheme := value
	if i := bytes.IndexByte(scheme, ' '); i >= 0 {
		scheme = scheme[:i]
	}
	if i := bytes.IndexByte(scheme, ','); i >= 0 {
		scheme = scheme[:i]
	}
	s := strings.ToLower(string(bytes.Trim(scheme, "\t")))
	if label, ok := authSchemes[s]; ok {
		return label
	}
	if s == "" {
		return "empty"
	}
	return "other"
}

func challengeSchemeClasses(value []byte) []string {
	var labels []string
	has := func(l string) bool {
		for _, x := range labels {
			if x == l {
				return true
			}
		}
		return false
	}
	for count, m := range listElement.FindAll(value, -1) {
		if count == 32 {
			break
		}
		head := elementHead.FindSubmatch(m)
		tok, equals := head[1], head[2]
		if len(tok) == 0 && len(head[0]) == len(m) {
			continue
		}
		var label string
		if len(tok) > 0 && len(equals) > 0 {
			if len(labels) > 0 {
				continue
			}
			label = "other"
		} else if len(tok) > 0 {
			label = "other"
			if l, ok := authSchemes[strings.ToLower(string(tok))]; ok {
				label = l
			}
		} else {
			label = "other"
		}
		if !has(label) {
			labels = append(labels, label)
		}
	}
	if len(labels) == 0 {
		return []string{"empty"}
	}
	return labels
}

// Parser is the HTTP/1 LineParser reached through the text route.
type Parser struct {
	opts             Options
	line             []byte
	first            bool
	headers          int
	host             string
	hasHost          bool
	hostCount        int
	http11Request    bool
	contentLength    int64
	hasContentLength bool
	transferEncoding bool
	done             bool
	protocolName     string
	reason           string
	method           string
	target           []byte
	status           int
	isRequest        bool
	contentTypeSeen  bool
	acceptSeen       bool
	authSchemes      []string
	challenges       []string
	upgrade          string
	hasUpgrade       bool
	connectionUpg    bool
	wsKey, wsVersion bool
	wsAccept         bool
	h2Settings       bool
	extra            []parsing.Row
	scope            string
	shift            *parsing.Shift
	family           string // "text" until the first line resolves the route (TextParser.family)
	mode             string // "", "http", "ssh", "smtp", "control", or a one-line family that is already done
	protocolName2    string // protocol name for the non-HTTP families
	continues        bool   // post-identification continuation (SSH KEXINIT, SMTP STARTTLS watch)
	refined          bool   // parsers.LineParser.refined: the published identification is complete
	kexinit          *kexInit
	smtpWatched      int
	control          *controlHeaders
	maxBytes         int
}

// ResolvedFamily is the family the first line resolved to ("text" before that).
func (p *Parser) ResolvedFamily() string {
	if p.family == "" {
		return "text"
	}
	return p.family
}

// New creates the text-route parser; the continuation option is NotPorted.
func New(opts Options) (*Parser, error) {
	if opts.Continuation != 0 {
		return nil, &parsing.NotPorted{What: "option continuation (HTTP)"}
	}
	return &Parser{opts: opts, first: true, reason: "Waiting for complete line", refined: true, maxBytes: opts.MaxBytes}, nil
}

// Refined reports whether the published identification is complete (false while a KEXINIT is awaited).
func (p *Parser) Refined() bool { return p.refined }

func (p *Parser) Done() bool { return p.done }

// Result exposes the identification once Done.
func (p *Parser) Result() *parsing.Result {
	if p.mode == "http" || p.mode == "" {
		return &parsing.Result{Family: "http", ProtocolName: p.protocolName, Host: p.host, HasHost: p.hasHost, HostSource: "http_host",
			ALPN: []string{}, Extra: p.extra, Reason: p.reason, Scope: p.scope, Shift: p.shift}
	}
	return &parsing.Result{Family: p.family, ProtocolName: p.protocolName2, ALPN: []string{}, Extra: p.extra, Reason: p.reason,
		Scope: p.scope, Shift: p.shift, Continues: p.continues}
}

// Feed ports LineParser.feed for the HTTP protocol (no SSH/IRC limits, no continuation).
func (p *Parser) Feed(data []byte) (int, error) {
	if p.continues && p.kexinit != nil {
		consumed, err := p.kexinit.feed(data)
		if err != nil {
			return consumed, err
		}
		if p.kexinit.done {
			p.extra = append(p.extra, kexinitPosture(p.kexinit.lists)...)
			p.refined, p.kexinit, p.continues = true, nil, false
		}
		return consumed, nil
	}
	continuing := p.done && p.continues
	pos := 0
	for pos < len(data) && (!p.done || (continuing && p.continues)) {
		newline := bytes.IndexByte(data[pos:], '\n')
		end := len(data)
		if newline >= 0 {
			end = pos + newline + 1
		}
		piece := data[pos:end]
		if len(p.line)+len(piece) > p.opts.MaxLine {
			return pos, parsing.Budget("Line length budget exceeded")
		}
		p.line = append(p.line, piece...)
		pos = end
		if newline < 0 {
			break
		}
		if !bytes.HasSuffix(p.line, []byte("\r\n")) {
			return pos, parsing.Malformed("Expected CRLF line ending")
		}
		line := append([]byte{}, p.line[:len(p.line)-2]...)
		p.line = p.line[:0]
		if err := p.consumeLine(line); err != nil {
			return pos, err
		}
	}
	return pos, nil
}

// route ports TextParser.consume_line's first-line dispatch. It returns handled=true when a non-HTTP
// family consumed the line (identified, or continuing), false when the line is an HTTP start-line.
func (p *Parser) route(line []byte) (bool, error) {
	isRequest := requestLine.Match(line)
	if !bytes.HasSuffix(line, []byte("HTTP/1.0")) && !bytes.HasSuffix(line, []byte("HTTP/1.1")) && controlStartRE.Match(line) {
		control, err := newControlHeaders(line, p.opts.MaxHeaders)
		if err != nil {
			return true, err
		}
		p.control, p.mode, p.family, p.protocolName2, p.scope = control, "control", control.family, control.protocolName, "initial_headers"
		p.reason = control.reason
		return true, nil
	}
	command := line
	if i := bytes.IndexByte(line, ' '); i >= 0 {
		command = line[:i]
	}
	upper := strings.ToUpper(string(command))
	special := bytes.HasPrefix(line, []byte("SSH-")) || smtpCommands[upper]
	if len(line) > 0 {
		switch line[0] {
		case 'I', 'i', 'C', 'c', '*':
			special = true
		}
	}
	if special && isRequest {
		return false, nil // HTTP
	}
	if bytes.HasPrefix(line, []byte("SSH-")) {
		p.family, p.mode = "ssh", "ssh"
		if len(line)+2 > 255 {
			return true, parsing.Malformed("SSH identification exceeds 255 bytes")
		}
		if !sshBanner.Match(line) {
			return true, parsing.Malformed("Invalid or unsupported SSH identification")
		}
		parts := bytes.SplitN(line, []byte("-"), 3)
		p.protocolName2, p.done, p.reason = "ssh", true, sshReason
		p.extra = []parsing.Row{{Field: "ssh_version", Value: string(parts[1]), Provenance: "banner", Strength: "structural"}}
		p.kexinit, p.continues, p.refined = newKexInit(p.maxBytes), true, false
		return true, nil
	}
	if smtpCommands[upper] {
		p.family, p.mode = "smtp", "smtp"
		if len(line)+2 > 512 {
			return true, parsing.Malformed("SMTP command exceeds 512 bytes")
		}
		_, identity, sep := bytes.Cut(line, []byte(" "))
		if !sep || len(identity) == 0 {
			return true, parsing.Malformed("SMTP greeting needs a domain or address literal")
		}
		text, ok := smtpIdentity(identity)
		if !ok {
			return true, parsing.Malformed("Invalid SMTP greeting identity")
		}
		p.protocolName2, p.done = "smtp", true
		p.reason = "SMTP client EHLO/HELO syntax validated; server exchange and message body not inspected"
		p.extra = []parsing.Row{{Field: "smtp_client_identity", Value: text, Provenance: "smtp_greeting", Strength: "asserted"}}
		p.continues = true
		return true, nil
	}
	if len(line) > 0 && (line[0] == 'I' || line[0] == 'i' || line[0] == 'C' || line[0] == 'c') {
		if m := natsStart.FindSubmatch(line); m != nil {
			if err := natsHandshake(strings.ToUpper(string(m[1])), m[2], p.opts.MaxHeaders); err != nil {
				return true, err
			}
			p.family, p.mode, p.protocolName2, p.scope, p.done, p.reason = "nats", "nats", "nats", "protocol_header", true, natsReason
			return true, nil
		}
	}
	if bytes.HasPrefix(line, []byte("* ")) {
		ok, err := imapServerCapability(line, p.opts.MaxHeaders)
		if err != nil {
			return true, err
		}
		if !ok {
			return true, parsing.Ambiguous("Untagged text without explicit IMAP revision capabilities is ambiguous", "imap")
		}
		p.family, p.mode, p.protocolName2, p.scope, p.done, p.reason = "imap", "imap", "imap", "protocol_header", true, imapSrvReason
		return true, nil
	}
	if greeting220.Match(line) {
		return true, parsing.Ambiguous("A 220 server greeting alone is ambiguous between SMTP and FTP; a client command is required", "smtp", "ftp")
	}
	if isRequest || responseLoose.Match(line) {
		return false, nil
	}
	// Not HTTP: the families Python tries before falling back to the HTTP start-line error.
	if len(line) > 0 && (line[0] == '+' || line[0] == '-') {
		if ok, err := pop3Greeting(line); err != nil {
			return true, err
		} else if ok {
			p.family, p.mode, p.protocolName2, p.scope, p.done = "pop3", "pop3", "pop3", "protocol_header", true
			p.reason = "POP3 server status line validated; mailbox and authentication unverified"
			return true, nil
		}
	}
	if ok, err := imapCommand(line, p.opts.MaxLine); err != nil {
		return true, err
	} else if ok {
		p.family, p.mode, p.protocolName2, p.scope, p.done = "imap", "imap", "imap", "initial_message", true
		p.reason = "IMAP tagged client command validated; arguments and credentials are not inspected or emitted"
		if parts := bytes.Split(line, []byte(" ")); len(parts) > 1 && strings.ToUpper(string(parts[1])) == "STARTTLS" {
			p.shift = &parsing.Shift{Boundary: "starttls", Expected: "tls"}
		}
		return true, nil
	}
	label, err := ircClientLine(line)
	if err != nil {
		return true, err
	}
	if label == "" && len(line) > 0 {
		switch line[0] {
		case 'N', 'n', 'P', 'p':
			if label, err = ircServerNotice(line); err != nil {
				return true, err
			}
		}
	}
	if label == "user" {
		return true, parsing.Ambiguous("USER with four parameters is valid for FTP and IRC; the server direction decides", "ftp", "irc")
	}
	if label != "" {
		p.family, p.mode, p.protocolName2, p.done = "irc", "irc", "irc", true
		p.scope = "protocol_header"
		if label == "nick" || label == "user" || label == "cap" {
			p.scope = "initial_message"
		}
		p.extra = []parsing.Row{{Field: "irc_message", Value: label, Provenance: "irc_line", Strength: "structural"}}
		p.reason = ircReason(label)
		return true, nil
	}
	family, candidates, shift, err := commandLine(line)
	if err != nil {
		return true, err
	}
	if candidates != nil {
		if family == "" {
			return true, parsing.Ambiguous("Command shared by FTP and POP3; the server greeting decides", candidates...)
		}
		p.family, p.mode, p.protocolName2, p.scope, p.done, p.shift = family, family, family, "initial_message", true, shift
		if family == "ftp" {
			p.reason = "FTP client command syntax validated; arguments are not emitted, transfers unverified"
		} else {
			p.reason = "POP3 client command syntax validated; credentials are not emitted, mailbox unverified"
		}
		return true, nil
	}
	return false, nil
}

// smtpIdentity validates an EHLO/HELO argument (domain or [address literal]); the text is reported as asserted.
func smtpIdentity(identity []byte) (string, bool) {
	for _, b := range identity {
		if b >= 128 {
			return "", false
		}
	}
	text := string(identity)
	if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
		address := text[1 : len(text)-1]
		if strings.HasPrefix(strings.ToLower(address), "ipv6:") {
			return text, names.IsIPv6(address[5:])
		}
		return text, names.IsIPv4(address)
	}
	if _, err := names.Normalize(text); err != nil {
		return "", false
	}
	return text, true
}

// consumeSMTP ports TextParser._consume_smtp: watch a bounded number of client commands for STARTTLS.
func (p *Parser) consumeSMTP(line []byte) error {
	p.smtpWatched++
	if len(line)+2 > 512 {
		return parsing.Malformed("SMTP command exceeds 512 bytes")
	}
	verbB, _, _ := bytes.Cut(line, []byte(" "))
	verb := strings.ToUpper(string(verbB))
	if !smtpVerbs[verb] {
		return parsing.Malformed("Unexpected SMTP command")
	}
	if verb == "STARTTLS" {
		if strings.ToUpper(string(line)) != "STARTTLS" {
			return parsing.Malformed("STARTTLS takes no parameters")
		}
		p.shift = &parsing.Shift{Boundary: "starttls", Expected: "tls"}
		p.continues = false
		return nil
	}
	limit := p.opts.MaxHeaders
	if limit > 8 {
		limit = 8
	}
	if verb != "NOOP" || p.smtpWatched >= limit {
		p.continues = false
	}
	return nil
}

func pop3Greeting(line []byte) (bool, error) {
	var rest []byte
	switch {
	case bytes.HasPrefix(line, []byte("+OK")):
		rest = line[3:]
	case bytes.HasPrefix(line, []byte("-ERR")):
		rest = line[4:]
	default:
		return false, nil
	}
	if len(rest) > 0 {
		bad := rest[0] != ' '
		if !bad {
			arg := rest[1:]
			if len(arg) == 0 {
				arg = []byte(" ")
			}
			bad = !printableArgument(arg)
		}
		if bad && !bytes.Equal(rest, []byte(" ")) {
			return false, parsing.Malformed("POP3 status line text outside printable profile")
		}
	}
	return true, nil
}

func printableArgument(arg []byte) bool {
	if len(arg) < 1 || len(arg) > 512 {
		return false
	}
	for _, b := range arg {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func imapCommand(line []byte, maxLine int) (bool, error) {
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) < 2 || !imapTag.Match(parts[0]) {
		return false, nil
	}
	tag := strings.ToUpper(string(parts[0]))
	if tag == "OK" || tag == "NO" || tag == "BAD" {
		return false, nil
	}
	command := strings.ToUpper(string(parts[1]))
	if !imapCommands[command] {
		return false, nil
	}
	if len(line) > maxLine {
		return false, parsing.Budget("IMAP command exceeds line budget")
	}
	for _, b := range line {
		if b < 32 || b > 126 {
			return false, parsing.Malformed("IMAP command outside printable profile")
		}
	}
	switch command {
	case "LOGIN", "AUTHENTICATE", "SELECT", "EXAMINE", "FETCH", "STORE", "SEARCH", "COPY", "MOVE", "STATUS":
		if len(parts) < 3 {
			return false, parsing.Malformed("IMAP command requires arguments")
		}
	case "CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "IDLE", "CHECK", "CLOSE", "EXPUNGE", "NAMESPACE":
		if len(parts) > 2 {
			return false, parsing.Malformed("IMAP command does not take arguments")
		}
	}
	return true, nil
}

var portArgument = regexp.MustCompile(`^(\d{1,3},){5}\d{1,3}$`)
var topArgument = regexp.MustCompile(`^\d{1,10} \d{1,10}$`)

// commandLine ports session_text.command_line: (family or "" for ambiguous, candidates, shift, error);
// candidates is nil when the line is not a command at all.
func commandLine(line []byte) (string, []string, *parsing.Shift, error) {
	if len(line) < 3 || len(line) > 520 {
		return "", nil, nil, nil
	}
	for _, b := range line {
		if b < 32 || b > 126 {
			return "", nil, nil, nil
		}
	}
	verbB, argument, hasSep := bytes.Cut(line, []byte(" "))
	verb := strings.ToUpper(string(verbB))
	if !cmdVerb.MatchString(verb) {
		return "", nil, nil, nil
	}
	if hasSep && !printableArgument(argument) {
		return "", nil, nil, parsing.Malformed("Command argument outside printable profile")
	}
	if noArgument[verb] && hasSep && len(argument) > 0 {
		switch verb {
		case "LIST", "NLST", "MLSD", "STAT", "UIDL", "TOP", "PASV":
		default:
			return "", nil, nil, parsing.Malformed("Command does not take an argument")
		}
	}
	if ftpOnly[verb] {
		switch verb {
		case "PORT", "EPRT", "TYPE", "CWD", "MKD", "RMD", "STOR", "APPE", "RNFR", "RNTO", "SIZE", "MDTM", "OPTS":
			if len(argument) == 0 {
				return "", nil, nil, parsing.Malformed("FTP command requires an argument")
			}
		}
		if verb == "TYPE" {
			a := strings.ToUpper(string(argument))
			if len(a) == 0 || !strings.ContainsRune("AIEL", rune(a[0])) {
				return "", nil, nil, parsing.Malformed("FTP TYPE argument invalid")
			}
		}
		if verb == "PORT" && !portArgument.Match(argument) {
			return "", nil, nil, parsing.Malformed("FTP PORT argument invalid")
		}
		return "ftp", []string{"ftp"}, nil, nil
	}
	if pop3Only[verb] {
		if verb == "APOP" && len(bytes.Split(argument, []byte(" "))) != 2 {
			return "", nil, nil, parsing.Malformed("POP3 APOP requires name and digest")
		}
		if verb == "TOP" && !topArgument.Match(argument) {
			return "", nil, nil, parsing.Malformed("POP3 TOP requires two numbers")
		}
		var shift *parsing.Shift
		if verb == "STLS" {
			shift = &parsing.Shift{Boundary: "starttls", Expected: "tls"}
		}
		return "pop3", []string{"pop3"}, shift, nil
	}
	if shared[verb] {
		if (verb == "USER" || verb == "PASS" || verb == "AUTH" || verb == "RETR" || verb == "DELE") && len(argument) == 0 {
			return "", nil, nil, parsing.Malformed("Command requires an argument")
		}
		if verb == "AUTH" {
			switch strings.ToUpper(string(argument)) {
			case "TLS", "SSL", "TLS-C", "TLS-P":
				return "ftp", []string{"ftp"}, &parsing.Shift{Boundary: "auth-tls", Expected: "tls"}, nil
			}
		}
		if verb == "PASS" {
			return "", []string{"ftp", "pop3", "irc"}, nil, nil
		}
		return "", []string{"ftp", "pop3"}, nil, nil
	}
	return "", nil, nil, nil
}

func (p *Parser) consumeLine(line []byte) error {
	switch p.mode {
	case "control":
		if err := p.control.consume(line); err != nil {
			return err
		}
		p.done, p.reason = p.control.done, p.control.reason
		return nil
	case "smtp":
		return p.consumeSMTP(line)
	}
	if p.first {
		handled, err := p.route(line)
		if err != nil {
			return err
		}
		if handled {
			p.first = false
			return nil
		}
		p.family, p.mode = "http", "http"
		p.first = false
		request := requestLine.Match(line)
		response := responseStrict.Match(line)
		if !request && !response {
			return parsing.Malformed("Unsupported HTTP/1.x start-line")
		}
		p.isRequest = request
		p.http11Request = request && bytes.HasSuffix(line, []byte("HTTP/1.1"))
		var version []byte
		if request {
			i := bytes.LastIndexByte(line, ' ')
			version = line[i+1:]
			parts := bytes.SplitN(line, []byte(" "), 3)
			p.method = strings.ToUpper(string(parts[0]))
			p.target = parts[1]
			if p.method != "CONNECT" {
				label := "extension"
				if methods[p.method] {
					label = p.method
				}
				p.extra = append(p.extra, parsing.Row{Field: "http_method", Value: label, Provenance: "request_line", Strength: "structural"})
			}
		} else {
			parts := bytes.SplitN(line, []byte(" "), 3)
			version = parts[0]
			p.status, _ = strconv.Atoi(string(parts[1]))
			p.extra = append(p.extra, parsing.Row{Field: "http_status", Value: strconv.Itoa(p.status), Provenance: "status_line", Strength: "structural"})
		}
		if bytes.Equal(version, []byte("HTTP/1.1")) {
			p.protocolName = "http/1.1"
		} else {
			p.protocolName = "http/1.0"
		}
		p.reason = "Start-line validated; waiting for headers"
		return nil
	}
	if len(line) == 0 {
		if p.http11Request && p.hostCount != 1 {
			return parsing.Malformed("HTTP/1.1 request requires one Host")
		}
		if p.transferEncoding && p.hasContentLength {
			return parsing.Malformed("Ambiguous Transfer-Encoding and Content-Length")
		}
		p.done = true
		p.reason = "HTTP start-line and headers validated; body and later requests not inspected"
		return p.shiftBoundary()
	}
	p.headers++
	if p.headers > p.opts.MaxHeaders {
		return parsing.Budget("Header count budget exceeded")
	}
	nameB, value, hasColon := bytes.Cut(line, []byte(":"))
	if !hasColon || !headerName.Match(nameB) {
		return parsing.Malformed("Invalid header name")
	}
	for _, c := range value {
		if (c < 32 && c != 9) || c == 127 {
			return parsing.Malformed("Control byte in header")
		}
	}
	name := strings.ToLower(string(nameB))
	value = bytes.Trim(value, " \t")
	switch name {
	case "host":
		p.hostCount++
		if p.hostCount > 1 || len(value) == 0 {
			return parsing.Malformed("Duplicate or empty Host")
		}
		if err := p.parseHost(value); err != nil {
			return parsing.Malformed("Invalid Host authority")
		}
	case "content-type":
		if !p.contentTypeSeen {
			p.contentTypeSeen = true
			p.extra = append(p.extra, parsing.Row{Field: "http_content_type", Value: ContentTypeClass(value), Provenance: "headers", Strength: "asserted"})
		}
	case "accept":
		if !p.acceptSeen {
			p.acceptSeen = true
			if acceptClass(value) == "dns" {
				p.extra = append(p.extra, parsing.Row{Field: "http_accept", Value: "dns", Provenance: "headers", Strength: "asserted"})
			}
		}
	case "authorization", "proxy-authorization":
		label := authSchemeClass(value)
		if !contains(p.authSchemes, label) {
			p.authSchemes = append(p.authSchemes, label)
			p.extra = append(p.extra, parsing.Row{Field: "http_auth_scheme", Value: label, Provenance: "headers", Strength: "asserted"})
		}
	case "www-authenticate", "proxy-authenticate":
		for _, label := range challengeSchemeClasses(value) {
			if !contains(p.challenges, label) {
				p.challenges = append(p.challenges, label)
				p.extra = append(p.extra, parsing.Row{Field: "http_auth_challenge", Value: label, Provenance: "headers", Strength: "asserted"})
			}
		}
	case "content-length":
		if p.hasContentLength || !contentLength.Match(value) {
			return parsing.Malformed("Invalid or duplicate Content-Length")
		}
		p.hasContentLength = true
		p.contentLength, _ = strconv.ParseInt(string(value), 10, 64)
	case "transfer-encoding":
		if p.transferEncoding || strings.ToLower(string(value)) != "chunked" {
			return parsing.Malformed("Unsupported or duplicate Transfer-Encoding")
		}
		p.transferEncoding = true
	case "upgrade":
		if p.hasUpgrade || !upgradeValue.Match(value) {
			return parsing.Malformed("Invalid or duplicate Upgrade header")
		}
		first, _, _ := bytes.Cut(value, []byte(","))
		p.upgrade, p.hasUpgrade = strings.ToLower(string(bytes.TrimSpace(first))), true
	case "connection":
		for _, tok := range bytes.Split(value, []byte(",")) {
			if strings.ToLower(string(bytes.TrimSpace(tok))) == "upgrade" {
				p.connectionUpg = true
			}
		}
	case "sec-websocket-key":
		if p.wsKey || !wsKey.Match(value) {
			return parsing.Malformed("Invalid or duplicate Sec-WebSocket-Key")
		}
		p.wsKey = true
	case "sec-websocket-version":
		if p.wsVersion || !bytes.Equal(value, []byte("13")) {
			return parsing.Malformed("Unsupported or duplicate Sec-WebSocket-Version")
		}
		p.wsVersion = true
	case "sec-websocket-accept":
		if p.wsAccept || !wsAccept.Match(value) {
			return parsing.Malformed("Invalid or duplicate Sec-WebSocket-Accept")
		}
		p.wsAccept = true
	case "http2-settings":
		if p.h2Settings || !h2SettingsValue(value) {
			return parsing.Malformed("Invalid or duplicate HTTP2-Settings")
		}
		p.h2Settings = true
	}
	return nil
}

// h2SettingsValue ports the base64url character check `[A-Za-z0-9_\-]{0,1024}` (RE2 caps repeat counts).
func h2SettingsValue(value []byte) bool {
	if len(value) > 1024 {
		return false
	}
	for _, c := range value {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func validPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n <= 65535
}

func (p *Parser) parseHost(value []byte) error {
	for _, c := range value {
		if c >= 128 {
			return parsing.Malformed("Invalid Host authority")
		}
	}
	text := string(value)
	if strings.HasPrefix(text, "[") {
		closing := strings.IndexByte(text, ']')
		if closing < 0 || !names.IsIPv6(text[1:closing]) {
			return parsing.Malformed("Invalid Host authority")
		}
		suffix := text[closing+1:]
		if suffix != "" && (!strings.HasPrefix(suffix, ":") || len(suffix) > 6 || !validPort(suffix[1:])) {
			return parsing.Malformed("Invalid Host authority")
		}
		return nil
	}
	host, port, hasPort := strings.Cut(text, ":")
	if hasPort && !validPort(port) {
		return parsing.Malformed("Invalid Host authority")
	}
	if names.IsIPv4(host) {
		return nil
	}
	normalized, err := names.Normalize(host)
	if err != nil {
		return parsing.Malformed("Invalid Host authority")
	}
	p.host, p.hasHost = normalized, true
	return nil
}

func (p *Parser) shiftBoundary() error {
	if p.method == "CONNECT" {
		if !connectTarget.Match(p.target) {
			return nil
		}
		p.scope = "tunnel_request"
		p.extra = append(p.extra, parsing.Row{Field: "http_method", Value: "CONNECT", Provenance: "request_line", Strength: "structural"})
		p.shift = &parsing.Shift{Boundary: "http-connect"}
		return nil
	}
	if !p.hasUpgrade {
		return nil
	}
	tok := "other"
	if p.upgrade == "websocket" || p.upgrade == "h2c" {
		tok = p.upgrade
	}
	p.extra = append(p.extra, parsing.Row{Field: "http_upgrade", Value: tok, Provenance: "headers", Strength: "structural"})
	if p.isRequest {
		if !p.connectionUpg {
			return parsing.Malformed("Upgrade requires a Connection: Upgrade header")
		}
		if (p.hasContentLength && p.contentLength != 0) || p.transferEncoding {
			return nil
		}
		if tok == "websocket" {
			if p.method != "GET" || !(p.wsKey && p.wsVersion) {
				return parsing.Malformed("WebSocket upgrade requires GET with Sec-WebSocket-Key and -Version 13")
			}
			p.shift = &parsing.Shift{Boundary: "websocket-upgrade", Expected: "websocket"}
		} else if tok == "h2c" && p.h2Settings {
			p.shift = &parsing.Shift{Boundary: "h2c-upgrade", Expected: "http2"}
		}
	} else if p.status == 101 {
		if tok == "websocket" {
			if !p.wsAccept {
				return parsing.Malformed("101 websocket upgrade requires Sec-WebSocket-Accept")
			}
			p.shift = &parsing.Shift{Boundary: "websocket-upgrade", Expected: "websocket"}
		} else if tok == "h2c" {
			if !p.connectionUpg {
				return parsing.Malformed("101 h2c upgrade requires a Connection: Upgrade header")
			}
			p.shift = &parsing.Shift{Boundary: "h2c-upgrade", Expected: "http2-server"}
		}
	}
	return nil
}
