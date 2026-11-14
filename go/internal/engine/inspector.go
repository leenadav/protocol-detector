package engine

import (
	"reflect"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/dnsx"
	"github.com/leenadav/protocol-detector/go/internal/protocols/framed"
	"github.com/leenadav/protocol-detector/go/internal/protocols/textroute"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

// Ported is the set of candidates a caller or a shift may name as a hint: every candidate the factory builds
// except the internal routes (review R5, 2026-11-14: a hand-kept copy of this set had drifted from the factory,
// so New refused the hint "kerberos" although the parser was ported and dispatch selected it).
var Ported = map[string]bool{}

// internalCandidates are dispatch routes that are not registry names; Python rejects them as hints too.
var internalCandidates = map[string]bool{"git_text": true}

// Families the Go backend can identify (for CAPABILITIES statuses and the harness filter).
var Families = []string{"http", "tls", "dns", "mdns", "netbios-ns", "llmnr", "ssh", "smtp", "imap", "pop3", "ftp", "nats", "irc", "sip", "rtsp", "telnet",
	"postgresql", "rfb", "bittorrent", "memcached", "rsync", "fins", "afp", "zmtp", "bolt", "stomp",
	"giop", "x11", "spice", "mysql", "mongodb", "tds", "tns", "cql", "kafka",
	"modbus", "dnp3", "ethernet-ip", "iec-104", "opcua", "s7comm",
	"mqtt", "resp", "amqp", "onc-rpc", "diameter",
	"bgp", "openvpn", "pptp", "fastcgi",
	"dcerpc", "websocket", "xmpp", "syslog", "git",
	"netbios-ss", "tacacs-plus", "socks5", "wireguard", "bacnet",
	"tftp", "ntp", "l2tp", "coap", "rip", "rtcp", "lifx-lan", "tuya-lan",
	"netflow", "ipfix", "sflow", "stun", "dhcp", "radius", "snmp", "rtp", "ssdp", "tplink-smarthome", "kerberos", "ldap", "smb1", "smb2"}

// factories builds the parser of each candidate; it is the single registry of what the Go backend ports.
var factories map[string]func(cfg contracts.Config) (parsing.Parser, error)

func init() {
	factories = map[string]func(cfg contracts.Config) (parsing.Parser, error){
		"text": func(cfg contracts.Config) (parsing.Parser, error) {
			return textroute.New(textroute.Options{MaxLine: cfg.MaxLine, MaxHeaders: cfg.MaxHeaders, MaxBytes: cfg.MaxBytes, Continuation: cfg.Continuation})
		},
		"irc": func(cfg contracts.Config) (parsing.Parser, error) {
			return textroute.NewIRC(cfg.MaxLine), nil
		},
		"telnet": func(cfg contracts.Config) (parsing.Parser, error) {
			return textroute.NewTelnet(), nil
		},
		"postgresql": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewPostgreSQL(cfg.MaxBytes), nil
		},
		"rfb": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewRFB(cfg.MaxBytes), nil
		},
		"bittorrent": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewBitTorrent(cfg.MaxBytes), nil
		},
		"memcached": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewMemcached(cfg.MaxBytes), nil
		},
		"rsync": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewRsync(cfg.MaxLine, cfg.MaxHeaders), nil
		},
		"fins": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewFINS(cfg.MaxBytes), nil
		},
		"afp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewAFP(cfg.MaxBytes), nil
		},
		"zmtp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewZMTP(cfg.MaxBytes), nil
		},
		"bolt": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewBolt(cfg.MaxBytes), nil
		},
		"stomp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSTOMP(cfg.MaxLine, cfg.MaxHeaders), nil
		},
		"giop": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewGIOP(cfg.MaxBytes, cfg.MaxLine, cfg.MaxHeaders), nil
		},
		"x11": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewX11(cfg.MaxBytes), nil
		},
		"x11-server": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewX11Reply(cfg.MaxBytes), nil
		},
		"spice": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSPICE(cfg.MaxBytes), nil
		},
		"mysql": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewMySQL(cfg.MaxBytes), nil
		},
		"mongodb": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewMongoDB(framed.MongoConfig{MaxBytes: cfg.MaxBytes, MaxHeaders: cfg.MaxHeaders, MaxLine: cfg.MaxLine, MaxCRC32CBytes: cfg.MaxCRC32CBytes}), nil
		},
		"tds": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewTDS(cfg.MaxBytes), nil
		},
		"tns": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewTNS(cfg.MaxBytes), nil
		},
		"kerberos": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewKerberos(cfg.MaxBytes, cfg.MaxHeaders), nil
		},
		"smb1": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSMB1(cfg.MaxBytes, cfg.MaxHeaders), nil
		},
		"smb2": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSMB2(cfg.MaxBytes), nil
		},
		"ldap": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewLDAP(cfg.MaxBytes), nil
		},
		"cql": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewCQL(cfg.MaxBytes), nil
		},
		"kafka": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewKafka(cfg.MaxBytes), nil
		},
		"modbus": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewModbus(cfg.MaxBytes), nil
		},
		"dnp3": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewDNP3(cfg.MaxBytes), nil
		},
		"ethernet-ip": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewENIP(cfg.MaxBytes), nil
		},
		"iec-104": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewIEC104(cfg.MaxBytes), nil
		},
		"opcua": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewOPCUA(cfg.MaxBytes), nil
		},
		"s7comm": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewS7(cfg.MaxBytes), nil
		},
		"mqtt": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewMQTT(cfg.MaxBytes), nil
		},
		"resp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewRESP(cfg.MaxBytes), nil
		},
		"amqp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewAMQP(), nil
		},
		"onc-rpc": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewRPC(cfg.MaxBytes), nil
		},
		"diameter": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewDiameter(cfg.MaxBytes, cfg.MaxHeaders), nil
		},
		"bgp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewBGP(cfg.MaxBytes), nil
		},
		"openvpn": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewOpenVPN(cfg.MaxBytes), nil
		},
		"pptp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewPPTP(cfg.MaxBytes), nil
		},
		"fastcgi": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewFastCGI(cfg.MaxBytes, cfg.MaxHeaders), nil
		},
		"dcerpc": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewDCERPC(cfg.MaxBytes, cfg.MaxHeaders), nil
		},
		"websocket": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewWebSocket(), nil
		},
		"xmpp": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewXMPP(cfg.MaxLine), nil
		},
		"syslog": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSyslog(cfg.MaxLine), nil
		},
		"git": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewGit(cfg.MaxBytes, cfg.MaxLine, cfg.MaxHeaders), nil
		},
		"netbios-ss": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewNetBIOSSession(cfg.MaxBytes), nil
		},
		"tacacs-plus": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewTACACS(cfg.MaxBytes), nil
		},
		"socks5": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewSOCKS5(), nil
		},
		"git_text": func(cfg contracts.Config) (parsing.Parser, error) {
			return framed.NewGitText(cfg.MaxLine,
				func() parsing.Parser { return framed.NewGit(cfg.MaxBytes, cfg.MaxLine, cfg.MaxHeaders) },
				func() (parsing.Parser, error) { return factory("text", cfg) }), nil
		},
		"tls": func(cfg contracts.Config) (parsing.Parser, error) {
			return tlsx.New(tlsx.Options{MaxBytes: cfg.MaxBytes, MaxHeaders: cfg.MaxHeaders, Fingerprints: cfg.Fingerprints,
				Certificates: cfg.Certificates, Continuation: cfg.Continuation})
		},
		"dns": func(cfg contracts.Config) (parsing.Parser, error) {
			return dnsx.NewTCP(cfg.MaxBytes), nil
		},
	}
	for name := range factories {
		if !internalCandidates[name] {
			Ported[name] = true
		}
	}
}

func factory(candidate string, cfg contracts.Config) (parsing.Parser, error) {
	if build, ok := factories[candidate]; ok {
		return build(cfg)
	}
	return nil, &parsing.NotPorted{What: "family " + candidate}
}

// Inspector is one direction of one ordered stream (engine.Inspector). Not safe for concurrent use.
type Inspector struct {
	cfg         contracts.Config
	hint        string
	hintSource  string
	source      string
	Observation contracts.Observation
	Metrics     contracts.Metrics
	revision    int
	prefix      []byte
	parser      parsing.Parser
	candidate   string
	terminal    bool
	Boundary    int // stream offset where a terminal identified message ended (-1: none)
	hasBoundary bool
	next        *Inspector
	carrier     *contracts.Observation
	shift       string
	shiftSource string
	NotPorted   *parsing.NotPorted // set when the Go backend cannot give this direction's outcome
	resolved    string             // family a text route resolved to before it finished (D12)
	continuing  bool               // identified; the parser still derives optional evidence or watches for a shift
	// Host-correlation metadata, never emitted: the identifying parser's LDAP message id, and the identification
	// that announced this inspector's shift (kept after the shifted phase merges; Python Inspector.announcement).
	ldapID       int
	hasLDAPID    bool
	Announcement *contracts.Observation
}

// LDAPMessageID reports the message id of the LDAP message this inspector identified (Python
// inspector.correlation["ldap_message_id"]).
func (in *Inspector) LDAPMessageID() (int, bool) { return in.ldapID, in.hasLDAPID }

// OpenShift ports Inspector.open_shift: a host-driven shift on this direction because the peer direction
// established that the boundary applies here too (an HTTP 2xx answering CONNECT, an LDAP StartTLS success).
// Allowed only on a terminal identified observation that has not shifted, with at least 64 bytes of budget left;
// it reports whether the next bytes will be inspected as the new phase. expected is "" or a ported candidate.
func (in *Inspector) OpenShift(boundary, expected string) bool {
	if len(boundary) < 1 || len(boundary) > 64 {
		panic("engine: shift boundary must be a short name")
	}
	if !in.terminal || in.next != nil || in.Observation.Status != contracts.Identified || in.NotPorted != nil {
		return false
	}
	for _, e := range in.Observation.Evidence {
		if e.Field == "shift" {
			return false
		}
	}
	remaining := in.cfg.MaxBytes - in.Metrics.BytesInspected
	if remaining < 64 {
		return false
	}
	cfg := in.cfg
	cfg.MaxBytes = remaining
	next, err := New(cfg, expected)
	if err != nil {
		if np, ok := err.(*parsing.NotPorted); ok {
			in.NotPorted = np
		} else {
			in.NotPorted = &parsing.NotPorted{What: "shift to " + expected}
		}
		return false
	}
	carrier := in.Observation
	in.carrier, in.shift, in.shiftSource = &carrier, boundary, in.source+":peer"
	announced := carrier
	in.Announcement = &announced
	next.hintSource = "shift:" + boundary
	in.next = next
	in.terminal = false
	return true
}

// Replay ports Inspector.replay: bytes this inspector skipped while terminal, retained by the host, fed into a
// phase the peer direction opened. They were counted as received when first offered and are not counted again.
// It returns false (and nothing) when no host-opened phase is pending or data exceeds the skipped bytes.
func (in *Inspector) Replay(data []byte) ([]contracts.Event, bool) {
	if in.next == nil || in.terminal || in.shiftSource != in.source+":peer" {
		return nil, false
	}
	if len(data) > in.Metrics.BytesReceived-in.Metrics.BytesInspected {
		return nil, false
	}
	in.Metrics.BytesReceived -= len(data)
	return in.Feed(data), true
}

// HasBoundary reports whether Boundary is set (a terminal identified message ended there).
func (in *Inspector) HasBoundary() bool { return in.hasBoundary }

// refiner is implemented by parsers whose published identification may be incomplete while they continue.
type refiner interface{ Refined() bool }

// refined ports Inspector._refined: rebuilt only when the parser derived something new.
func (in *Inspector) refined() contracts.Observation {
	if r, ok := in.parser.(refiner); ok && !r.Refined() {
		return in.Observation
	}
	return in.identified()
}

// continueFeed ports Inspector._continue: bytes for a parser that already identified.
func (in *Inspector) continueFeed(chunk []byte) []contracts.Event {
	consumed, err := in.parser.Feed(chunk)
	if err != nil {
		if np, ok := err.(*parsing.NotPorted); ok {
			in.NotPorted, in.terminal = np, true
			return nil
		}
		in.Metrics.BytesInspected += len(chunk)
		return in.finish(in.refined(), contracts.Refined)
	}
	in.Metrics.BytesInspected += consumed
	r := in.parser.Result()
	if !r.Continues {
		if r.Shift != nil {
			return in.beginShift(r.Shift, chunk[consumed:])
		}
		return in.finish(in.refined(), contracts.Refined)
	}
	if in.Metrics.BytesInspected >= in.cfg.MaxBytes {
		return in.finish(in.refined(), contracts.Refined)
	}
	return nil
}

// familyResolver is implemented by routed parsers that learn their family from the first line.
type familyResolver interface{ ResolvedFamily() string }

// ResolvedFamily ports Inspector.resolved_family: the candidate, or what a text route resolved to ("" for none).
func (in *Inspector) ResolvedFamily() string {
	if in.candidate == "text" || in.candidate == "git_text" || in.candidate == "tpkt" {
		if in.resolved == "" || in.resolved == "text" {
			return ""
		}
		return in.resolved
	}
	return in.candidate
}

// New creates an inspector; options the Go backend lacks are rejected with NotPorted, a hint outside
// the ported families too (Python rejects unknown hints at construction).
func New(cfg contracts.Config, hint string) (*Inspector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Heuristics {
		return nil, &parsing.NotPorted{What: "option heuristics"}
	}
	if cfg.RetainContexts {
		return nil, &parsing.NotPorted{What: "option retain_contexts (signatures)"}
	}
	if hint != "" && !Ported[hint] {
		return nil, &parsing.NotPorted{What: "hint " + hint}
	}
	return &Inspector{cfg: cfg, hint: hint, hintSource: "caller", source: "wire", Observation: contracts.Initial("tcp"), shiftSource: "wire"}, nil
}

func (in *Inspector) Terminal() bool { return in.terminal }

func (in *Inspector) publish(obs contracts.Observation, kind contracts.Kind) []contracts.Event {
	if reflect.DeepEqual(obs, in.Observation) {
		return nil
	}
	in.Observation = obs
	in.revision++
	in.Metrics.EventsEmitted++
	return []contracts.Event{{Kind: kind, Revision: in.revision, Observation: obs}}
}

func (in *Inspector) finish(obs contracts.Observation, kind contracts.Kind) []contracts.Event {
	in.terminal = true
	in.continuing = false
	if fr, ok := in.parser.(familyResolver); ok && in.parser != nil {
		in.resolved = fr.ResolvedFamily()
	}
	in.parser = nil
	in.prefix = in.prefix[:0]
	return in.publish(obs, kind)
}

func (in *Inspector) observation(status contracts.Status, reason string) contracts.Observation {
	o := contracts.Initial("tcp")
	o.Status, o.Reason = status, reason
	return o
}

func str(s string) *string { return &s }

func (in *Inspector) identified() contracts.Observation {
	r := in.parser.Result()
	in.ldapID, in.hasLDAPID = r.LDAPMessageID, r.HasLDAPMessageID
	var encryption, protocol *string
	if in.candidate == "tls" {
		encryption = str("tls")
	} else {
		protocol = str(r.ProtocolName)
	}
	if (in.candidate == "text" || in.candidate == "git_text" || in.candidate == "tpkt") && r.Family != "" {
		in.candidate = r.Family
	}
	var hostname *string
	if r.HasHost {
		hostname = str(r.Host)
	}
	alpn := []string{}
	if encryption != nil && r.ALPN != nil {
		alpn = r.ALPN
	}
	var evidence []contracts.Evidence
	if encryption != nil {
		evidence = append(evidence, contracts.Evidence{Field: "encryption", Value: "tls", Source: in.source, Strength: "structural"})
	} else {
		evidence = append(evidence, contracts.Evidence{Field: "application_protocol", Value: r.ProtocolName, Source: in.source, Strength: "structural"})
	}
	if in.hint != "" {
		evidence = append(evidence, contracts.Evidence{Field: "candidate_hint", Value: in.hint, Source: in.hintSource, Strength: "context"})
	}
	hostSource := r.HostSource
	if hostSource == "" {
		if encryption != nil {
			hostSource = "tls_sni"
		} else {
			hostSource = "http_host"
		}
	}
	if hostname != nil && *hostname != "" {
		evidence = append(evidence, contracts.Evidence{Field: "hostname", Value: *hostname, Source: in.source + ":" + hostSource, Strength: "asserted"})
	}
	for _, offered := range alpn {
		evidence = append(evidence, contracts.Evidence{Field: "offered_alpn", Value: offered, Source: in.source + ":client_hello", Strength: "offered"})
	}
	for _, row := range r.Extra {
		evidence = append(evidence, contracts.Evidence{Field: row.Field, Value: row.Value, Source: in.source + ":" + row.Provenance, Strength: row.Strength})
	}
	if evidence == nil {
		evidence = []contracts.Evidence{}
	}
	scope := r.Scope
	if scope == "" {
		scope = "initial_message"
	}
	return contracts.Observation{Status: contracts.Identified, Transport: "tcp", Encryption: encryption, ApplicationProtocol: protocol,
		Hostname: hostname, OfferedALPN: alpn, Evidence: evidence, Reason: r.Reason, Scope: scope}
}

func (in *Inspector) failed(err error) ([]contracts.Event, bool) {
	switch e := err.(type) {
	case *parsing.NotPorted:
		in.NotPorted = e
		in.terminal = true
		return nil, true
	case *parsing.Error:
		switch e.Kind {
		case "budget":
			return in.finish(in.observation(contracts.BudgetExhausted, e.Message), contracts.Updated), true
		case "ambiguous":
			o := in.observation(contracts.Unknown, e.Message)
			o.Evidence = []contracts.Evidence{{Field: "ambiguous_candidates", Value: joinComma(e.Candidates), Source: in.source, Strength: "context"}}
			return in.finish(o, contracts.Updated), true
		case "unsupported":
			return in.finish(in.observation(contracts.Unknown, e.Message), contracts.Updated), true
		default:
			return in.finish(in.observation(contracts.Malformed, e.Message), contracts.Updated), true
		}
	}
	return nil, false
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// Feed ports Inspector.feed without the signature/heuristic unknown buffer and the continuation paths.
func (in *Inspector) Feed(data []byte) []contracts.Event {
	in.Metrics.BytesReceived += len(data)
	if in.terminal || len(data) == 0 {
		return nil
	}
	if in.Metrics.Updates >= in.cfg.MaxUpdates {
		return in.finish(in.observation(contracts.BudgetExhausted, "Update budget exhausted"), contracts.Updated)
	}
	in.Metrics.Updates++
	allowance := in.cfg.MaxBytes - in.Metrics.BytesInspected
	chunk := data
	if allowance < len(chunk) {
		chunk = data[:allowance]
	}
	if in.next != nil {
		return in.forward(chunk)
	}
	previous := 0
	if in.candidate == "" {
		previous = len(in.prefix)
		var probe []byte
		if previous > 0 {
			probe = append(append([]byte{}, in.prefix...), chunk[:minInt(len(chunk), Lookahead-previous)]...)
		} else {
			probe = chunk[:minInt(len(chunk), Lookahead)]
		}
		candidate := in.hint
		if candidate == "" {
			candidate = Select(probe)
		}
		if candidate == Unknown {
			in.Metrics.BytesInspected += len(probe) - previous
			return in.finish(in.observation(contracts.Unknown, "Prefix outside supported protocol families"), contracts.Updated)
		}
		if candidate == Wait {
			in.prefix = append(in.prefix, chunk...)
			in.Metrics.BytesInspected += len(chunk)
			return nil
		}
		in.candidate = candidate
		in.Metrics.CandidatesSelected++
		parser, err := factory(candidate, in.cfg)
		if err != nil {
			events, _ := in.failed(err)
			return events
		}
		in.parser = parser
		if previous > 0 {
			chunk = append(append([]byte{}, in.prefix...), chunk...)
			in.prefix = in.prefix[:0]
		}
	}
	in.Metrics.ParserCalls++
	if in.continuing {
		return in.continueFeed(chunk)
	}
	newBytes := len(chunk) - previous
	in.Metrics.BytesInspected += newBytes
	consumed, err := in.parser.Feed(chunk)
	if err != nil {
		events, _ := in.failed(err)
		return events
	}
	in.Metrics.BytesInspected -= newBytes - maxInt(0, consumed-previous)
	if in.parser.Done() {
		r := in.parser.Result()
		if r.Continues {
			in.continuing = true
			events := in.publish(in.identified(), contracts.Updated)
			if rest := chunk[consumed:]; len(rest) > 0 {
				events = append(events, in.continueFeed(rest)...)
			}
			return events
		}
		if r.Shift != nil {
			return in.beginShift(r.Shift, chunk[consumed:])
		}
		in.Boundary, in.hasBoundary = in.Metrics.BytesReceived-len(data)-previous+consumed, true
		return in.finish(in.identified(), contracts.Updated)
	}
	if in.Metrics.BytesInspected >= in.cfg.MaxBytes {
		return in.finish(in.observation(contracts.BudgetExhausted, "Byte budget exhausted"), contracts.Updated)
	}
	return nil
}

func (in *Inspector) beginShift(shift *parsing.Shift, rest []byte) []contracts.Event {
	events := in.publish(in.identified(), contracts.Updated)
	in.parser = nil
	in.continuing = false
	in.prefix = in.prefix[:0]
	carrier := in.Observation
	in.carrier, in.shift = &carrier, shift.Boundary
	announced := carrier
	in.Announcement = &announced
	remaining := in.cfg.MaxBytes - in.Metrics.BytesInspected
	if remaining < 64 {
		in.next = nil
		return append(events, in.finish(in.shiftResult(in.observation(contracts.BudgetExhausted, "Byte budget exhausted at the shift boundary")), contracts.Shifted)...)
	}
	cfg := in.cfg
	cfg.MaxBytes = remaining
	next, err := New(cfg, shift.Expected)
	if err != nil {
		if np, ok := err.(*parsing.NotPorted); ok {
			in.NotPorted, in.terminal = np, true
			return events
		}
		in.NotPorted, in.terminal = &parsing.NotPorted{What: "shift to " + shift.Expected}, true
		return events
	}
	next.hintSource = "shift:" + shift.Boundary
	in.next = next
	if len(rest) > 0 {
		events = append(events, in.forward(rest)...)
	}
	return events
}

func (in *Inspector) forward(data []byte) []contracts.Event {
	inner := in.next
	bytesBefore, callsBefore := inner.Metrics.BytesInspected, inner.Metrics.ParserCalls
	events := inner.Feed(data)
	in.Metrics.BytesInspected += inner.Metrics.BytesInspected - bytesBefore
	in.Metrics.ParserCalls += inner.Metrics.ParserCalls - callsBefore
	if inner.NotPorted != nil {
		in.NotPorted, in.terminal = inner.NotPorted, true
		return nil
	}
	if len(events) > 0 || inner.terminal {
		return in.mergeShift()
	}
	return nil
}

func (in *Inspector) shiftResult(inner contracts.Observation) contracts.Observation {
	carrier, boundary := *in.carrier, in.shift
	marker := contracts.Evidence{Field: "shift", Value: boundary, Source: in.shiftSource, Strength: "structural"}
	if inner.Status == contracts.Identified {
		var kept []contracts.Evidence
		for _, e := range carrier.Evidence {
			if (e.Field == "hostname" && inner.Hostname == nil) || (e.Field == "application" && inner.Application == nil && inner.Hostname == nil) {
				kept = append(kept, e)
			}
		}
		from := "unknown"
		if carrier.ApplicationProtocol != nil {
			from = *carrier.ApplicationProtocol
		} else if carrier.Encryption != nil {
			from = *carrier.Encryption
		}
		evidence := append(append(append([]contracts.Evidence{}, inner.Evidence...), kept...), marker,
			contracts.Evidence{Field: "shift_from", Value: from, Source: in.source, Strength: "structural"})
		out := inner
		if out.Hostname == nil {
			out.Hostname = carrier.Hostname
		}
		if !(inner.Application != nil || inner.Hostname != nil) {
			out.Application = carrier.Application
		}
		out.Evidence = evidence
		out.Reason = "After " + boundary + " boundary: " + inner.Reason
		return out
	}
	out := carrier
	out.Evidence = append(append([]contracts.Evidence{}, carrier.Evidence...), marker,
		contracts.Evidence{Field: "shifted_payload", Value: string(inner.Status), Source: in.source, Strength: "context"})
	out.Reason = carrier.Reason + "; bytes after the " + boundary + " boundary: " + inner.Reason
	return out
}

func (in *Inspector) mergeShift() []contracts.Event {
	inner := in.next
	if inner.Observation.Status == contracts.Detecting {
		return nil
	}
	merged := in.shiftResult(inner.Observation)
	if inner.terminal {
		in.next, in.carrier, in.terminal = nil, nil, true
	}
	return in.publish(merged, contracts.Shifted)
}

// Invalidate ports Inspector.invalidate: upstream reassembly is no longer trustworthy.
func (in *Inspector) Invalidate(reason string) []contracts.Event {
	in.next, in.carrier, in.parser, in.Announcement = nil, nil, nil, nil
	in.terminal = true
	in.prefix = in.prefix[:0]
	return in.publish(in.observation(contracts.Invalidated, reason), contracts.Retracted)
}

// End ports Inspector.end for the ported paths.
func (in *Inspector) End(reason string) []contracts.Event {
	if in.terminal {
		return nil
	}
	if in.next != nil {
		events := in.next.End(reason)
		if in.next.NotPorted != nil {
			in.NotPorted, in.terminal = in.next.NotPorted, true
			return nil
		}
		if len(events) > 0 || in.next.terminal {
			return in.mergeShift()
		}
		in.next = nil
		return in.finish(in.shiftResult(in.observation(contracts.Incomplete, reason)), contracts.Shifted)
	}
	if in.continuing {
		if r := in.parser.Result(); r.Shift != nil {
			events := in.beginShift(r.Shift, nil)
			return append(events, in.End(reason)...)
		}
		return in.finish(in.refined(), contracts.Refined) // keep the identification; no further evidence
	}
	return in.finish(in.observation(contracts.Incomplete, reason), contracts.Updated)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
