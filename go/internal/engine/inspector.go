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

// Ported is the set of dispatch candidates the Go backend has a parser for.
var Ported = map[string]bool{"text": true, "tls": true, "dns": true, "irc": true, "telnet": true,
	"postgresql": true, "rfb": true, "bittorrent": true, "memcached": true, "rsync": true, "fins": true, "afp": true,
	"zmtp": true, "bolt": true, "stomp": true}

// Families the Go backend can identify (for CAPABILITIES statuses and the harness filter).
var Families = []string{"http", "tls", "dns", "mdns", "netbios-ns", "llmnr", "ssh", "smtp", "imap", "pop3", "ftp", "nats", "irc", "sip", "rtsp", "telnet",
	"postgresql", "rfb", "bittorrent", "memcached", "rsync", "fins", "afp", "zmtp", "bolt", "stomp"}

func factory(candidate string, cfg contracts.Config) (parsing.Parser, error) {
	switch candidate {
	case "text":
		return textroute.New(textroute.Options{MaxLine: cfg.MaxLine, MaxHeaders: cfg.MaxHeaders, MaxBytes: cfg.MaxBytes, Continuation: cfg.Continuation})
	case "irc":
		return textroute.NewIRC(cfg.MaxLine), nil
	case "telnet":
		return textroute.NewTelnet(), nil
	case "postgresql":
		return framed.NewPostgreSQL(cfg.MaxBytes), nil
	case "rfb":
		return framed.NewRFB(cfg.MaxBytes), nil
	case "bittorrent":
		return framed.NewBitTorrent(cfg.MaxBytes), nil
	case "memcached":
		return framed.NewMemcached(cfg.MaxBytes), nil
	case "rsync":
		return framed.NewRsync(cfg.MaxLine, cfg.MaxHeaders), nil
	case "fins":
		return framed.NewFINS(cfg.MaxBytes), nil
	case "afp":
		return framed.NewAFP(cfg.MaxBytes), nil
	case "zmtp":
		return framed.NewZMTP(cfg.MaxBytes), nil
	case "bolt":
		return framed.NewBolt(cfg.MaxBytes), nil
	case "stomp":
		return framed.NewSTOMP(cfg.MaxLine, cfg.MaxHeaders), nil
	case "tls":
		return tlsx.New(tlsx.Options{MaxBytes: cfg.MaxBytes, MaxHeaders: cfg.MaxHeaders, Fingerprints: cfg.Fingerprints,
			Certificates: cfg.Certificates, Continuation: cfg.Continuation})
	case "dns":
		return dnsx.NewTCP(cfg.MaxBytes), nil
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
}

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
	in.next, in.carrier, in.parser = nil, nil, nil
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
