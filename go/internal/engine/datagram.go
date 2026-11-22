package engine

import (
	"bytes"
	"encoding/binary"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/dnsx"
	"github.com/leenadav/protocol-detector/go/internal/protocols/framed"
	"github.com/leenadav/protocol-detector/go/internal/protocols/heuristics"
	"github.com/leenadav/protocol-detector/go/internal/protocols/quicx"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
)

// Datagram ports DatagramInspector for the DNS-layout validators; any other candidate the Python
// preselection would run makes the outcome NotPorted (the Go backend cannot tell whether that
// validator would have matched).
type Datagram struct {
	cfg     contracts.Config
	Metrics contracts.Metrics
	sigs    *signatures.Set
	// Assembler is the optional bounded cross-datagram QUIC CRYPTO store owned by the host (nil: none).
	Assembler *quicx.Assembler
}

// NewDatagram validates the options like New.
func NewDatagram(cfg contracts.Config) (*Datagram, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Datagram{cfg: cfg}, nil
}

// SetSignatures attaches a signature set (Python's constructor argument); a non-empty set requires retain_contexts.
func (d *Datagram) SetSignatures(set *signatures.Set) error {
	if set.Len() > 0 && !d.cfg.RetainContexts {
		return errs.New(errs.Invalid, errs.ScopeProcess, "Signatures require Config(retain_contexts=True)")
	}
	d.sigs = set
	return nil
}

// match ports SignatureSet.match: the first matching signature, without counting candidates (as in Python).
func (d *Datagram) match(family string, contexts parsing.Contexts) *signatures.Signature {
	if d.sigs == nil || contexts == nil {
		return nil
	}
	found, _ := d.sigs.MatchCounted(family, contexts)
	return found
}

// unknown ports DatagramInspector._unknown: custom unknown-udp signatures may still name an application.
func (d *Datagram) unknown(data []byte, base contracts.Observation, reason, hint string) contracts.Observation {
	if d.sigs.Wants("unknown-udp") {
		head := data
		if len(head) > d.cfg.SignatureBytes {
			head = head[:d.cfg.SignatureBytes]
		}
		if found := d.match("unknown-udp", parsing.Contexts{"unknown-req-udp-payload": append([]byte{}, head...),
			"unknown-req-udp-payload-length": int64(len(data))}); found != nil {
			o := contracts.Initial("udp")
			o.Status, o.Application, o.Scope = contracts.Identified, str(found.Name), "signature_match"
			o.Reason = "Custom signature matched an unknown datagram; no protocol profile validated"
			o.Evidence = []contracts.Evidence{{Field: "application", Value: found.Name, Source: "signature:unknown-udp", Strength: "configured_signature"}}
			if hint != "" {
				o.Evidence = append(o.Evidence, contracts.Evidence{Field: "candidate_hint", Value: hint, Source: "caller", Strength: "context"})
			}
			return o
		}
	}
	base.Status, base.Reason, base.Evidence = contracts.Unknown, reason, d.unknownEvidence(data)
	return base
}

// DNS-layout validators handled by dnsx; as in Python VALIDATORS, the mdns and netbios-ns hints run the dns validator.
var datagramValidators = map[string]bool{"dns": true, "llmnr": true, "mdns": true, "netbios-ns": true}

// DatagramHints is the Python VALIDATORS table (protocol_engine/datagram.py): exactly the hints a caller may give.
// A hint outside it is a caller error in both runtimes; a hint inside it whose validator the Go backend lacks is
// reported NotPorted as a datagram candidate. test_migration_parity compares this list with VALIDATORS. Until
// 2026-11-15 this was a hand-kept subset that refused 15 valid hints (bacnet, ikev2, kerberos, openvpn, ...) even
// where the validator was ported, the datagram counterpart of review finding R5.
var DatagramHints = map[string]bool{"bacnet": true, "coap": true, "dhcp": true, "dns": true, "dtls": true, "ethernet-ip": true,
	"ikev2": true, "kerberos": true, "l2tp": true, "lifx-lan": true, "llmnr": true, "mdns": true, "netbios-ns": true, "netflow": true,
	"ntp": true, "onc-rpc": true, "openvpn": true, "quic": true, "radius": true, "rip": true, "rtcp": true, "rtp": true, "sflow": true,
	"sip": true, "snmp": true, "ssdp": true, "stun": true, "syslog": true, "tftp": true, "tplink-smarthome": true, "tuya-lan": true,
	"wireguard": true}

func sipProbe(data []byte, limit int) bool {
	if len(data) == 0 || data[0] < 65 || data[0] > 90 {
		return false
	}
	window := data
	if len(window) > limit {
		window = window[:limit]
	}
	end := bytes.Index(window, []byte("\r\n"))
	if end < 0 {
		return false
	}
	start := end - 8
	if start < 0 {
		start = 0
	}
	return bytes.HasPrefix(data, []byte("SIP/2.0 ")) || bytes.Equal(data[start:end], []byte(" SIP/2.0"))
}

func quicProbe(data []byte) bool {
	if len(data) < 7 || data[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		return true
	}
	switch version {
	case 0x00000001:
		return (data[0]>>4)&3 == 0 && data[0]&0x40 != 0
	case 0x6b3343cf:
		return (data[0]>>4)&3 == 1 && data[0]&0x40 != 0
	}
	return false
}

func wireguardProbe(data []byte) bool {
	sizes := map[byte]int{1: 148, 2: 92, 3: 64}
	return len(data) >= 4 && data[1] == 0 && data[2] == 0 && data[3] == 0 && sizes[data[0]] == len(data)
}

func ssdpProbe(data []byte) bool {
	return bytes.HasPrefix(data, []byte("M-SEARCH ")) || bytes.HasPrefix(data, []byte("NOTIFY ")) || bytes.HasPrefix(data, []byte("HTTP/1.1 200 OK"))
}

func berLengthOK(data []byte, pos int) (int, int, bool) {
	if pos >= len(data) {
		return 0, 0, false
	}
	first := int(data[pos])
	pos++
	if first < 128 {
		return first, pos, true
	}
	width := first & 127
	if width < 1 || width > 4 || pos+width > len(data) {
		return 0, 0, false
	}
	n := 0
	for _, b := range data[pos : pos+width] {
		n = n<<8 | int(b)
	}
	return n, pos + width, true
}

func kerberosProbe(data []byte) bool {
	if len(data) < 40 {
		return false
	}
	switch data[0] {
	case 0x6a, 0x6b, 0x6c, 0x6d, 0x7e:
	default:
		return false
	}
	size, start, ok := berLengthOK(data, 1)
	return ok && start+size == len(data)
}

func ikeHeaderAt(data []byte, start int) bool {
	if !(len(data) >= start+28 && data[start+17] == 32 && data[start+18] == 34 && bytes.Equal(data[start+20:start+24], make([]byte, 4))) {
		return false
	}
	switch data[start+16] {
	case 33, 34, 40, 41, 43:
	default:
		return false
	}
	spi := data[start+8 : start+16]
	if data[start+19] == 8 {
		return bytes.Equal(spi, make([]byte, 8))
	}
	return data[start+19] == 0x20 && !bytes.Equal(spi, make([]byte, 8))
}

func ikeProbe(data []byte) bool {
	return len(data) >= 352 && (ikeHeaderAt(data, 0) || (bytes.Equal(data[:4], make([]byte, 4)) && ikeHeaderAt(data, 4)))
}

// candidates ports the preselection chain of DatagramInspector.inspect.
func (d *Datagram) candidates(data []byte, hint string) []string {
	if hint != "" {
		return []string{hint}
	}
	var out []string
	switch {
	case quicProbe(data):
		out = []string{"quic"}
	case wireguardProbe(data):
		out = []string{"wireguard"}
	case ssdpProbe(data):
		out = []string{"ssdp"}
	case len(data) >= 3 && data[0] == 0x16 && data[1] == 0xfe && (data[2] == 0xff || data[2] == 0xfd):
		out = []string{"dtls"}
	case len(data) >= 8 && bytes.Equal(data[4:8], []byte{0x21, 0x12, 0xa4, 0x42}):
		out = []string{"stun"}
	case len(data) >= 240 && bytes.Equal(data[236:240], []byte{0x63, 0x82, 0x53, 0x63}):
		out = []string{"dhcp"}
	case bytes.HasPrefix(data, []byte("<")):
		out = []string{"syslog"}
	case sipProbe(data, d.cfg.MaxLine):
		out = []string{"sip"}
	default:
		if bytes.HasPrefix(data, []byte{0x30}) {
			out = append(out, "snmp")
		} else if len(data) >= 2 && data[0] == 0 && (data[1] == 1 || data[1] == 2 || data[1] == 6) {
			out = append(out, "tftp")
		}
		if dnsx.Probe(data) {
			out = append(out, "dns")
		}
		if len(data) >= 4 && len(data) > 4+int(data[0]&15) && data[0]>>6 == 1 && data[0]&15 <= 8 {
			out = append(out, "coap")
		}
		if len(data) >= 16 && data[0] == 0 && (data[1] == 5 || data[1] == 9 || data[1] == 10) {
			out = append(out, "netflow")
		}
		if len(data) >= 28 && bytes.Equal(data[:4], []byte{0, 0, 0, 5}) {
			out = append(out, "sflow")
		}
		if len(data) >= 4 && data[0] == 0x81 && data[1] <= 0x0c && int(binary.BigEndian.Uint16(data[2:4])) == len(data) {
			out = append(out, "bacnet")
		}
		if kerberosProbe(data) {
			out = append(out, "kerberos")
		}
		if len(data) >= 14 && (data[0] == 0x38 || data[0] == 0x40 || data[0] == 0x50) {
			out = append(out, "openvpn")
		}
		if len(data) >= 20 && data[0]&0xcb == 0xc8 {
			out = append(out, "l2tp")
		}
		if enipProbe(data) && len(data) >= 24 {
			out = append(out, "ethernet-ip")
		}
		if len(data) >= 20 && (bytes.Equal(data[4:12], []byte{0, 0, 0, 0, 0, 0, 0, 2}) || (bytes.Equal(data[4:8], []byte{0, 0, 0, 1}) && (bytes.Equal(data[8:12], []byte{0, 0, 0, 0}) || bytes.Equal(data[8:12], []byte{0, 0, 0, 1})))) {
			out = append(out, "onc-rpc")
		}
		if len(data) >= 24 && (data[0] == 1 || data[0] == 2) && (data[1] == 1 || data[1] == 2) && data[2] == 0 && data[3] == 0 && (len(data)-4)%20 == 0 {
			out = append(out, "rip")
		}
		if len(data) >= 36 && int(binary.LittleEndian.Uint16(data[:2])) == len(data) && binary.LittleEndian.Uint16(data[2:4])&0xdfff == 0x1000|1024 {
			out = append(out, "lifx-lan")
		}
		if len(data) >= 24 && bytes.Equal(data[:4], []byte{0, 0, 0x55, 0xaa}) && bytes.Equal(data[len(data)-4:], []byte{0, 0, 0xaa, 0x55}) {
			out = append(out, "tuya-lan")
		}
		if len(data) >= 8 && data[0] == 0xd0 && data[1] == 0xf2 {
			out = append(out, "tplink-smarthome")
		}
	}
	if ikeProbe(data) {
		out = append(out, "ikev2")
	}
	return out
}

// Inspect classifies one complete datagram without flow scope or time. A NotPorted error means the Go backend
// cannot give the Python outcome for this payload (a validator it lacks was selected).
func (d *Datagram) Inspect(data []byte, hint string) (contracts.Observation, error) {
	return d.InspectFlow(data, hint, "", nil)
}

// InspectFlow ports DatagramInspector.inspect with scope and now: scope names the datagram's flow for the QUIC
// CRYPTO store (the host passes its flow identity, hence direction); now drives the store's idle expiry.
func (d *Datagram) InspectFlow(data []byte, hint, scope string, now *float64) (contracts.Observation, error) {
	base := contracts.Initial("udp")
	base.Scope = "datagram"
	if hint != "" && !DatagramHints[hint] {
		return base, &parsing.NotPorted{What: "unknown UDP hint " + hint}
	}
	d.Metrics.BytesReceived += len(data)
	d.Metrics.Updates++
	if len(data) > d.cfg.MaxBytes {
		base.Status, base.Reason = contracts.BudgetExhausted, "Datagram exceeds byte budget"
		return base, nil
	}
	candidates := d.candidates(data, hint)
	if len(candidates) == 0 {
		return d.unknown(data, base, "No supported datagram structure selected", hint), nil
	}
	for _, c := range candidates {
		if _, ported := framed.DatagramValidators[c]; !datagramValidators[c] && !ported && c != "quic" && c != "dtls" {
			return base, &parsing.NotPorted{What: "datagram candidate " + c}
		}
	}
	d.Metrics.BytesInspected += len(data)
	type match struct {
		protocol, encryption, reason string
		evidence                     []contracts.Evidence
		hostname                     *string
		alpn                         []string
		retracts                     bool
		contexts                     parsing.Contexts
		family                       string // signature family reading contexts
	}
	var matches []match
	type failure struct{ status, reason string }
	var errors []failure
	for _, c := range candidates {
		d.Metrics.CandidatesSelected++
		d.Metrics.ParserCalls++
		var found match
		var err error
		if c == "quic" {
			var m *quicx.Match
			opts := quicx.Options{MaxHeaders: d.cfg.MaxHeaders, MaxBytes: d.cfg.MaxBytes, Decrypt: d.cfg.QUICDecrypt, Fingerprints: d.cfg.Fingerprints, RetainContexts: d.cfg.RetainContexts}
			if m, err = quicx.Validate(data, opts, d.Assembler, scope, now); err == nil {
				found = match{encryption: "quic", reason: m.Reason, alpn: m.ALPN, retracts: m.Retracts, contexts: m.Contexts, family: "tls"}
				if m.HasHost {
					found.hostname = str(m.Hostname)
				}
				for _, r := range m.Evidence {
					found.evidence = append(found.evidence, contracts.Evidence{Field: r.Field, Value: r.Value, Source: r.Source, Strength: r.Strength})
				}
			} else if np, ok := err.(*parsing.NotPorted); ok {
				return base, np
			}
		} else if c == "dtls" {
			var m *tlsx.DTLSMatch
			if m, err = tlsx.DTLS(data, d.cfg.MaxBytes, d.cfg.MaxHeaders, d.cfg.Fingerprints); err == nil {
				found = match{encryption: "dtls", reason: m.Reason, alpn: m.ALPN}
				if m.HasHost {
					found.hostname = str(m.Hostname)
				}
				for _, r := range m.Rows {
					found.evidence = append(found.evidence, contracts.Evidence{Field: r.Field, Value: r.Value, Source: r.Provenance, Strength: r.Strength})
				}
			} else if np, ok := err.(*parsing.NotPorted); ok {
				return base, np
			}
		} else if validator, ok := framed.DatagramValidators[c]; ok {
			var m *framed.Datagram
			if m, err = validator(data, framed.Limits{MaxBytes: d.cfg.MaxBytes, MaxHeaders: d.cfg.MaxHeaders, MaxLine: d.cfg.MaxLine}); err == nil {
				found = match{protocol: m.Protocol, encryption: m.Encryption, reason: m.Reason}
				if m.Simple {
					found.evidence = []contracts.Evidence{{Field: "application_protocol", Value: m.Protocol, Source: "wire", Strength: "structural"}}
				}
				for _, r := range m.Evidence {
					found.evidence = append(found.evidence, contracts.Evidence{Field: r.Field, Value: r.Value, Source: r.Provenance, Strength: r.Strength})
				}
			}
		} else {
			var details *dnsx.Details
			if details, err = dnsx.Validate(data, d.cfg.MaxBytes, c == "llmnr"); err == nil {
				found = match{protocol: details.Protocol, reason: details.Reason,
					evidence: []contracts.Evidence{{Field: "application_protocol", Value: details.Protocol, Source: "wire", Strength: "structural"}}}
				for _, r := range details.Rows {
					found.evidence = append(found.evidence, contracts.Evidence{Field: r.Field, Value: r.Value, Source: r.Provenance, Strength: r.Strength})
				}
				if d.cfg.RetainContexts && c != "llmnr" {
					found.contexts, found.family = parsing.Contexts{"dns-req-query-name": append([]byte{}, details.QName...),
						"dns-req-query-type": int64(details.QType)}, "dns"
				}
				if d.cfg.Heuristics && c != "llmnr" { // datagram.dns_with_contexts: the query-name shape, never the name
					found.evidence = append(found.evidence, heuristics.DNSNameShape(details.QName)...)
				}
			}
		}
		if err != nil {
			e := err.(*parsing.Error)
			switch e.Kind {
			case "budget":
				errors = append(errors, failure{"budget_exhausted", e.Message})
			case "unsupported", "ambiguous":
				errors = append(errors, failure{"unknown", e.Message})
			default:
				errors = append(errors, failure{"malformed", e.Message})
			}
			continue
		}
		matches = append(matches, found)
	}
	if len(matches) > 1 {
		base.Status, base.Reason = contracts.Unknown, "Ambiguous datagram matches multiple supported structures"
		return base, nil
	}
	if len(matches) == 1 {
		for _, f := range errors {
			if f.status == "budget_exhausted" {
				base.Status, base.Reason = contracts.BudgetExhausted, "A competing datagram candidate exhausted its budget"
				return base, nil
			}
		}
		m := matches[0]
		if m.retracts {
			// D02: a contradiction withdraws what this connection asserted; nothing new is derived.
			base.Status, base.Evidence, base.Reason = contracts.Invalidated, m.evidence, m.reason
			base.Encryption = str(m.encryption)
			return base, nil
		}
		evidence := m.evidence
		if m.contexts != nil && m.family != "" {
			if found := d.match(m.family, m.contexts); found != nil {
				base.Application = str(found.Name)
				evidence = append(evidence, contracts.Evidence{Field: "application", Value: found.Name, Source: "signature:" + m.family, Strength: "configured_signature"})
			}
		}
		if hint != "" {
			evidence = append(evidence, contracts.Evidence{Field: "candidate_hint", Value: hint, Source: "caller", Strength: "context"})
		}
		base.Status, base.Evidence, base.Reason = contracts.Identified, evidence, m.reason
		if m.protocol != "" {
			base.ApplicationProtocol = str(m.protocol)
		}
		if m.encryption != "" {
			base.Encryption = str(m.encryption)
		}
		if m.hostname != nil {
			base.Hostname = m.hostname
		}
		if m.alpn != nil {
			base.OfferedALPN = m.alpn
		}
		return base, nil
	}
	chosen := errors[0]
	for _, f := range errors {
		if f.status == "budget_exhausted" {
			chosen = f
			break
		}
	}
	if chosen.status == "unknown" && hint == "" && len(errors) == len(candidates) {
		// A hint restricts validation to its candidate; it never opens unknown-payload signatures.
		return d.unknown(data, base, chosen.reason, hint), nil
	}
	base.Status, base.Reason = contracts.Status(chosen.status), chosen.reason
	return base, nil
}

// unknownEvidence is DatagramInspector._unknown's heuristic evidence (none without the heuristics option).
func (d *Datagram) unknownEvidence(data []byte) []contracts.Evidence {
	if !d.cfg.Heuristics {
		return []contracts.Evidence{}
	}
	rows := heuristics.Evidence(data, "wire", d.cfg.HeuristicBytes)
	if rows == nil {
		return []contracts.Evidence{}
	}
	return rows
}
