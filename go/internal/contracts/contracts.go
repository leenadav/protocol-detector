// Package contracts holds the typed observations, events, metrics and configuration shared by every
// Go component, serialized in exactly the shape the Python reference emits so that the differential
// harness (migration/parity) compares the two implementations field by field.
//
// Vocabularies are closed (migration/CONTRACTS.md). Decoding an unknown status, kind or scope fails
// rather than passing a foreign value through, and a Config decodes from the Python option names on
// top of the documented defaults.
package contracts

import (
	"encoding/json"
	"fmt"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// Status is the observation status vocabulary.
type Status string

const (
	Detecting       Status = "detecting"
	Identified      Status = "identified"
	Unknown         Status = "unknown"
	Malformed       Status = "malformed"
	Incomplete      Status = "incomplete"
	BudgetExhausted Status = "budget_exhausted"
	Invalidated     Status = "invalidated"
)

var statuses = map[Status]bool{Detecting: true, Identified: true, Unknown: true, Malformed: true, Incomplete: true, BudgetExhausted: true, Invalidated: true}

// Kind is the event kind vocabulary.
type Kind string

const (
	Updated     Kind = "updated"
	Refined     Kind = "refined"
	Shifted     Kind = "shifted"
	Retracted   Kind = "invalidated"
	DatagramObs Kind = "datagram"
)

var kinds = map[Kind]bool{Updated: true, Refined: true, Shifted: true, Retracted: true, DatagramObs: true}

// Strength grades evidence; the values are the Python strings.
const (
	StrengthStructural = "structural"
	StrengthOffered    = "offered"
	StrengthHint       = "hint"
)

// Evidence is one (field, value, source, strength) tuple; serialized as a 4-element JSON array.
type Evidence struct {
	Field, Value, Source, Strength string
}

func (e Evidence) MarshalJSON() ([]byte, error) {
	return json.Marshal([4]string{e.Field, e.Value, e.Source, e.Strength})
}

func (e *Evidence) UnmarshalJSON(b []byte) error {
	var parts []string
	if err := json.Unmarshal(b, &parts); err != nil {
		return errs.New(errs.Invalid, "", "evidence is not a string array")
	}
	if len(parts) != 4 {
		return errs.New(errs.Invalid, "", "evidence needs field, value, source and strength")
	}
	*e = Evidence{parts[0], parts[1], parts[2], parts[3]}
	return nil
}

// Observation is the engine's view of one direction. Pointer strings are nullable (Python None).
type Observation struct {
	Status              Status     `json:"status"`
	Transport           string     `json:"transport"`
	Encryption          *string    `json:"encryption"`
	ApplicationProtocol *string    `json:"application_protocol"`
	Application         *string    `json:"application"`
	Hostname            *string    `json:"hostname"`
	OfferedALPN         []string   `json:"offered_alpn"`
	Evidence            []Evidence `json:"evidence"`
	Reason              string     `json:"reason"`
	Scope               string     `json:"scope"`
}

// Initial is the observation a stream direction starts from (Python Observation defaults).
func Initial(transport string) Observation {
	return Observation{Status: Detecting, Transport: transport, OfferedALPN: []string{}, Evidence: []Evidence{},
		Reason: "Waiting for stream prefix", Scope: "initial_message"}
}

// Validate rejects values outside the closed vocabularies.
func (o Observation) Validate() error {
	if !statuses[o.Status] {
		return errs.New(errs.Invalid, "", fmt.Sprintf("unknown status %q", o.Status))
	}
	if o.Transport != "tcp" && o.Transport != "udp" {
		return errs.New(errs.Invalid, "", fmt.Sprintf("unknown transport %q", o.Transport))
	}
	if o.OfferedALPN == nil || o.Evidence == nil {
		return errs.New(errs.Invalid, "", "offered_alpn and evidence are lists, never null")
	}
	return nil
}

type observationJSON Observation

func (o *Observation) UnmarshalJSON(b []byte) error {
	var raw observationJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.OfferedALPN == nil {
		raw.OfferedALPN = []string{}
	}
	if raw.Evidence == nil {
		raw.Evidence = []Evidence{}
	}
	*o = Observation(raw)
	return o.Validate()
}

func (o Observation) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(observationJSON(o))
}

// Event is one published revision of a direction's observation.
type Event struct {
	Kind        Kind        `json:"kind"`
	Revision    int         `json:"revision"`
	Observation Observation `json:"observation"`
}

type eventJSON Event

func (e *Event) UnmarshalJSON(b []byte) error {
	var raw eventJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if !kinds[raw.Kind] {
		return errs.New(errs.Invalid, "", fmt.Sprintf("unknown event kind %q", raw.Kind))
	}
	if raw.Revision < 0 {
		return errs.New(errs.Invalid, "", "negative revision")
	}
	*e = Event(raw)
	return nil
}

// Metrics counts the work of one direction; names and meanings follow the Python Metrics.
type Metrics struct {
	BytesReceived       int `json:"bytes_received"`
	BytesInspected      int `json:"bytes_inspected"`
	Updates             int `json:"updates"`
	ParserCalls         int `json:"parser_calls"`
	CandidatesSelected  int `json:"candidates_selected"`
	EventsEmitted       int `json:"events_emitted"`
	SignatureCandidates int `json:"signature_candidates"`
}

// Config carries the per-direction budgets and options. Every limit here is per direction; aggregate
// limits live with the owner of the flow table (buffer.Account).
type Config struct {
	MaxBytes        int  `json:"max_bytes"`
	MaxUpdates      int  `json:"max_updates"`
	MaxLine         int  `json:"max_line"`
	MaxHeaders      int  `json:"max_headers"`
	MaxCRC32CBytes  int  `json:"max_crc32c_bytes"`
	RetainContexts  bool `json:"retain_contexts"`
	SignatureBytes  int  `json:"signature_bytes"`
	Fingerprints    bool `json:"fingerprints"`
	QUICDecrypt     bool `json:"quic_decrypt"`
	Heuristics      bool `json:"heuristics"`
	HeuristicBytes  int  `json:"heuristic_bytes"`
	Certificates    bool `json:"certificates"`
	Continuation    int  `json:"continuation"`
	MaxTransactions int  `json:"max_transactions"`
}

// DefaultConfig mirrors protocol_engine/model.py; the defaults are part of the contract (C8).
func DefaultConfig() Config {
	return Config{MaxBytes: 65536, MaxUpdates: 4096, MaxLine: 8192, MaxHeaders: 128, MaxCRC32CBytes: 4096,
		SignatureBytes: 2000, QUICDecrypt: true, HeuristicBytes: 512, MaxTransactions: 16}
}

type configJSON Config

// UnmarshalJSON applies the given fields over the defaults and rejects unknown names and bad values.
func (c *Config) UnmarshalJSON(b []byte) error {
	raw := configJSON(DefaultConfig())
	var names map[string]json.RawMessage
	if err := json.Unmarshal(b, &names); err != nil {
		return err
	}
	for name := range names {
		if !configNames[name] {
			return errs.New(errs.Invalid, "", fmt.Sprintf("unknown configuration field %q", name))
		}
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*c = Config(raw)
	return c.Validate()
}

var configNames = map[string]bool{"max_bytes": true, "max_updates": true, "max_line": true, "max_headers": true, "max_crc32c_bytes": true,
	"retain_contexts": true, "signature_bytes": true, "fingerprints": true, "quic_decrypt": true, "heuristics": true,
	"heuristic_bytes": true, "certificates": true, "continuation": true, "max_transactions": true}

// configRange is one integer option's inclusive range; the table is protocol_engine/model.Config.__post_init__.
type configRange struct {
	Name      string
	Low, High int
}

// ConfigRanges lists every integer option with its inclusive range, in the order of the Python table (review R4,
// 2026-11-14: Go rejected the valid max_crc32c_bytes=0, which disables checksum work, and had no upper bounds, so
// max_bytes=1<<40 was accepted where Python caps it at 1 MiB).
var ConfigRanges = []configRange{
	{"max_bytes", 64, 1048576}, {"max_updates", 1, 1000000}, {"max_line", 16, 65536}, {"max_headers", 1, 4096},
	{"max_crc32c_bytes", 0, 1048576}, {"signature_bytes", 16, 65536}, {"heuristic_bytes", 16, 65536},
	{"continuation", 0, 1048576}, {"max_transactions", 1, 4096},
}

func (c Config) integer(name string) int {
	switch name {
	case "max_bytes":
		return c.MaxBytes
	case "max_updates":
		return c.MaxUpdates
	case "max_line":
		return c.MaxLine
	case "max_headers":
		return c.MaxHeaders
	case "max_crc32c_bytes":
		return c.MaxCRC32CBytes
	case "signature_bytes":
		return c.SignatureBytes
	case "heuristic_bytes":
		return c.HeuristicBytes
	case "continuation":
		return c.Continuation
	case "max_transactions":
		return c.MaxTransactions
	}
	panic("contracts: no integer option " + name)
}

// Validate applies the Python resource limits: every integer option inside its inclusive range. A shifted phase
// keeps the same table (the engine opens one only with at least 64 bytes of budget left, as Python does).
func (c Config) Validate() error {
	for _, r := range ConfigRanges {
		if value := c.integer(r.Name); value < r.Low || value > r.High {
			return errs.New(errs.Invalid, errs.ScopeDirection, fmt.Sprintf("Invalid inspection resource limits: %s must be %d..%d", r.Name, r.Low, r.High))
		}
	}
	return nil
}
