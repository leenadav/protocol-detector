// Package parity reads the language-neutral differential cases (migration/fixtures/cases.json) and
// writes a backend's results in the shape migration/parity/compare.py compares.
//
// Only the inputs and the typed parts of the expectations are decoded here; a Go backend produces
// results, Python compares them. Loading honours context cancellation between cases and bounds the
// file size it will read.
package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// MaxDocumentBytes bounds the fixture file; the committed file is a few megabytes.
const MaxDocumentBytes = 64 << 20

// Document is the cases file.
type Document struct {
	Schema    int             `json:"schema"`
	Reference json.RawMessage `json:"reference"`
	Cases     []Case          `json:"cases"`
}

// Case is one input with its expectation (kept raw except for the typed stream/datagram parts).
type Case struct {
	ID       string           `json:"id"`
	Kind     string           `json:"kind"`
	Label    string           `json:"label"`
	Hint     *string          `json:"hint"`
	Config   contracts.Config `json:"config"`
	Chunks   []string         `json:"chunks"`
	Payload  string           `json:"payload"`
	End      *string          `json:"end"`
	Expected json.RawMessage  `json:"expected"`
}

// StreamExpectation is the typed expectation of a stream case.
type StreamExpectation struct {
	Events  []contracts.Event     `json:"events"`
	Final   contracts.Observation `json:"final"`
	Metrics contracts.Metrics     `json:"metrics"`
}

// DatagramExpectation is the typed expectation of a datagram case.
type DatagramExpectation struct {
	Observation contracts.Observation `json:"observation"`
	Metrics     contracts.Metrics     `json:"metrics"`
}

// Results is what a backend writes for compare.py --results.
type Results struct {
	Backend string                     `json:"backend"`
	Results map[string]json.RawMessage `json:"results"`
}

// Load reads and validates the document; ctx is checked while cases are decoded.
func Load(ctx context.Context, path string) (*Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "cases file cannot be opened")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "cases file cannot be read")
	}
	if len(data) > MaxDocumentBytes {
		return nil, errs.Exceeded(errs.ScopeProcess, MaxDocumentBytes, "cases file size")
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "cases file is not the expected JSON shape: "+err.Error())
	}
	if doc.Schema != 1 {
		return nil, errs.New(errs.Unsupported, errs.ScopeProcess, fmt.Sprintf("cases schema %d", doc.Schema))
	}
	seen := make(map[string]bool, len(doc.Cases))
	for i := range doc.Cases {
		if err := ctx.Err(); err != nil {
			return nil, errs.New(errs.Cancelled, errs.ScopeProcess, "loading cases")
		}
		c := &doc.Cases[i]
		if c.ID == "" || seen[c.ID] {
			return nil, errs.New(errs.Invalid, errs.ScopeProcess, "case ids must be unique and non-empty")
		}
		seen[c.ID] = true
		switch c.Kind {
		case "stream":
			if _, err := c.Stream(); err != nil {
				return nil, errs.New(errs.Invalid, errs.ScopeProcess, "stream expectation of "+c.ID+": "+err.Error())
			}
		case "datagram":
			if _, err := c.Datagram(); err != nil {
				return nil, errs.New(errs.Invalid, errs.ScopeProcess, "datagram expectation of "+c.ID+": "+err.Error())
			}
		case "session":
			// Session expectations are adapter records; typed in M3 when the Go adapter exists.
		default:
			return nil, errs.New(errs.Unsupported, errs.ScopeProcess, "case kind "+c.Kind)
		}
	}
	return &doc, nil
}

// Stream decodes a stream case's expectation.
func (c *Case) Stream() (*StreamExpectation, error) {
	var e StreamExpectation
	if err := json.Unmarshal(c.Expected, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Datagram decodes a datagram case's expectation.
func (c *Case) Datagram() (*DatagramExpectation, error) {
	var e DatagramExpectation
	if err := json.Unmarshal(c.Expected, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
