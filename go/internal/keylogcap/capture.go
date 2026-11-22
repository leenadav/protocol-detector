package keylogcap

import (
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// The offline adapter's bounds (capture.py MAX_CAPTURE, MAX_FRAMES, MAX_CONNECTIONS).
const (
	MaxCapture     = 8 * 1024 * 1024
	MaxFrames      = 20000
	MaxConnections = 64
	chunk          = 65536
)

// Refusal is an exception the reference raises: Type is its class (DecryptionError, CaptureError or
// StreamError), Code the reason code of a DecryptionError.
type Refusal struct{ Type, Message, Code string }

func (r *Refusal) Error() string { return r.Message }

func refusal(err error) error {
	switch e := err.(type) {
	case *decrypt.Error:
		return &Refusal{"DecryptionError", e.Message, e.Code}
	case *capture.Error:
		return &Refusal{"CaptureError", e.Message, ""}
	case *StreamError:
		return &Refusal{"StreamError", e.Message, ""}
	}
	return err
}

func rowOrders(r *row) pyjson.Orders {
	base := analyze.Orders(nil)
	return func(path string) []string {
		if path == "session" {
			return r.keys
		}
		return base(path)
	}
}

// Analyze is poc_decryption.capture.analyze_capture: the decryption report of one capture and its key log,
// as the JSON text json.dumps writes for it (without the worker's "synthetic" flag).
func Analyze(data []byte, keylog string, pack *content.Pack) (string, error) {
	if len(data) > MaxCapture {
		return "", &Refusal{"DecryptionError", "Capture exceeds 8 MiB.", decrypt.BudgetExhausted}
	}
	keys := decrypt.NewKeyProvider()
	if _, err := keys.Append(keylog); err != nil {
		return "", refusal(err)
	}
	owner, err := newCoordinator(pack, Budget{PerDirection: decrypt.MaxStream, Aggregate: 4 * 1024 * 1024, Connections: MaxConnections, Pending: 8192},
		MaxConnections)
	if err != nil {
		return "", err
	}
	d := newDecryptor(pack, owner.Tier, keys)
	decoder, frames, skipped := capture.NewDecoder(), 0, 0
	for offset := 0; offset < len(data); offset += chunk {
		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}
		records, err := decoder.Feed(data[offset:end])
		if err != nil {
			return "", refusal(err)
		}
		for _, record := range records {
			frames++
			if frames > MaxFrames || record.Truncated() {
				return "", &Refusal{"DecryptionError", "Capture is truncated or exceeds 20,000 frames.", decrypt.BudgetExhausted}
			}
			packet, derr := transport.Decode(record.Data, record.Linktype, transport.Ignore)
			if derr != nil {
				if _, ok := derr.(*transport.Reject); !ok {
					return "", derr
				}
				skipped++
				continue
			}
			tcp, ok := packet.(*transport.TCP)
			if !ok {
				continue
			}
			if err := owner.accept(tcp, record.Timestamp); err != nil {
				return "", refusal(err)
			}
			if owner.RejectedConnections > 0 {
				return "", &Refusal{"DecryptionError", "Capture exceeds 64 TCP connections.", decrypt.BudgetExhausted}
			}
		}
		if err := d.pump(); err != nil {
			return "", refusal(err)
		}
		if err := d.work(256, 64); err != nil {
			return "", refusal(err)
		}
	}
	if err := decoder.End(); err != nil {
		return "", refusal(err)
	}
	if err := owner.end("Capture input EOF"); err != nil {
		return "", refusal(err)
	}
	if err := d.pump(); err != nil {
		return "", refusal(err)
	}
	if err := d.work(1<<20, 1); err != nil {
		return "", refusal(err)
	}
	return d.report(frames, skipped, ""), nil
}

// report is Decryptor.report: the cached rows and the run's counters as JSON text. It parses nothing and
// authenticates nothing.
func (d *decryptor) report(frames, skipped int, profile string) string {
	owner := d.owner
	if profile == "" {
		profile = Profile
	}
	var done func()
	if owner.Telemetry != nil {
		done = owner.Telemetry.Stage("report")
	}
	d.reportCalls++
	rows := d.rows()
	if done != nil {
		done()
	}
	var b strings.Builder
	b.WriteString(`{"connections": [`)
	decrypted := 0
	for i, r := range rows {
		if r.values["status"] == "decrypted" {
			decrypted++
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pyjson.Dumps(r.values, "session", rowOrders(r)))
	}
	b.WriteString("], ")
	rest := map[string]interface{}{"frames": frames, "skipped": skipped, "decrypted": decrypted, "profile": profile,
		"counts": map[string]interface{}{"opened": d.opened, "closed": d.closedCount, "records_authenticated": d.recordsAuthenticated,
			"plaintext_bytes": d.plaintextBytes, "work_calls": d.workCalls, "report_calls": d.reportCalls, "retracted": d.retracted,
			"awaiting_keys": d.awaitingKeys(), "active": len(d.connections)},
		"budget": map[string]interface{}{"retained_bytes": owner.Allocated(), "retained_limit": owner.Limit(),
			"rejected_connections": owner.RejectedConnections, "rejected_bytes": owner.RejectedBytes}}
	text := pyjson.Dumps(rest, "report", func(path string) []string {
		switch path {
		case "report":
			return []string{"frames", "skipped", "decrypted", "profile", "counts", "budget"}
		case "report.counts":
			return []string{"opened", "closed", "records_authenticated", "plaintext_bytes", "work_calls", "report_calls", "retracted", "awaiting_keys", "active"}
		}
		return []string{"retained_bytes", "retained_limit", "rejected_connections", "rejected_bytes"}
	})
	b.WriteString(text[1:])
	return b.String()
}
