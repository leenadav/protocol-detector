package tlsx

import (
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// continuation.go ports protocol_engine/continuation.TlsContinuation (D07): with Config.continuation > 0
// the record layer after a TLS hello is framed within the byte budget. Only record counts per content type
// are reported (and whether protected application data or an alert was seen); nothing is decrypted or read
// inside a record, and the hello identification never changes.

const maxContinuationRecords = 256

var recordTypes = map[byte]string{20: "ccs", 21: "alert", 22: "handshake", 23: "application_data"}

type tlsContinuation struct {
	budget    int
	remaining int // bytes left in the record that carried the hello, then in each later record
	header    []byte
	counts    map[string]int
	records   int
	done      bool
	ended     string
}

func newTLSContinuation(budget, recordRemaining int) *tlsContinuation {
	return &tlsContinuation{budget: budget, remaining: recordRemaining, counts: map[string]int{}}
}

func (c *tlsContinuation) end(why string) { c.done, c.ended = true, why }

// evidence ports TlsContinuation.evidence.
func (c *tlsContinuation) evidence() []parsing.Row {
	var rows []parsing.Row
	if c.records > 0 {
		summary := ""
		for _, name := range []string{"handshake", "ccs", "alert", "application_data"} {
			if n, ok := c.counts[name]; ok {
				if summary != "" {
					summary += ","
				}
				summary += name + "=" + strconv.Itoa(n)
			}
		}
		rows = append(rows, parsing.Row{Field: "tls_records", Value: summary, Provenance: "continuation", Strength: "structural"})
		if _, ok := c.counts["application_data"]; ok {
			rows = append(rows, parsing.Row{Field: "tls_application_data", Value: "observed", Provenance: "continuation", Strength: "structural"})
		}
		if _, ok := c.counts["alert"]; ok {
			rows = append(rows, parsing.Row{Field: "tls_alert", Value: "observed", Provenance: "continuation", Strength: "structural"})
		}
	}
	if c.done {
		rows = append(rows, parsing.Row{Field: "continuation", Value: c.ended, Provenance: "continuation", Strength: "context"})
	}
	return rows
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// feed ports TlsContinuation.feed: record headers are validated, record bodies skipped unread.
func (c *tlsContinuation) feed(data []byte) int {
	pos := 0
	for pos < len(data) && !c.done {
		if c.budget <= 0 {
			c.end("budget")
			break
		}
		if c.remaining > 0 {
			amount := min3(c.remaining, len(data)-pos, c.budget)
			c.remaining -= amount
			pos += amount
			c.budget -= amount
			continue
		}
		amount := min3(5-len(c.header), len(data)-pos, c.budget)
		c.header = append(c.header, data[pos:pos+amount]...)
		pos += amount
		c.budget -= amount
		if len(c.header) < 5 {
			break
		}
		h := c.header
		c.header = nil
		length := int(h[3])<<8 | int(h[4])
		name, known := recordTypes[h[0]]
		if !known || h[1] != 3 || h[2] > 4 || length < 1 || length > 16384+256 {
			c.end("framing")
			break
		}
		c.counts[name]++
		c.records++
		c.remaining = length
		if c.records >= maxContinuationRecords {
			c.end("records")
		}
	}
	return pos
}
