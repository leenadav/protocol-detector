// Package parsertest is shared support for the per-parser unit and fuzz tests (integration work item #18). It
// drives one parsing.Parser the way the engine does and renders what it decided, so a test can require that a
// parser's answer does not depend on how the stream was split.
package parsertest

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Drive feeds data to a fresh parser in pieces of step bytes (the whole input when step is 0 or less) and
// returns a rendering of the outcome: the error, whether the parser finished, the bytes it consumed and its
// result. It follows the engine's contract. Before the parser is done, an error ends the run. A done parser
// whose result continues (optional evidence, or a watch for a protocol shift) is fed the rest of the stream,
// and an error there ends the continuation without undoing the identification. A done parser that does not
// continue gets no more bytes. A parser that consumes more than it was given, a negative amount, or that
// stalls without being done is reported in the rendering.
func Drive(parser parsing.Parser, data []byte, step int) string {
	if step <= 0 || step > len(data) {
		step = len(data)
	}
	consumed, failure, continuation, continuing, stop := 0, "", "", false, false
	for pos := 0; pos < len(data) && !stop; pos += step {
		end := pos + step
		if end > len(data) {
			end = len(data)
		}
		for rest := data[pos:end]; len(rest) > 0 && !stop; {
			n, err := parser.Feed(rest)
			if n < 0 || n > len(rest) {
				return fmt.Sprintf("BROKEN: consumed %d of %d", n, len(rest))
			}
			consumed += n
			rest = rest[n:]
			switch {
			case err != nil && continuing:
				continuation, stop = err.Error(), true
			case err != nil:
				failure, stop = err.Error(), true
			case !parser.Done():
				if len(rest) > 0 {
					return fmt.Sprintf("BROKEN: stalled with %d bytes left and not done", len(rest))
				}
			default:
				r := parser.Result()
				continuing = r != nil && r.Continues && r.Shift == nil
				stop = !continuing || n == 0
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "error=%q done=%v consumed=%d", failure, parser.Done(), consumed)
	if continuation != "" {
		fmt.Fprintf(&b, " continuation-error=%q", continuation)
	}
	if r := parser.Result(); r != nil && failure == "" {
		fmt.Fprintf(&b, " family=%q protocol=%q host=%q/%v/%q alpn=%q extra=%q reason=%q scope=%q continues=%v",
			r.Family, r.ProtocolName, r.Host, r.HasHost, r.HostSource, r.ALPN, r.Extra, r.Reason, r.Scope, r.Continues)
		if r.Shift != nil {
			fmt.Fprintf(&b, " shift=%q/%q", r.Shift.Boundary, r.Shift.Expected)
		}
	}
	return b.String()
}

// Streams returns the whole byte stream of every unhinted stream case of the shared fixtures whose label is in
// labels (every stream case when labels is empty), in fixture order and without duplicates.
func Streams(path string, labels ...string) ([][]byte, error) {
	doc, err := parity.Load(context.Background(), path)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}
	seen, out := map[string]bool{}, [][]byte{}
	for i := range doc.Cases {
		c := &doc.Cases[i]
		if c.Kind != "stream" || c.Hint != nil || (len(want) > 0 && !want[c.Label]) {
			continue
		}
		joined := strings.Join(c.Chunks, "")
		if seen[joined] {
			continue
		}
		seen[joined] = true
		data, err := hex.DecodeString(joined)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		out = append(out, data)
	}
	return out, nil
}
