// Package parsertest is shared support for the per-parser unit and fuzz tests (integration work item #18). It
// drives one parsing.Parser the way the engine does and renders what it decided, so a test can require that a
// parser's answer does not depend on how the stream was split.
package parsertest

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
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
	var cuts []int
	for pos := step; pos < len(data); pos += step {
		cuts = append(cuts, pos)
	}
	return DriveCuts(parser, data, cuts)
}

// DriveCuts is Drive with arbitrary chunk boundaries: data is fed in the pieces that cuts delimit (ascending
// offsets strictly inside data; anything else is ignored), so a property test can require that every split of a
// stream, not only an even one, gives the rendering of the whole stream.
func DriveCuts(parser parsing.Parser, data []byte, cuts []int) string {
	consumed, failure, continuation, continuing, stop := 0, "", "", false, false
	for _, piece := range Pieces(data, cuts) {
		if stop {
			break
		}
		for rest := piece; len(rest) > 0 && !stop; {
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

// Pieces splits data at cuts: ascending offsets strictly inside data, each once; an offset that is out of
// range or not above the previous one is skipped. The pieces join back to data, and none is empty.
func Pieces(data []byte, cuts []int) [][]byte {
	out, prev := make([][]byte, 0, len(cuts)+1), 0
	for _, c := range cuts {
		if c <= prev || c >= len(data) {
			continue
		}
		out = append(out, data[prev:c])
		prev = c
	}
	if prev < len(data) {
		out = append(out, data[prev:])
	}
	return out
}

// CasesEnv names the environment variable that, when set, gives the path of the frozen parity cases
// (migration/fixtures/cases.json) in place of a test's relative path. The nightly mutation run
// (migration/mutation/mutation.py) sets it to the absolute path: gremlins tests each mutant in a temporary copy of
// go/ alone, where a relative path up to migration/ does not exist, so every covered mutant failed to load the
// fixtures and counted as killed (PRO-521).
const CasesEnv = "PROTODETECT_CASES"

// Cases returns the path a test reads the frozen parity cases from: the CasesEnv override when set, else rel.
func Cases(rel string) string {
	if p := os.Getenv(CasesEnv); p != "" {
		return p
	}
	return rel
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

// credited is a parser whose retained buffers grow from a Credit and which reports them.
type credited interface {
	parsing.Parser
	parsing.Credited
	parsing.Retainer
}

// CheckCredit drives parser over data in pieces of step bytes, as Drive does, with a Credit of limit bytes
// (integration work item #14). After every call it requires that the parser retains no more than was charged
// to the Credit since the previous call, so a buffer that grew outside the Credit is reported, and that
// neither the retained figure nor the most ever charged exceeds limit. The Credit is settled to the measured
// figure after each call, as the facade does. A growth the Credit refuses must end the run with the error of
// parsing.Denied; what the same call grew before the refusal was charged and is covered by the checks. It returns "" when every check held, else
// what failed, and whether a growth was refused.
func CheckCredit(parser parsing.Parser, data []byte, step, limit int) (failure string, denied bool) {
	p, ok := parser.(credited)
	if !ok {
		return "the parser does not take a Credit or does not report what it retains", false
	}
	credit := parsing.NewCredit(limit)
	p.SetCredit(credit)
	if step <= 0 || step > len(data) {
		step = len(data)
	}
	continuing := false
	for pos := 0; pos < len(data); pos += step {
		end := pos + step
		if end > len(data) {
			end = len(data)
		}
		for rest := data[pos:end]; len(rest) > 0; {
			n, err := p.Feed(rest)
			retained := p.RetainedBytes()
			switch {
			case retained > credit.Used():
				return fmt.Sprintf("retains %d bytes after a call that charged %d", retained, credit.Used()), false
			case retained > limit || credit.Peak() > limit:
				return fmt.Sprintf("retains %d, charged at most %d, against a limit of %d", retained, credit.Peak(), limit), false
			case parsing.IsDenied(err):
				return "", true
			case credit.Denied():
				return fmt.Sprintf("the Credit refused a growth but the parser returned %v", err), true
			case err != nil:
				return "", false // the parser's own verdict; not a memory question
			}
			credit.Settle(retained)
			if n <= 0 || n > len(rest) {
				break
			}
			rest = rest[n:]
			if p.Done() {
				r := p.Result()
				continuing = r != nil && r.Continues && r.Shift == nil
				if !continuing {
					return "", false
				}
			}
		}
	}
	return "", false
}
