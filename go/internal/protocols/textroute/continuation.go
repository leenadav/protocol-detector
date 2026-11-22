package textroute

import (
	"bytes"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// continuation.go ports protocol_engine/continuation.HttpContinuation (D07): with Config.continuation > 0
// the parser that identified an HTTP/1 direction keeps framing later messages of that direction within the
// byte budget and the message cap, and adds bounded structural evidence (message count, method labels,
// status classes, a Host differing from the identifying one, why the continuation ended). The published
// identification never changes. Bodies are skipped by their declared framing; a response without declared
// framing is close-delimited and ends the continuation. 1xx, 204 and 304 responses end at the header
// boundary whatever Content-Length or Transfer-Encoding they carry (RFC 9112 section 6.3; Codex finding R3).

const (
	maxContinuationMethods = 8
)

// continuationMethods is continuation._KNOWN_METHODS (narrower than the first-message method labels).
var continuationMethods = set("GET HEAD POST PUT DELETE OPTIONS PATCH TRACE CONNECT PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT RPC_IN_DATA RPC_OUT_DATA RPC_CONNECT")

type chunkState int

const (
	chunkNone chunkState = iota
	chunkSize
	chunkData
	chunkDataCRLF
	chunkTrailers
)

type httpContinuation struct {
	opts          Options
	budget        int
	limit         int
	firstHost     string
	hasFirstHost  bool
	messages      int
	methods       []string
	statusClasses []string
	hostVariation bool
	shift         *parsing.Shift
	scope         string
	done          bool
	ended         string
	parser        *Parser
	skip          uint64 // body bytes still to skip
	chunked       bool
	chunkLine     []byte
	chunkState    chunkState
}

func newHTTPContinuation(opts Options, first *Parser) *httpContinuation {
	c := &httpContinuation{opts: opts, budget: opts.Continuation, limit: opts.MaxTransactions,
		firstHost: first.host, hasFirstHost: first.hasHost, messages: 1}
	c.bodyAfter(first)
	return c
}

// bodyAfter ports HttpContinuation._body_after: the framing of the message that was just completed.
func (c *httpContinuation) bodyAfter(m *Parser) {
	response := !m.isRequest
	if response && ((m.status >= 100 && m.status < 200) || m.status == 204 || m.status == 304) {
		c.skip = 0 // no body, whatever CL/TE declare (on a 304 they can describe a hypothetical representation)
		return
	}
	if m.transferEncoding {
		c.chunked, c.chunkState = true, chunkSize
		return
	}
	if response && !m.hasContentLength {
		c.end("close-delimited")
		return
	}
	c.skip = 0
	if m.hasContentLength {
		c.skip = uint64(m.contentLength)
	}
}

func (c *httpContinuation) end(why string) {
	c.done, c.ended, c.parser = true, why, nil
}

// evidence ports HttpContinuation.evidence (counts and classes only).
func (c *httpContinuation) evidence() []parsing.Row {
	rows := []parsing.Row{{Field: "http_messages", Value: strconv.Itoa(c.messages), Provenance: "continuation", Strength: "structural"}}
	if len(c.methods) > 0 {
		rows = append(rows, parsing.Row{Field: "http_methods", Value: join(c.methods), Provenance: "continuation", Strength: "structural"})
	}
	if len(c.statusClasses) > 0 {
		rows = append(rows, parsing.Row{Field: "http_status_classes", Value: join(c.statusClasses), Provenance: "continuation", Strength: "structural"})
	}
	if c.hostVariation {
		rows = append(rows, parsing.Row{Field: "http_host_variation", Value: "observed", Provenance: "continuation", Strength: "asserted"})
	}
	if c.done {
		rows = append(rows, parsing.Row{Field: "continuation", Value: c.ended, Provenance: "continuation", Strength: "context"})
	}
	return rows
}

func join(values []string) string {
	var b bytes.Buffer
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(v)
	}
	return b.String()
}

func minSkip(skip uint64, a, b int) int {
	n := a
	if b < n {
		n = b
	}
	if skip < uint64(n) {
		return int(skip)
	}
	return n
}

// feed ports HttpContinuation.feed. Framing errors and budget ends never fail the identification.
func (c *httpContinuation) feed(data []byte) int {
	pos := 0
	for pos < len(data) && !c.done {
		if c.budget <= 0 {
			c.end("budget")
			break
		}
		if c.skip > 0 {
			amount := minSkip(c.skip, len(data)-pos, c.budget)
			c.skip -= uint64(amount)
			pos += amount
			c.budget -= amount
			continue
		}
		if c.chunked {
			pos = c.feedChunked(data, pos)
			continue
		}
		if c.parser == nil {
			if c.messages >= c.limit {
				c.end("messages")
				break
			}
			c.parser = &Parser{opts: Options{MaxLine: c.opts.MaxLine, MaxHeaders: c.opts.MaxHeaders, MaxBytes: c.opts.MaxBytes, ForceHTTP: true},
				first: true, reason: "Waiting for complete line", refined: true, maxBytes: c.opts.MaxBytes, subordinate: true}
		}
		end := len(data)
		if pos+c.budget < end {
			end = pos + c.budget
		}
		piece := data[pos:end]
		consumed, err := c.parser.Feed(piece)
		if err != nil { // malformed or budget: the identification stands; framing is lost
			c.budget -= len(piece)
			pos += len(piece)
			c.end("framing")
			break
		}
		pos += consumed
		c.budget -= consumed
		if c.parser.done {
			c.record(c.parser)
			if c.done {
				break
			}
		} else if consumed < len(piece) {
			break
		}
	}
	return pos
}

// record ports HttpContinuation._record for one completed later message.
func (c *httpContinuation) record(m *Parser) {
	c.messages++
	if m.isRequest {
		label := "extension"
		if continuationMethods[m.method] {
			label = m.method
		}
		if !contains(c.methods, label) && len(c.methods) < maxContinuationMethods {
			c.methods = append(c.methods, label)
		}
	} else {
		label := strconv.Itoa(m.status/100) + "xx"
		if !contains(c.statusClasses, label) {
			c.statusClasses = append(c.statusClasses, label)
		}
	}
	if m.hasHost && c.hasFirstHost && m.host != c.firstHost {
		c.hostVariation = true
	}
	if m.shift != nil {
		c.shift, c.scope = m.shift, m.scope
		c.end("shift")
		return
	}
	c.parser = nil
	c.bodyAfter(m)
}

// validChunkSize ports _CHUNK_SIZE: 1..16 hex digits, optionally ";" and printable/space/tab extension bytes.
func validChunkSize(line []byte) (uint64, bool) {
	digits := line
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		digits = line[:i]
		for _, b := range line[i+1:] {
			if !(b >= 0x21 && b <= 0x7e) && b != ' ' && b != '\t' {
				return 0, false
			}
		}
	}
	if len(digits) < 1 || len(digits) > 16 {
		return 0, false
	}
	size, err := strconv.ParseUint(string(digits), 16, 64)
	if err != nil { // includes a sign, which ParseUint rejects
		return 0, false
	}
	return size, true
}

// feedChunked ports HttpContinuation._feed_chunked.
func (c *httpContinuation) feedChunked(data []byte, pos int) int {
	for pos < len(data) && c.budget > 0 {
		if c.chunkState == chunkData {
			amount := minSkip(c.skip, len(data)-pos, c.budget)
			c.skip -= uint64(amount)
			pos += amount
			c.budget -= amount
			if c.skip == 0 {
				c.chunkState = chunkDataCRLF
			}
			continue
		}
		newline := bytes.IndexByte(data[pos:], '\n')
		end := len(data)
		if newline >= 0 {
			newline += pos
			end = newline + 1
		}
		limit := end
		if pos+c.budget < limit {
			limit = pos + c.budget
		}
		piece := data[pos:limit]
		if len(c.chunkLine)+len(piece) > c.opts.MaxLine {
			c.end("framing")
			return pos + len(piece)
		}
		c.chunkLine = append(c.chunkLine, piece...)
		pos += len(piece)
		c.budget -= len(piece)
		if newline < 0 || end > pos {
			return pos
		}
		line := c.chunkLine
		c.chunkLine = nil
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			c.end("framing")
			return pos
		}
		line = line[:len(line)-2]
		switch c.chunkState {
		case chunkSize:
			size, ok := validChunkSize(line)
			if !ok {
				c.end("framing")
				return pos
			}
			if size == 0 {
				c.chunkState = chunkTrailers
			} else {
				c.skip, c.chunkState = size, chunkData
			}
		case chunkDataCRLF:
			if len(line) > 0 {
				c.end("framing")
				return pos
			}
			c.chunkState = chunkSize
		default: // trailers: header lines until an empty line; names are not read
			if len(line) == 0 {
				c.chunked, c.chunkState = false, chunkNone
				return pos
			}
		}
	}
	return pos
}
