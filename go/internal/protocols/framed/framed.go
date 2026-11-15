// Package framed ports protocol_engine/framing.FrameParser and the initial binary-message families built
// on it (binary.py PostgreSQL/RFB/BitTorrent/memcached, fins.py, afp.py, greetings.py ZMTP/Bolt), plus
// the two small line protocols of the same batch (rsync.py, stomp.py). Every advertised size is bounded
// before the buffer grows; reason sentences and evidence rows are the Python ones.
package framed

import (
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// spec is one family's frame rule: the fixed header size, the advertised total size, and the check of
// the complete frame. State discovered in size() (message kind) is kept by the closure that built it.
type spec struct {
	header   int
	size     func(header []byte) (int, error)
	validate func(frame []byte) (*parsing.Result, error)
}

// Parser is FrameParser.feed over a spec.
type Parser struct {
	maxBytes   int
	spec       spec
	buffer     []byte
	needed     int
	headerDone bool
	done       bool
	result     *parsing.Result
}

func newParser(maxBytes int, s spec) *Parser {
	return &Parser{maxBytes: maxBytes, spec: s, needed: s.header}
}

func (p *Parser) Done() bool              { return p.done }
func (p *Parser) Result() *parsing.Result { return p.result }

// Feed ports FrameParser.feed: fill the header, size the frame against the budget, validate once complete.
func (p *Parser) Feed(data []byte) (int, error) {
	pos := 0
	for !p.done {
		amount := p.needed - len(p.buffer)
		if amount > len(data)-pos {
			amount = len(data) - pos
		}
		p.buffer = append(p.buffer, data[pos:pos+amount]...)
		pos += amount
		if len(p.buffer) < p.needed {
			break
		}
		if !p.headerDone {
			size, err := p.spec.size(p.buffer)
			if err != nil {
				return pos, err
			}
			p.needed = size
			if p.needed < p.spec.header {
				return pos, parsing.Malformed("Frame length shorter than its header")
			}
			if p.needed > p.maxBytes {
				return pos, parsing.Budget("Advertised frame exceeds byte budget")
			}
			p.headerDone = true
			if len(p.buffer) < p.needed {
				if pos == len(data) {
					break
				}
				continue
			}
		}
		result, err := p.spec.validate(p.buffer)
		if err != nil {
			return pos, err
		}
		if result.Scope == "" {
			result.Scope = "initial_message"
		}
		if result.ALPN == nil {
			result.ALPN = []string{}
		}
		p.result = result
		p.done = true
		p.buffer = nil
	}
	return pos, nil
}

func row(field, value, provenance, strength string) parsing.Row {
	return parsing.Row{Field: field, Value: value, Provenance: provenance, Strength: strength}
}

func be(b []byte) int {
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
