package framed

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- Native Git pkt-line requests and the first server line (git_transport.py) --------------------------------

func gitHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

var gitParameter = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(?:=[\x21-\x7e]+)?$`)

// NewGit creates the pkt-line parser (an explicit git hint, or the git dispatch, uses it directly).
func NewGit(maxBytes, maxLine, maxHeaders int) *Parser {
	fieldBudget := maxHeaders
	if fieldBudget > 16 {
		fieldBudget = 16
	}
	widthBudget := maxLine
	if widthBudget > 512 {
		widthBudget = 512
	}
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			if !gitHex(h) {
				return 0, parsing.Malformed("Invalid lowercase Git pkt-line length")
			}
			size, _ := strconv.ParseInt(string(h), 16, 32)
			if size < 5 || size > 65520 {
				return 0, parsing.Malformed("Git request requires a data packet within pkt-line limits")
			}
			return int(size), nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			body := d[4:]
			if string(body) == "version 2\n" || (len(body) > 41 && body[40] == ' ' && gitHex(body[:40])) ||
				(len(body) > 65 && body[64] == ' ' && gitHex(body[:64])) {
				return gitAdvertisement(body)
			}
			if body[len(body)-1] != 0 {
				return nil, parsing.Malformed("Git service request must end with NUL")
			}
			if bytes.Count(body, []byte{0}) > fieldBudget+3 {
				return nil, parsing.Budget("Git request field count exceeds budget")
			}
			fields := bytes.Split(body, []byte{0})
			fields = fields[:len(fields)-1]
			command, path, separator := bytes.Cut(fields[0], []byte(" "))
			switch string(command) {
			case "git-upload-pack", "git-receive-pack", "git-upload-archive":
			default:
				separator = false
			}
			if !separator || len(path) == 0 {
				return nil, parsing.Malformed("Invalid Git service command or empty pathname")
			}
			if len(fields[0])+5 > maxLine {
				return nil, parsing.Budget("Git initial request field exceeds line budget")
			}
			for _, b := range path {
				if b < 32 || b == 127 {
					return nil, parsing.Unsupported("Control characters in Git pathname outside supported profile")
				}
			}
			rest := fields[1:]
			if len(rest) > 0 && bytes.HasPrefix(rest[0], []byte("host=")) {
				authority := rest[0][5:]
				rest = rest[1:]
				if len(authority) > 260 {
					return nil, parsing.Budget("Git virtual host exceeds profile budget")
				}
				if !gitAuthority(authority) {
					return nil, parsing.Malformed("Invalid Git ASCII DNS/IPv4 virtual host or port")
				}
			}
			version := ""
			if len(rest) > 0 {
				if len(rest[0]) != 0 || len(rest) == 1 {
					return nil, parsing.Malformed("Git extra parameters require a NUL separator and fields")
				}
				rest = rest[1:]
				if len(rest) > fieldBudget {
					return nil, parsing.Budget("Git extra parameter count exceeds budget")
				}
				keys := map[string]bool{}
				for _, parameter := range rest {
					if len(parameter) > widthBudget {
						return nil, parsing.Budget("Git extra parameter exceeds width budget")
					}
					if !gitParameter.Match(parameter) {
						return nil, parsing.Unsupported("Git extra parameter outside supported ASCII profile")
					}
					key, value, hasValue := bytes.Cut(parameter, []byte("="))
					if len(key) > 64 {
						return nil, parsing.Budget("Git parameter key exceeds budget")
					}
					if keys[string(key)] {
						return nil, parsing.Unsupported("Duplicate Git extra parameter outside supported profile")
					}
					keys[string(key)] = true
					if string(key) == "version" {
						if !hasValue || (string(value) != "1" && string(value) != "2") {
							return nil, parsing.Unsupported("Unsupported Git protocol version offer")
						}
						version = string(value)
					}
				}
			}
			evidence := []parsing.Row{row("git_message", "service-request", "pkt_line", "structural")}
			if version != "" {
				evidence = append(evidence, row("offered_version", version, "service_request", "offered"))
			}
			return &parsing.Result{ProtocolName: "git", Scope: "service_request", Extra: evidence,
				Reason: "Native Git service request framing validated; repository, server, version negotiation and packfile unverified"}, nil
		}})
}

// gitAuthority ports the host= check: ASCII, an optional 1..65535 decimal port, a DNS name or a strict IPv4 address.
func gitAuthority(authority []byte) bool {
	for _, b := range authority {
		if b >= 0x80 {
			return false
		}
	}
	host, port, colon := bytes.Cut(authority, []byte(":"))
	if colon {
		if len(port) == 0 || len(port) > 5 || !gitDigits(port) {
			return false
		}
		if n, _ := strconv.Atoi(string(port)); n < 1 || n > 65535 {
			return false
		}
	}
	if _, err := names.Normalize(string(host)); err == nil {
		return true
	}
	return names.IsIPv4(string(host))
}

func gitDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func gitAdvertisement(body []byte) (*parsing.Result, error) {
	name := "version-2"
	if string(body) != "version 2\n" {
		digest := 64
		if body[40] == ' ' {
			digest = 40
		}
		rest := body[digest+1:]
		if !bytes.HasSuffix(rest, []byte("\n")) {
			return nil, parsing.Malformed("Git ref advertisement line must end with LF")
		}
		refname, capabilities, separator := bytes.Cut(rest[:len(rest)-1], []byte{0})
		if !separator || len(refname) == 0 || len(refname) > 1024 {
			return nil, parsing.Malformed("Git ref advertisement requires a refname and a capability list")
		}
		if string(refname) != "HEAD" && !bytes.HasPrefix(refname, []byte("refs/")) {
			return nil, parsing.Unsupported("Git ref advertisement refname outside HEAD/refs/ profile")
		}
		bad := false
		for _, b := range refname {
			if b <= 32 || b == 127 {
				bad = true
			}
		}
		for _, b := range capabilities {
			if b < 32 || b == 127 {
				bad = true
			}
		}
		if bad {
			return nil, parsing.Malformed("Git ref advertisement contains control characters")
		}
		if bytes.IndexByte(capabilities, 0) >= 0 {
			return nil, parsing.Malformed("Git ref advertisement has more than one NUL")
		}
		name = "ref-advertisement"
	}
	label := "version 2"
	if name == "ref-advertisement" {
		label = "ref advertisement"
	}
	return &parsing.Result{ProtocolName: "git", Scope: "negotiation_response", Extra: []parsing.Row{row("git_message", name, "pkt_line", "structural")},
		Reason: "Git server " + label + " pkt-line validated; object ids, refnames and capabilities not emitted"}, nil
}

// --- The git/text discriminator (git_transport.GitTextParser) -----------------------------------------------------

// GitText resolves the ASCII pkt-line / HTTP-method overlap: it scans for the first NUL or LF within max_line,
// replays that bounded field once into the selected parser, then delegates every later call to it.
type GitText struct {
	maxLine int
	pending []byte
	child   parsing.Parser
	newGit  func() parsing.Parser
	newText func() (parsing.Parser, error)
}

// NewGitText creates the discriminator; the factories build the two possible children.
func NewGitText(maxLine int, newGit func() parsing.Parser, newText func() (parsing.Parser, error)) *GitText {
	return &GitText{maxLine: maxLine, newGit: newGit, newText: newText}
}

func (p *GitText) Done() bool { return p.child != nil && p.child.Done() }

func (p *GitText) Result() *parsing.Result {
	if p.child == nil {
		return nil
	}
	return p.child.Result()
}

// ResolvedFamily forwards the child's family ("" before a child exists, as Python's attribute lookup yields None).
func (p *GitText) ResolvedFamily() string {
	switch c := p.child.(type) {
	case nil:
		return ""
	case interface{ ResolvedFamily() string }:
		return c.ResolvedFamily()
	}
	return "git"
}

// Refined forwards the child's refinement state when it has one.
func (p *GitText) Refined() bool {
	if r, ok := p.child.(interface{ Refined() bool }); ok {
		return r.Refined()
	}
	return true
}

// Feed ports GitTextParser.feed.
func (p *GitText) Feed(data []byte) (int, error) {
	if p.child != nil {
		return p.child.Feed(data)
	}
	previous := len(p.pending)
	allowance := p.maxLine - previous
	nul := find(data, 0, 0, allowance)
	lf := find(data, '\n', 0, allowance)
	end := -1
	for _, i := range []int{nul, lf} {
		if i >= 0 && (end < 0 || i < end) {
			end = i
		}
	}
	amount := len(data)
	if allowance < amount {
		amount = allowance
	}
	if end >= 0 {
		amount = end + 1
	}
	p.pending = append(p.pending, data[:amount]...)
	if end < 0 {
		if len(data) > amount || len(p.pending) >= p.maxLine {
			return amount, parsing.Budget("Git/text discriminator exceeds line budget")
		}
		return amount, nil
	}
	if nul == amount-1 {
		p.child = p.newGit()
	} else {
		child, err := p.newText()
		if err != nil {
			return amount, err
		}
		p.child = child
	}
	pending := p.pending
	p.pending = nil
	consumed, err := p.child.Feed(pending)
	if err != nil {
		return amount, err
	}
	current := consumed - previous
	if current < 0 {
		current = 0
	}
	if !p.child.Done() {
		n, err := p.child.Feed(data[amount:])
		current += n
		if err != nil {
			return current, err
		}
	}
	return current, nil
}
