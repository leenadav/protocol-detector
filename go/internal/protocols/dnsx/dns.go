// Package dnsx ports the DNS-layout validator (protocol_engine/wire.py: dns_probe, dns_details) and the
// DNS-over-TCP framing parser (binary.DNSParser). Names are validated and never emitted; the structured
// evidence rows and reason sentences are the Python ones.
package dnsx

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Probe reports the DNS message layout (v0.55): QUERY opcode with 1..8 questions, zero questions for a
// response carrying answers, or the NetBIOS name service opcodes 5..8 with at most one question.
func Probe(data []byte) bool {
	if len(data) < 12 || data[3]&0x40 != 0 {
		return false
	}
	opcode := data[2] & 0x78
	questions := int(binary.BigEndian.Uint16(data[4:6]))
	if opcode == 0 && questions == 1 {
		return true
	}
	if len(data) <= 12 || data[12] < 1 || data[12] > 63 {
		return false
	}
	total := 0
	for i := 4; i < 12; i += 2 {
		total += int(binary.BigEndian.Uint16(data[i:]))
	}
	if total < 1 || total > 32 {
		return false
	}
	if opcode == 0 {
		if questions == 0 {
			return data[2]&0x80 != 0 && !(data[6] == 0 && data[7] == 0)
		}
		return questions <= 8
	}
	return (opcode == 0x28 || opcode == 0x30 || opcode == 0x38 || opcode == 0x40) && questions <= 1
}

var rcodes = []string{"noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset", "nxrrset", "notauth", "notzone"}

var qtypes = map[int]string{1: "a", 2: "ns", 5: "cname", 6: "soa", 12: "ptr", 15: "mx", 16: "txt", 28: "aaaa", 33: "srv", 35: "naptr", 43: "ds",
	46: "rrsig", 48: "dnskey", 64: "svcb", 65: "https", 255: "any", 32: "nb"}

var nbnsOpcodes = map[int]string{0: "query", 5: "registration", 6: "release", 7: "wack", 8: "refresh"}

// Reasons shared with Python.
const (
	ReasonDNS   = "DNS question and record framing validated; unknown RDATA semantics and DNSSEC unverified"
	ReasonMDNS  = "Multicast DNS framing validated (.local names, QU or cache-flush bits, question count); names and records never emitted"
	ReasonLLMNR = "LLMNR header and single question validated with the llmnr hint (opcode zero, zero Z field); names never emitted"
)

// Details is the validated message: protocol family, reason and the evidence rows (without the
// application_protocol row), plus the question name and type (never emitted; kept for contexts).
type Details struct {
	Protocol string
	Reason   string
	QName    []byte
	QType    int
	Rows     []parsing.Row
}

func row(field, value string) parsing.Row {
	return parsing.Row{Field: field, Value: value, Provenance: "wire", Strength: "structural"}
}

func isNetbiosLabel(b byte) bool { return (b >= 'A' && b <= 'P') || (b >= 'a' && b <= 'p') }

func netbiosName(qname []byte) bool {
	first := qname
	if i := bytes.IndexByte(qname, '.'); i >= 0 {
		first = qname[:i]
	}
	if len(first) != 32 {
		return false
	}
	for _, b := range first {
		if !isNetbiosLabel(b) {
			return false
		}
	}
	return true
}

func localName(name []byte) bool {
	return bytes.Equal(name, []byte("local")) || bytes.HasSuffix(name, []byte(".local"))
}

// QueryTypeClass is the closed label for the question type.
func QueryTypeClass(qname []byte, qtype int) string {
	netbios := netbiosName(qname)
	if qtype == 33 && netbios {
		return "nbstat"
	}
	if qtype == 32 {
		if netbios {
			return "nb"
		}
		return "other"
	}
	if label, ok := qtypes[qtype]; ok {
		return label
	}
	return "other"
}

func expandName(data []byte, start, end int) []byte {
	var labels [][]byte
	pos := start
	for pos < end {
		length := int(data[pos])
		if length&0xc0 != 0 {
			break
		}
		pos++
		if length == 0 {
			break
		}
		labels = append(labels, bytes.ToLower(data[pos:pos+length]))
		pos += length
	}
	return bytes.Join(labels, []byte("."))
}

func nbnsRdata(data []byte, pos, end, kind, opcode int, response bool) error {
	size := end - pos
	if kind == 32 {
		if opcode == 7 {
			if !response || size != 2 {
				return parsing.Malformed("NetBIOS WACK carries exactly the two-byte flags word in a response")
			}
			return nil
		}
		if size < 6 || size%6 != 0 {
			return parsing.Malformed("NetBIOS NB record data must be one or more 6-byte address entries")
		}
		for entry := pos; entry < end; entry += 6 {
			if binary.BigEndian.Uint16(data[entry:])&0x1fff != 0 {
				return parsing.Malformed("NetBIOS NB_FLAGS reserved bits set")
			}
		}
		return nil
	}
	if !response {
		return parsing.Malformed("NetBIOS node status data appears only in responses")
	}
	if size < 47 || (size-47)%18 != 0 || 1+18*int(data[pos])+46 != size {
		return parsing.Malformed("NetBIOS node status data must hold NUM_NAMES 18-byte entries and the 46-byte statistics")
	}
	for entry := pos + 1; entry < pos+1+18*int(data[pos]); entry += 18 {
		if binary.BigEndian.Uint16(data[entry+16:])&0x01ff != 0 {
			return parsing.Malformed("NetBIOS NAME_FLAGS reserved bits set")
		}
	}
	return nil
}

// Validate ports dns_details. maxBytes is Config.max_bytes (the name-walk work budget); llmnr selects
// the hint-only LLMNR header semantics.
func Validate(data []byte, maxBytes int, llmnr bool) (*Details, error) {
	if llmnr {
		if len(data) < 12 || data[2]&0x78 != 0 || data[3]&0xf0 != 0 || data[4] != 0 || data[5] != 1 {
			return nil, parsing.Unsupported("LLMNR requires opcode zero, one question and a zero Z field")
		}
	} else if !Probe(data) {
		return nil, parsing.Unsupported("DNS layout requires the QUERY or a NetBIOS name service opcode and a bounded question count")
	}
	if data[2]&2 != 0 {
		return nil, parsing.Unsupported("Truncated DNS messages require transport retry")
	}
	response := data[2]&0x80 != 0
	opcode := int(data[2]>>3) & 15
	rcode := int(data[3] & 0x0f)
	var counts [4]int
	total := 0
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(data[4+2*i:]))
		total += counts[i]
	}
	if total > 128 {
		return nil, parsing.Budget("DNS record count exceeds inspection limit")
	}
	steps := 0
	boundaries := map[int]bool{}
	var name func(start int) (int, error)
	name = func(start int) (int, error) {
		pos, end, size := start, -1, 1
		visited := map[int]bool{}
		for {
			steps++
			if steps > maxBytes {
				return 0, parsing.Budget("DNS name work budget exhausted")
			}
			if pos >= len(data) || visited[pos] {
				return 0, parsing.Malformed("Truncated or cyclic DNS name")
			}
			visited[pos] = true
			length := int(data[pos])
			if length&0xc0 == 0xc0 {
				if pos+1 >= len(data) {
					return 0, parsing.Malformed("Truncated DNS compression pointer")
				}
				target := (length&63)<<8 | int(data[pos+1])
				if target >= pos || !boundaries[target] {
					return 0, parsing.Malformed("DNS pointer must reference an earlier parsed name boundary")
				}
				if end == -1 {
					end = pos + 2
				}
				pos = target
				continue
			}
			if length&0xc0 != 0 || pos+1+length > len(data) {
				return 0, parsing.Malformed("Invalid DNS label length")
			}
			boundaries[pos] = true
			pos++
			if length == 0 {
				if end != -1 {
					return end, nil
				}
				return pos, nil
			}
			size += 1 + length
			if size > 255 {
				return 0, parsing.Malformed("DNS expanded name exceeds 255 bytes")
			}
			pos += length
		}
	}
	pos := 12
	var qname []byte
	qtype := 0
	unicastRequested, local := false, false
	netbios := opcode != 0
	for index := 0; index < counts[0]; index++ {
		start := pos
		next, err := name(pos)
		if err != nil {
			return nil, err
		}
		pos = next
		if pos+4 > len(data) {
			return nil, parsing.Malformed("Truncated DNS question")
		}
		expanded := expandName(data, start, pos)
		kind, class := int(binary.BigEndian.Uint16(data[pos:])), int(binary.BigEndian.Uint16(data[pos+2:]))
		if kind == 0 || (class&0x7fff != 1 && class&0x7fff != 255) {
			return nil, parsing.Unsupported("Unsupported DNS question type/class profile")
		}
		pos += 4
		if index == 0 {
			qname, qtype = expanded, kind
			netbios = netbios || ((kind == 32 || kind == 33) && netbiosName(expanded))
		}
		unicastRequested = unicastRequested || class&0x8000 != 0
		local = local || localName(expanded)
	}
	cacheFlush := false
	for section := 1; section < 4; section++ {
		for i := 0; i < counts[section]; i++ {
			start := pos
			next, err := name(pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if pos+10 > len(data) {
				return nil, parsing.Malformed("Truncated DNS resource record")
			}
			kind := int(binary.BigEndian.Uint16(data[pos:]))
			class := int(binary.BigEndian.Uint16(data[pos+2:]))
			size := int(binary.BigEndian.Uint16(data[pos+8:]))
			pos += 10
			end := pos + size
			if end > len(data) {
				return nil, parsing.Malformed("DNS RDATA exceeds message")
			}
			if counts[0] == 0 && qtype == 0 {
				qname, qtype = expandName(data, start, pos-10), kind
				netbios = netbios || ((kind == 32 || kind == 33) && netbiosName(qname))
				local = local || localName(qname)
			}
			if class&0x8000 != 0 && kind != 41 {
				if !response {
					return nil, parsing.Malformed("The cache-flush bit belongs to multicast DNS responses, not to queries")
				}
				cacheFlush = true
			}
			if (kind == 1 || kind == 28) && size != map[bool]int{true: 4, false: 16}[kind == 1] {
				return nil, parsing.Malformed("Invalid DNS address record size")
			}
			if kind == 2 || kind == 5 || kind == 12 {
				if n, err := name(pos); err != nil {
					return nil, err
				} else if n != end {
					return nil, parsing.Malformed("Invalid DNS name RDATA length")
				}
			}
			if kind == 15 {
				if size < 3 {
					return nil, parsing.Malformed("Invalid DNS MX RDATA")
				}
				if n, err := name(pos + 2); err != nil {
					return nil, err
				} else if n != end {
					return nil, parsing.Malformed("Invalid DNS MX RDATA")
				}
			}
			if kind == 6 {
				n1, err := name(pos)
				if err != nil {
					return nil, err
				}
				n2, err := name(n1)
				if err != nil {
					return nil, err
				}
				if n2+20 != end {
					return nil, parsing.Malformed("Invalid DNS SOA RDATA")
				}
			}
			if kind == 33 && !netbios {
				if size < 7 {
					return nil, parsing.Malformed("Invalid DNS SRV RDATA")
				}
				if n, err := name(pos + 6); err != nil {
					return nil, err
				} else if n != end {
					return nil, parsing.Malformed("Invalid DNS SRV RDATA")
				}
			}
			if kind == 47 {
				if n, err := name(pos); err != nil {
					return nil, err
				} else if n > end {
					return nil, parsing.Malformed("Invalid DNS NSEC RDATA")
				}
			}
			if kind == 16 {
				cursor := pos
				for cursor < end {
					cursor += 1 + int(data[cursor])
				}
				if cursor != end {
					return nil, parsing.Malformed("Invalid DNS TXT RDATA")
				}
			}
			if kind == 41 {
				cursor := pos
				for cursor < end {
					if cursor+4 > end {
						return nil, parsing.Malformed("Truncated EDNS option")
					}
					cursor += 4 + int(binary.BigEndian.Uint16(data[cursor+2:]))
				}
				if cursor != end {
					return nil, parsing.Malformed("Invalid EDNS option length")
				}
			}
			if netbios && (kind == 32 || kind == 33) {
				if err := nbnsRdata(data, pos, end, kind, opcode, response); err != nil {
					return nil, err
				}
			}
			pos = end
		}
	}
	if pos != len(data) {
		return nil, parsing.Malformed("Trailing bytes after DNS sections")
	}
	var rows []parsing.Row
	if !response {
		rows = append(rows, row("dns_message", "query"))
	} else {
		label := "other"
		if rcode < len(rcodes) {
			label = rcodes[rcode]
		}
		rows = append(rows, row("dns_message", "response"), row("dns_rcode", label))
	}
	rows = append(rows, row("dns_query_type", QueryTypeClass(qname, qtype)))
	if llmnr {
		conflict, tentative := data[2]&0x04 != 0, data[2]&0x01 != 0
		if !response && (rcode != 0 || counts[1] != 0 || counts[2] != 0 || tentative) {
			return nil, parsing.Malformed("LLMNR query must not carry answers, authority records, a response code or the T bit")
		}
		if netbios || local {
			return nil, parsing.Unsupported("NetBIOS or .local names are not LLMNR")
		}
		label := "none"
		if conflict {
			label = "conflict"
		} else if tentative {
			label = "tentative"
		}
		return &Details{"llmnr", ReasonLLMNR, qname, qtype, append(rows, row("llmnr_flags", label))}, nil
	}
	if netbios {
		label, ok := nbnsOpcodes[opcode]
		if !ok || !netbiosName(qname) {
			return nil, parsing.Unsupported("NetBIOS name service needs an encoded name with a query, registration, release, WACK or refresh opcode")
		}
		if !response {
			if rcode != 0 || counts[1] != 0 || counts[2] != 0 || (opcode != 0 && (counts[0] != 1 || counts[3] != 1)) {
				return nil, parsing.Malformed("NetBIOS name service request sections outside RFC 1002")
			}
		} else if counts[0] > 1 || counts[1] > 1 || counts[2] != 0 || counts[3] != 0 {
			return nil, parsing.Malformed("NetBIOS name service response sections outside RFC 1002")
		}
		reason := fmt.Sprintf("NetBIOS name service %s framing validated; names, addresses and node status are never emitted", label)
		return &Details{"netbios-ns", reason, qname, qtype, append(rows, row("nbns_opcode", label))}, nil
	}
	probe := !response && qtype == 255 && counts[2] > 0
	if counts[0] == 0 || unicastRequested || cacheFlush || local || probe {
		if counts[0] == 0 && !(local || cacheFlush) {
			return nil, parsing.Malformed("DNS response without a question")
		}
		if response && (rcode != 0 || data[2]&0x04 == 0) {
			return nil, parsing.Malformed("Multicast DNS responses carry the AA bit and a zero response code")
		}
		if !response && rcode != 0 {
			return nil, parsing.Malformed("Multicast DNS queries carry no response code")
		}
		profile := "plain"
		switch {
		case counts[0] == 0:
			profile = "announcement"
		case !response && counts[2] != 0:
			profile = "probe"
		case !response && counts[1] != 0:
			profile = "known-answer"
		case unicastRequested:
			profile = "unicast-requested"
		}
		return &Details{"mdns", ReasonMDNS, qname, qtype, append(rows, row("mdns_profile", profile))}, nil
	}
	if counts[0] != 1 {
		return nil, parsing.Unsupported("Several questions without multicast DNS markers are outside the DNS profile")
	}
	if !response && (data[2]&0x04 != 0 || rcode != 0 || counts[1] != 0 || counts[2] != 0) {
		return nil, parsing.Malformed("DNS query must not carry the AA bit, answers, authority records or a response code")
	}
	return &Details{"dns", ReasonDNS, qname, qtype, rows}, nil
}

// TCP is the DNS-over-TCP framing parser (binary.DNSParser on the FrameParser base).
type TCP struct {
	maxBytes   int
	buffer     []byte
	needed     int
	headerDone bool
	done       bool
	result     *parsing.Result
}

// NewTCP creates the parser with the direction's byte budget.
func NewTCP(maxBytes int) *TCP {
	return &TCP{maxBytes: maxBytes, needed: 2}
}

func (p *TCP) Done() bool              { return p.done }
func (p *TCP) Result() *parsing.Result { return p.result }

// Feed ports FrameParser.feed with DNSParser's frame_size/validate.
func (p *TCP) Feed(data []byte) (int, error) {
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
			size := int(binary.BigEndian.Uint16(p.buffer[:2]))
			if size < 12 {
				return pos, parsing.Malformed("DNS TCP message shorter than DNS header")
			}
			p.needed = size + 2
			if p.needed < 2 {
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
		details, err := Validate(p.buffer[2:], p.maxBytes, false)
		if err != nil {
			return pos, err
		}
		if details.Protocol == "netbios-ns" {
			for _, r := range details.Rows {
				if r.Field == "nbns_opcode" && r.Value != "query" {
					return pos, parsing.Unsupported("NetBIOS name service registration traffic is UDP only")
				}
			}
		}
		rows := make([]parsing.Row, len(details.Rows))
		for i, r := range details.Rows {
			rows[i] = parsing.Row{Field: r.Field, Value: r.Value, Provenance: "message", Strength: r.Strength}
		}
		p.result = &parsing.Result{ProtocolName: "dns", Reason: details.Reason, Extra: rows}
		p.done = true
		p.buffer = nil
	}
	return pos, nil
}
