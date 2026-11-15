package framed

import (
	"encoding/binary"
	"regexp"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// order reads unsigned integers in the byte order a message header declared.
type order bool // true = little endian

func (o order) uint(b []byte) int {
	if o {
		n := 0
		for i := len(b) - 1; i >= 0; i-- {
			n = n<<8 | int(b[i])
		}
		return n
	}
	return be(b)
}

// --- GIOP 1.2 over the bounded CDR cursor (giop.py, cdr.py) ---------------------------------------

// cdr ports cdr.CDRCursor: offsets are relative to the complete message, so alignment uses pos.
type cdr struct {
	data  []byte
	order order
	pos   int
}

func (c *cdr) take(size int) ([]byte, error) {
	if size < 0 || size > len(c.data)-c.pos {
		return nil, parsing.Malformed("CDR field exceeds enclosing message")
	}
	start := c.pos
	c.pos += size
	return c.data[start:c.pos], nil
}

func (c *cdr) align(width int) error {
	_, err := c.take((width - c.pos%width) % width)
	return err
}

func (c *cdr) uint(width int) (int, error) {
	if err := c.align(width); err != nil {
		return 0, err
	}
	b, err := c.take(width)
	if err != nil {
		return 0, err
	}
	return c.order.uint(b), nil
}

func (c *cdr) sequence(limit int) ([]byte, error) {
	size, err := c.uint(4)
	if err != nil {
		return nil, err
	}
	if size > limit {
		return nil, parsing.Budget("CDR sequence exceeds field budget")
	}
	return c.take(size)
}

func (c *cdr) string(limit int) ([]byte, error) {
	value, err := c.sequence(limit)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || value[len(value)-1] != 0 {
		return nil, parsing.Malformed("CDR string requires exactly one terminal NUL")
	}
	for _, b := range value[:len(value)-1] {
		if b == 0 {
			return nil, parsing.Malformed("CDR string requires exactly one terminal NUL")
		}
	}
	return value[:len(value)-1], nil
}

var giopOperation = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var giopReplyStatus = []string{"no-exception", "user-exception", "system-exception", "location-forward", "location-forward-perm", "needs-addressing-mode"}
var giopLocateStatus = []string{"unknown-object", "object-here", "object-forward", "object-forward-perm", "loc-system-exception", "loc-needs-addressing-mode"}
var giopMinimum = map[byte]int{0: 24, 1: 12, 3: 12, 4: 8}

// NewGIOP creates the GIOP 1.2 parser (KeyAddr Request/LocateRequest, Reply, LocateReply).
func NewGIOP(maxBytes, maxLine, maxHeaders int) *Parser {
	var little order
	contextBudget := maxHeaders
	if contextBudget > 128 {
		contextBudget = 128
	}
	contexts := func(c *cdr) error {
		count, err := c.uint(4)
		if err != nil {
			return err
		}
		if count > contextBudget {
			return parsing.Budget("GIOP service-context count exceeds budget")
		}
		// Preflight even a malicious count before iterating; contents stay opaque.
		if count > (len(c.data)-c.pos)/8 {
			return parsing.Malformed("Truncated GIOP service-context list")
		}
		for i := 0; i < count; i++ {
			if _, err := c.uint(4); err != nil {
				return err
			}
			if _, err := c.sequence(maxBytes); err != nil {
				return err
			}
		}
		return nil
	}
	return newParser(maxBytes, spec{header: 12,
		size: func(d []byte) (int, error) {
			if string(d[:4]) != "GIOP" {
				return 0, parsing.Malformed("Invalid GIOP magic")
			}
			if d[4] != 1 || d[5] != 2 {
				return 0, parsing.Unsupported("GIOP profile supports version 1.2 only")
			}
			if d[6]&^1 != 0 {
				return 0, parsing.Unsupported("Fragmented GIOP and reserved flags outside profile")
			}
			minimum, ok := giopMinimum[d[7]]
			if !ok {
				return 0, parsing.Unsupported("GIOP profile requires Request, Reply, LocateRequest or LocateReply")
			}
			little = d[6] == 1
			size := little.uint(d[8:12])
			if size < minimum {
				return 0, parsing.Malformed("GIOP body too short for supported message header")
			}
			return size + 12, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			c := &cdr{data: d, order: little, pos: 12}
			if _, err := c.uint(4); err != nil { // Request ID is opaque and never emitted.
				return nil, err
			}
			if d[7] == 1 || d[7] == 4 {
				return giopReply(d, c, contexts)
			}
			request := d[7] == 0
			if request {
				flags, err := c.uint(1)
				if err != nil {
					return nil, err
				}
				if flags != 0 && flags != 1 && flags != 3 {
					return nil, parsing.Unsupported("Unsupported GIOP response flags")
				}
				reserved, err := c.take(3)
				if err != nil {
					return nil, err
				}
				if !allZero(reserved) {
					return nil, parsing.Unsupported("GIOP profile requires zero reserved request bytes")
				}
			}
			target, err := c.uint(2)
			if err != nil {
				return nil, err
			}
			if target != 0 {
				return nil, parsing.Unsupported("GIOP profile requires KeyAddr target")
			}
			if _, err := c.sequence(maxLine); err != nil { // opaque object key, including empty
				return nil, err
			}
			r := &parsing.Result{ProtocolName: "giop/1.2"}
			if request {
				operation, err := c.string(maxLine)
				if err != nil {
					return nil, err
				}
				if !giopOperation.Match(operation) {
					return nil, parsing.Unsupported("GIOP operation outside ASCII identifier profile")
				}
				if err := contexts(c); err != nil {
					return nil, err
				}
				if c.pos < len(d) {
					if err := c.align(8); err != nil {
						return nil, err
					}
					if c.pos == len(d) {
						return nil, parsing.Malformed("GIOP empty request body must not have padding")
					}
				}
				r.Scope = "request_header"
				r.Reason = "GIOP 1.2 KeyAddr request header validated; arguments, contexts and server unverified"
				r.Extra = []parsing.Row{row("giop_message", "request", "header", "structural")}
				return r, nil
			}
			if c.pos != len(d) {
				return nil, parsing.Malformed("Unexpected bytes after GIOP LocateRequest")
			}
			r.Scope = "locate_request"
			r.Reason = "GIOP 1.2 KeyAddr LocateRequest validated; object identity and server unverified"
			r.Extra = []parsing.Row{row("giop_message", "locate-request", "header", "structural")}
			return r, nil
		}})
}

func giopReply(d []byte, c *cdr, contexts func(*cdr) error) (*parsing.Result, error) {
	status, err := c.uint(4)
	if err != nil {
		return nil, err
	}
	r := &parsing.Result{ProtocolName: "giop/1.2"}
	var label, name string
	if d[7] == 1 {
		if status > 5 {
			return nil, parsing.Malformed("GIOP reply status outside 0..5")
		}
		if err := contexts(c); err != nil {
			return nil, err
		}
		if c.pos < len(d) {
			if err := c.align(8); err != nil {
				return nil, err
			}
			if c.pos == len(d) {
				return nil, parsing.Malformed("GIOP empty reply body must not have padding")
			}
		}
		label, name = giopReplyStatus[status], "reply"
		r.Scope = "reply_header"
		r.Reason = "GIOP 1.2 Reply header validated; status reported, body and contexts opaque"
	} else {
		if status > 5 {
			return nil, parsing.Malformed("GIOP locate status outside 0..5")
		}
		if (status == 0 || status == 1) && c.pos != len(d) {
			return nil, parsing.Malformed("GIOP LocateReply without a body for UNKNOWN_OBJECT/OBJECT_HERE")
		}
		label, name = giopLocateStatus[status], "locate-reply"
		r.Scope = "locate_reply"
		r.Reason = "GIOP 1.2 LocateReply validated; status reported, forwarded reference opaque"
	}
	r.Extra = []parsing.Row{row("giop_message", name, "header", "structural"), row("giop_status", label, "header", "asserted")}
	return r, nil
}

// --- X11 connection setup (desktop.py) -----------------------------------------------------------------

var x11AuthNames = map[string]string{"MIT-MAGIC-COOKIE-1": "mit-magic-cookie-1", "XDM-AUTHORIZATION-1": "xdm-authorization-1", "SUN-DES-1": "sun-des-1",
	"MIT-KERBEROS-5": "mit-kerberos-5"}

func pad4(n int) int { return (n + 3) &^ 3 }

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func byteOrderLabel(little order) string {
	if little {
		return "lsb"
	}
	return "msb"
}

// NewX11 creates the client setup-request parser.
func NewX11(maxBytes int) *Parser {
	var little order
	var nameLength int
	return newParser(maxBytes, spec{header: 12,
		size: func(d []byte) (int, error) {
			switch d[0] {
			case 0x42:
				little = false
			case 0x6c:
				little = true
			default:
				return 0, parsing.Unsupported("X11 setup requires the byte-order byte B or l")
			}
			if d[1] != 0 {
				return 0, parsing.Malformed("X11 setup unused byte must be zero")
			}
			if little.uint(d[2:4]) != 11 || little.uint(d[4:6]) != 0 {
				return 0, parsing.Unsupported("Only X11 protocol 11.0 is supported")
			}
			name, data := little.uint(d[6:8]), little.uint(d[8:10])
			if name > 64 || data > 1024 {
				return 0, parsing.Malformed("X11 authorization lengths outside the profile")
			}
			if name == 0 && data > 0 {
				return 0, parsing.Malformed("X11 authorization data without a protocol name")
			}
			nameLength = name
			return 12 + pad4(name) + pad4(data), nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			name := d[12 : 12+nameLength]
			if !printable(name) {
				return nil, parsing.Malformed("X11 authorization protocol name must be printable")
			}
			label := "none"
			if nameLength > 0 {
				if label = x11AuthNames[string(name)]; label == "" {
					label = "other"
				}
			}
			return &parsing.Result{ProtocolName: "x11", Extra: []parsing.Row{row("x11_message", "setup-request", "setup", "structural"),
				row("x11_byte_order", byteOrderLabel(little), "setup", "structural"), row("x11_authorization", label, "setup", "asserted")},
				Reason: "X11 connection setup request validated; authorization data not emitted, requests not inspected"}, nil
		}})
}

// NewX11Reply creates the server setup-reply parser (selected only by the x11-server hint).
func NewX11Reply(maxBytes int) *Parser {
	var little order
	var status byte
	return newParser(maxBytes, spec{header: 8,
		size: func(d []byte) (int, error) {
			if d[0] > 2 {
				return 0, parsing.Unsupported("X11 setup reply status must be 0, 1 or 2")
			}
			switch {
			case d[2] == 0 && d[3] == 11:
				little = false
			case d[2] == 11 && d[3] == 0:
				little = true
			default:
				return 0, parsing.Unsupported("X11 setup reply requires protocol major 11")
			}
			if little.uint(d[4:6]) != 0 {
				return 0, parsing.Unsupported("Only X11 protocol 11.0 is supported")
			}
			status = d[0]
			words := little.uint(d[6:8])
			if status == 1 && words < 8 {
				return 0, parsing.Malformed("X11 setup success reply too short for its fixed fields")
			}
			if status == 0 && words < (int(d[1])+3)/4 {
				return 0, parsing.Malformed("X11 setup failure reason exceeds the reply")
			}
			if status == 2 && d[1] != 0 {
				return 0, parsing.Malformed("X11 authenticate reply unused byte must be zero")
			}
			return 8 + 4*words, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			var label string
			if status == 1 {
				vendor := little.uint(d[24:26])
				roots, formats := int(d[28]), int(d[29])
				if d[30] > 1 || d[31] > 1 || !scanline(d[32]) || !scanline(d[33]) {
					return nil, parsing.Malformed("X11 setup image byte order, bit order or scanline fields outside the specification")
				}
				if d[34] < 8 || d[35] < d[34] {
					return nil, parsing.Malformed("X11 keycode range outside the specification")
				}
				if roots == 0 || formats == 0 || 40+pad4(vendor)+8*formats+40*roots > len(d) {
					return nil, parsing.Malformed("X11 setup vendor, format and screen sizes exceed the reply")
				}
				label = "setup-success"
			} else {
				reason := d[8:]
				if status == 0 {
					end := 8 + int(d[1])
					if end > len(d) {
						end = len(d)
					}
					reason = d[8:end]
				}
				end := len(reason)
				for end > 0 && reason[end-1] == 0 {
					end--
				}
				if !printable(reason[:end]) {
					return nil, parsing.Malformed("X11 setup reason must be printable")
				}
				label = "setup-failed"
				if status == 2 {
					label = "setup-authenticate"
				}
			}
			return &parsing.Result{ProtocolName: "x11", Scope: "negotiation_response", Extra: []parsing.Row{row("x11_message", label, "setup", "structural"),
				row("x11_byte_order", byteOrderLabel(little), "setup", "structural")},
				Reason: "X11 setup reply validated with caller hint; vendor, reason and screen details not emitted"}, nil
		}})
}

func scanline(b byte) bool { return b == 8 || b == 16 || b == 32 }

// --- SPICE link header (desktop.py) ---------------------------------------------------------------------

var spiceChannels = map[byte]string{1: "main", 2: "display", 3: "inputs", 4: "cursor", 5: "playback", 6: "record", 7: "tunnel", 8: "smartcard",
	9: "usbredir", 10: "port", 11: "webdav"}
var spiceLinkErrors = []string{"ok", "error", "invalid-magic", "invalid-data", "version-mismatch", "need-secured", "need-unsecured",
	"permission-denied", "bad-connection-id", "channel-not-available"}

const spicePublicKey = 162
const maxSpiceCaps = 32

func le32(b []byte) int { return int(binary.LittleEndian.Uint32(b)) }

// NewSPICE creates the link-header parser (client SpiceLinkMess or server SpiceLinkReply).
func NewSPICE(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 16,
		size: func(d []byte) (int, error) {
			if string(d[:4]) != "REDQ" {
				return 0, parsing.Unsupported("SPICE link magic expected")
			}
			if le32(d[4:8]) != 2 || le32(d[8:12]) > 2 {
				return 0, parsing.Unsupported("Only SPICE link protocol 2.x is supported")
			}
			size := le32(d[12:16])
			if size < 18 || size > 16+spicePublicKey+12+8*maxSpiceCaps {
				return 0, parsing.Malformed("SPICE link message size outside the profile")
			}
			return 16 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			body := d[16:]
			if len(body) < 18 {
				return nil, parsing.Malformed("SPICE link message shorter than its fixed fields")
			}
			// The client layout is tried first; a reply can never satisfy it (see desktop.py).
			channelType := body[4]
			common, channel, offset := le32(body[6:10]), le32(body[10:14]), le32(body[14:18])
			if channelType != 0 && offset == 18 && common <= maxSpiceCaps && channel <= maxSpiceCaps && len(body) == 18+4*(common+channel) {
				if channelType != 1 && le32(body[:4]) == 0 {
					return nil, parsing.Malformed("SPICE secondary channel without a connection id")
				}
				label, ok := spiceChannels[channelType]
				if !ok {
					label = "other"
				}
				return &parsing.Result{ProtocolName: "spice", Extra: []parsing.Row{row("spice_message", "link-message", "link_header", "structural"),
					row("spice_channel", label, "link_message", "structural")}, Reason: "SPICE link message validated; connection id and capabilities not emitted"}, nil
			}
			if len(body) < spicePublicKey+16 || le32(body[spicePublicKey+12:spicePublicKey+16]) != spicePublicKey+16 {
				return nil, parsing.Malformed("SPICE link message fields outside the profile")
			}
			linkError := le32(body[:4])
			common = le32(body[spicePublicKey+4 : spicePublicKey+8])
			channel = le32(body[spicePublicKey+8 : spicePublicKey+12])
			if linkError >= len(spiceLinkErrors) {
				return nil, parsing.Malformed("SPICE link error outside the specification")
			}
			if common > maxSpiceCaps || channel > maxSpiceCaps || len(body) != spicePublicKey+16+4*(common+channel) {
				return nil, parsing.Malformed("SPICE link reply capability counts disagree with its size")
			}
			return &parsing.Result{ProtocolName: "spice", Scope: "negotiation_response", Extra: []parsing.Row{row("spice_message", "link-reply", "link_header", "structural"),
				row("spice_link_error", spiceLinkErrors[linkError], "link_reply", "structural")}, Reason: "SPICE link reply validated; public key and capabilities not emitted"}, nil
		}})
}
