// Package capture ports protocol_adapters/capture_stream.PcapStreamDecoder and packets.read_pcap_records:
// incremental classic PCAP (all four magics) and pcapng (section header, interface description, enhanced and
// simple packet blocks; other blocks skipped) framing. Every length is checked before a slice is taken, blocks
// and records are bounded, and a failure closes the decoder: capture framing is untrusted input.
package capture

import (
	"encoding/binary"
	"io"
	"math/big"
	"os"
	"strconv"
)

// Error is CaptureError.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func fail(message string) *Error { return &Error{message} }

// Record is CaptureRecord: one captured frame with its original wire length and link type.
type Record struct {
	Timestamp      float64
	Data           []byte
	OriginalLength int
	Linktype       int
}

// Truncated reports a record shorter than the frame on the wire.
func (r Record) Truncated() bool { return len(r.Data) < r.OriginalLength }

var linkTypes = map[int]bool{0: true, 1: true, 101: true, 108: true, 113: true, 228: true, 276: true}

const (
	maxSnaplen = 1048576
	maxBlock   = maxSnaplen + 65536 // packet data plus bounded options
	maxChunk   = 65536
)

type iface struct {
	linktype, snaplen int
	resolution        uint64
}

// Decoder is PcapStreamDecoder.
type Decoder struct {
	buffer        []byte
	format        string // "", "pcap" or "pcapng"
	linktype      int    // -1 until known
	finished      bool
	failed        bool
	order         binary.ByteOrder
	resolution    uint64
	snaplen       int
	interfaces    []iface
	sections      int
	BlocksSkipped int
}

// NewDecoder returns an open decoder.
func NewDecoder() *Decoder { return &Decoder{linktype: -1} }

// Linktype is the classic header link type or the first pcapng interface's (-1 before it is known).
func (d *Decoder) Linktype() int { return d.linktype }

// Format is "pcap" or "pcapng" once the first four bytes arrived.
func (d *Decoder) Format() string { return d.format }

// Feed adds at most 64 KiB and returns the records completed by it.
func (d *Decoder) Feed(chunk []byte) ([]Record, error) {
	if d.finished || d.failed {
		return nil, fail("PCAP decoder is closed")
	}
	if len(chunk) > maxChunk {
		return nil, fail("PCAP input chunk exceeds 64 KiB")
	}
	d.buffer = append(d.buffer, chunk...)
	if d.format == "" {
		if len(d.buffer) < 4 {
			return nil, nil
		}
		d.format = "pcap"
		if string(d.buffer[:4]) == "\x0a\x0d\x0d\x0a" {
			d.format = "pcapng"
		}
	}
	var records []Record
	var err *Error
	if d.format == "pcapng" {
		records, err = d.parsePcapng()
	} else {
		records, err = d.parse()
	}
	if err != nil {
		d.failed = true
		d.buffer = nil
		return nil, err
	}
	return records, nil
}

// timestamp is Python's true division of two integers: correctly rounded.
func timestamp(value, resolution uint64) float64 {
	if value < 1<<53 && resolution < 1<<53 {
		return float64(value) / float64(resolution)
	}
	f, _ := new(big.Rat).SetFrac(new(big.Int).SetUint64(value), new(big.Int).SetUint64(resolution)).Float64()
	return f
}

func (d *Decoder) parse() ([]Record, *Error) {
	if d.linktype < 0 {
		if len(d.buffer) < 24 {
			return nil, nil
		}
		switch string(d.buffer[:4]) {
		case "\xd4\xc3\xb2\xa1":
			d.order, d.resolution = binary.LittleEndian, 1000000
		case "\xa1\xb2\xc3\xd4":
			d.order, d.resolution = binary.BigEndian, 1000000
		case "\x4d\x3c\xb2\xa1":
			d.order, d.resolution = binary.LittleEndian, 1000000000
		case "\xa1\xb2\x3c\x4d":
			d.order, d.resolution = binary.BigEndian, 1000000000
		default:
			return nil, fail("Not a classic PCAP or pcapng capture")
		}
		major, minor := d.order.Uint16(d.buffer[4:6]), d.order.Uint16(d.buffer[6:8])
		snaplen, linktype := d.order.Uint32(d.buffer[16:20]), d.order.Uint32(d.buffer[20:24])
		if major != 2 || minor != 4 || snaplen < 1 || snaplen > maxSnaplen {
			return nil, fail("Unsupported PCAP version or snapshot length")
		}
		if linktype > 1<<30 || !linkTypes[int(linktype)] {
			return nil, fail("Unsupported capture link type: " + strconv.FormatUint(uint64(linktype), 10))
		}
		d.snaplen, d.linktype = int(snaplen), int(linktype)
		d.buffer = d.buffer[24:]
	}
	var records []Record
	pos := 0
	for len(d.buffer)-pos >= 16 {
		seconds, fraction := d.order.Uint32(d.buffer[pos:]), d.order.Uint32(d.buffer[pos+4:])
		included, original := d.order.Uint32(d.buffer[pos+8:]), d.order.Uint32(d.buffer[pos+12:])
		if uint64(included) > uint64(d.snaplen) || included > original || uint64(fraction) >= d.resolution {
			return nil, fail("Invalid PCAP record lengths or timestamp")
		}
		end := pos + 16 + int(included)
		if end > len(d.buffer) {
			break
		}
		// seconds + fraction / resolution, as the reference computes it (one division, one addition).
		records = append(records, Record{float64(seconds) + float64(fraction)/float64(d.resolution),
			append([]byte{}, d.buffer[pos+16:end]...), int(original), d.linktype})
		pos = end
	}
	if pos > 0 {
		d.buffer = append([]byte{}, d.buffer[pos:]...)
	}
	return records, nil
}

func (d *Decoder) parsePcapng() ([]Record, *Error) {
	var records []Record
	pos := 0
	for len(d.buffer)-pos >= 12 {
		section := string(d.buffer[pos:pos+4]) == "\x0a\x0d\x0d\x0a"
		order := d.order
		if section {
			switch string(d.buffer[pos+8 : pos+12]) {
			case "\x4d\x3c\x2b\x1a":
				order = binary.LittleEndian
			case "\x1a\x2b\x3c\x4d":
				order = binary.BigEndian
			default:
				return nil, fail("pcapng section header without a valid byte-order magic")
			}
		} else if d.order == nil {
			return nil, fail("pcapng stream must start with a section header block")
		}
		total := int(order.Uint32(d.buffer[pos+4:]))
		if total < 12 || total%4 != 0 || total > maxBlock {
			return nil, fail("Invalid pcapng block length")
		}
		if len(d.buffer)-pos < total {
			break
		}
		if int(order.Uint32(d.buffer[pos+total-4:])) != total {
			return nil, fail("pcapng block trailer disagrees with its header")
		}
		body := d.buffer[pos+8 : pos+total-4]
		kind := order.Uint32(d.buffer[pos:])
		var err *Error
		switch {
		case section:
			err = d.section(order, body)
		case kind == 1:
			err = d.interfaceBlock(body)
		case kind == 6:
			var r Record
			if r, err = d.enhanced(body); err == nil {
				records = append(records, r)
			}
		case kind == 3:
			var r Record
			if r, err = d.simple(body); err == nil {
				records = append(records, r)
			}
		default:
			d.BlocksSkipped++ // name resolution, statistics, decryption secrets, custom blocks
		}
		if err != nil {
			return nil, err
		}
		pos += total
	}
	if pos > 0 {
		d.buffer = append([]byte{}, d.buffer[pos:]...)
	}
	return records, nil
}

func (d *Decoder) section(order binary.ByteOrder, body []byte) *Error {
	if len(body) < 16 {
		return fail("Truncated pcapng section header")
	}
	if order.Uint16(body[4:]) != 1 || order.Uint16(body[6:]) != 0 {
		return fail("Unsupported pcapng version")
	}
	d.order = order
	d.interfaces = nil
	d.sections++
	_, err := d.options(body[16:])
	return err
}

type option struct {
	code  int
	value []byte
}

// options walks an option list: every option must fit the block and end at opt_endofopt or the end.
func (d *Decoder) options(data []byte) ([]option, *Error) {
	var found []option
	pos := 0
	for pos < len(data) {
		if pos+4 > len(data) {
			return nil, fail("Truncated pcapng option header")
		}
		code, length := int(d.order.Uint16(data[pos:])), int(d.order.Uint16(data[pos+2:]))
		padded := (length + 3) &^ 3
		if pos+4+padded > len(data) {
			return nil, fail("pcapng option exceeds its block")
		}
		if code == 0 {
			return found, nil
		}
		found = append(found, option{code, data[pos+4 : pos+4+length]})
		if len(found) > 256 {
			return nil, fail("pcapng option count exceeds profile")
		}
		pos += 4 + padded
	}
	return found, nil
}

func (d *Decoder) interfaceBlock(body []byte) *Error {
	if len(body) < 8 {
		return fail("Truncated pcapng interface description")
	}
	linktype, snaplen := int(d.order.Uint16(body)), d.order.Uint32(body[4:])
	if !linkTypes[linktype] {
		return fail("Unsupported capture link type: " + strconv.Itoa(linktype))
	}
	if snaplen > maxSnaplen {
		return fail("pcapng snapshot length exceeds 1 MiB")
	}
	resolution := uint64(1000000)
	opts, err := d.options(body[8:])
	if err != nil {
		return err
	}
	for _, o := range opts {
		if o.code != 9 {
			continue
		}
		if len(o.value) != 1 {
			return fail("Invalid pcapng if_tsresol option")
		}
		exponent := int(o.value[0] & 0x7f)
		if o.value[0]&0x80 != 0 {
			if exponent > 48 {
				return fail("pcapng binary timestamp resolution outside profile")
			}
			resolution = 1 << uint(exponent)
		} else {
			if exponent > 12 {
				return fail("pcapng decimal timestamp resolution outside profile")
			}
			resolution = 1
			for i := 0; i < exponent; i++ {
				resolution *= 10
			}
		}
	}
	if len(d.interfaces) >= 256 {
		return fail("pcapng interface count exceeds profile")
	}
	snap := int(snaplen)
	if snap == 0 {
		snap = maxSnaplen
	}
	d.interfaces = append(d.interfaces, iface{linktype, snap, resolution})
	if d.linktype < 0 {
		d.linktype, d.snaplen, d.resolution = linktype, snap, resolution
	}
	return nil
}

func (d *Decoder) enhanced(body []byte) (Record, *Error) {
	if len(body) < 20 {
		return Record{}, fail("Truncated pcapng enhanced packet block")
	}
	index, high, low := d.order.Uint32(body), d.order.Uint32(body[4:]), d.order.Uint32(body[8:])
	captured, original := d.order.Uint32(body[12:]), d.order.Uint32(body[16:])
	if uint64(index) >= uint64(len(d.interfaces)) {
		return Record{}, fail("pcapng packet references an undefined interface")
	}
	in := d.interfaces[index]
	if uint64(captured) > uint64(in.snaplen) || captured > original {
		return Record{}, fail("Invalid pcapng packet lengths")
	}
	padded := (int(captured) + 3) &^ 3
	if 20+padded > len(body) {
		return Record{}, fail("pcapng packet data exceeds its block")
	}
	if _, err := d.options(body[20+padded:]); err != nil {
		return Record{}, err
	}
	return Record{timestamp(uint64(high)<<32|uint64(low), in.resolution), append([]byte{}, body[20:20+int(captured)]...), int(original), in.linktype}, nil
}

func (d *Decoder) simple(body []byte) (Record, *Error) {
	if len(d.interfaces) == 0 {
		return Record{}, fail("pcapng simple packet without an interface description")
	}
	if len(body) < 4 {
		return Record{}, fail("Truncated pcapng simple packet block")
	}
	in := d.interfaces[0]
	original := int(d.order.Uint32(body))
	captured := original
	if captured > in.snaplen {
		captured = in.snaplen
	}
	if 4+((captured+3)&^3) != len(body) {
		return Record{}, fail("pcapng simple packet length disagrees with its block")
	}
	return Record{0, append([]byte{}, body[4:4+captured]...), original, in.linktype}, nil
}

// End closes the decoder; leftover bytes or a missing header are an error.
func (d *Decoder) End() error {
	d.finished = true
	if d.failed || len(d.buffer) > 0 || (d.format == "pcap" && d.linktype < 0) || (d.format != "pcap" && d.sections == 0) {
		return fail("Incomplete or failed PCAP stream")
	}
	return nil
}

// ReadFile is read_pcap_records: it calls visit for each record in file order and stops at the first error
// (a framing error, an I/O error or one visit returns).
func ReadFile(path string, visit func(Record) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Read(f, visit)
}

// Read is ReadFile over an open stream, in the reference's 64 KiB chunks.
func Read(f io.Reader, visit func(Record) error) error {
	d := NewDecoder()
	chunk := make([]byte, maxChunk)
	for {
		n, rerr := io.ReadFull(f, chunk)
		if n > 0 {
			records, err := d.Feed(chunk[:n])
			if err != nil {
				return err
			}
			for _, r := range records {
				if err := visit(r); err != nil {
					return err
				}
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return d.End()
}
