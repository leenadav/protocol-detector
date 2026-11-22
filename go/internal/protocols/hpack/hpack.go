// Package hpack ports protocol_engine/hpack.py: RFC 7541 header block decoding, bounded for passive inspection.
// One Decoder per connection direction; Decode turns a complete header block into (name, value) pairs and never
// emits anything itself. Budgets: the field count, the encoded length of one string, the decoded header list size
// and the dynamic table size (which never grows past the maximum the decoder was created with). Every structural
// error is Malformed, every exceeded bound is Budget.
package hpack

import (
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Constants of hpack.py.
const (
	DefaultTableSize = 4096
	entryOverhead    = 32
	maxIntegerBytes  = 4
	eos              = 256
	staticCount      = 61
)

type step struct {
	next    uint8
	emitted []byte
	eos     bool
}

// huffman is the nibble-driven decoder (hpack._build_huffman): 256 states x 16 nibbles, and the depth of each
// state on the all-ones path (what valid padding may leave behind: fewer than 8 bits).
var huffman, huffmanOnes = buildHuffman()

func buildHuffman() ([]step, map[int]int) {
	type child struct {
		leaf  bool
		value int
		set   bool
	}
	children := [][2]child{{}}
	for symbol, code := range huffmanCodes {
		node := 0
		for shift := int(code[1]) - 1; shift >= 0; shift-- {
			bit := (code[0] >> uint(shift)) & 1
			if shift == 0 {
				children[node][bit] = child{true, symbol, true}
			} else {
				branch := children[node][bit]
				if !branch.set {
					children = append(children, [2]child{})
					branch = child{false, len(children) - 1, true}
					children[node][bit] = branch
				}
				node = branch.value
			}
		}
	}
	if len(children) != 256 {
		panic("hpack: Huffman code is not complete")
	}
	for _, pair := range children {
		if !pair[0].set || !pair[1].set {
			panic("hpack: Huffman code is not complete")
		}
	}
	table := make([]step, 256*16)
	for state := 0; state < 256; state++ {
		for nibble := 0; nibble < 16; nibble++ {
			node, out, hit := state, []byte(nil), false
			for shift := 3; shift >= 0; shift-- {
				c := children[node][(nibble>>uint(shift))&1]
				if c.leaf {
					if c.value == eos {
						hit = true
					} else {
						out = append(out, byte(c.value))
					}
					node = 0
				} else {
					node = c.value
				}
			}
			table[state<<4|nibble] = step{uint8(node), out, hit}
		}
	}
	ones, node, depth := map[int]int{}, 0, 0
	for {
		c := children[node][1]
		if c.leaf {
			break
		}
		depth++
		ones[c.value] = depth
		node = c.value
	}
	return table, ones
}

// decodeInteger is hpack.decode_integer (RFC 7541 5.1).
func decodeInteger(data []byte, pos int, prefixBits uint) (int, int, error) {
	mask := (1 << prefixBits) - 1
	value := int(data[pos]) & mask
	pos++
	if value < mask {
		return value, pos, nil
	}
	shift := uint(0)
	for {
		if pos >= len(data) {
			return 0, pos, parsing.Malformed("Truncated HPACK integer")
		}
		if shift >= 7*maxIntegerBytes {
			return 0, pos, parsing.Malformed("HPACK integer exceeds the decoder limit")
		}
		b := data[pos]
		pos++
		value += int(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return value, pos, nil
		}
	}
}

// HuffmanDecode is hpack.huffman_decode: canonical code, strict padding (fewer than 8 one bits), no EOS.
func HuffmanDecode(data []byte) ([]byte, error) {
	state := 0
	var out []byte
	for _, b := range data {
		for _, nibble := range [2]int{int(b >> 4), int(b & 15)} {
			s := huffman[state<<4|nibble]
			if s.eos {
				return nil, parsing.Malformed("HPACK Huffman string contains EOS")
			}
			out = append(out, s.emitted...)
			state = int(s.next)
		}
	}
	if state != 0 {
		depth, ok := huffmanOnes[state]
		if !ok || depth >= 8 {
			return nil, parsing.Malformed("Invalid HPACK Huffman padding")
		}
	}
	return out, nil
}

// Field is one decoded header field.
type Field struct{ Name, Value []byte }

// Decoder is the dynamic table plus budgets for one direction of one connection.
type Decoder struct {
	maxTableSize, tableSize int
	table                   []Field // newest entry first: index 62 is table[0]
	used                    int
	maxFields, maxString    int
	maxListSize             int
}

// NewDecoder mirrors hpack.Decoder(max_table_size, max_fields, max_string, max_list_size).
func NewDecoder(maxTableSize, maxFields, maxString, maxListSize int) *Decoder {
	return &Decoder{maxTableSize: maxTableSize, tableSize: maxTableSize, maxFields: maxFields, maxString: maxString, maxListSize: maxListSize}
}

func (d *Decoder) lookup(index int) (Field, error) {
	if index == 0 {
		return Field{}, parsing.Malformed("HPACK index zero")
	}
	if index <= staticCount {
		e := staticTable[index-1]
		return Field{[]byte(e[0]), []byte(e[1])}, nil
	}
	index -= staticCount + 1
	if index >= len(d.table) {
		return Field{}, parsing.Malformed("HPACK index beyond the dynamic table")
	}
	return d.table[index], nil
}

func (d *Decoder) str(data []byte, pos int) ([]byte, int, error) {
	if pos >= len(data) {
		return nil, pos, parsing.Malformed("Truncated HPACK string")
	}
	huffmanCoded := data[pos]&0x80 != 0
	length, pos, err := decodeInteger(data, pos, 7)
	if err != nil {
		return nil, pos, err
	}
	if length > d.maxString {
		return nil, pos, parsing.Budget("HPACK string exceeds the length budget")
	}
	end := pos + length
	if end > len(data) {
		return nil, pos, parsing.Malformed("Truncated HPACK string")
	}
	value := append([]byte{}, data[pos:end]...)
	if huffmanCoded {
		decoded, err := HuffmanDecode(value)
		if err != nil {
			return nil, end, err
		}
		if decoded == nil {
			decoded = []byte{}
		}
		return decoded, end, nil
	}
	return value, end, nil
}

func (d *Decoder) evict() {
	old := d.table[len(d.table)-1]
	d.table = d.table[:len(d.table)-1]
	d.used -= len(old.Name) + len(old.Value) + entryOverhead
}

func (d *Decoder) add(f Field) {
	size := len(f.Name) + len(f.Value) + entryOverhead
	if size > d.tableSize {
		d.table, d.used = nil, 0
		return
	}
	for d.used+size > d.tableSize {
		d.evict()
	}
	d.table = append([]Field{f}, d.table...)
	d.used += size
}

func (d *Decoder) resize(size int) error {
	if size > d.maxTableSize {
		return parsing.Malformed("HPACK dynamic table size update above the acknowledged maximum")
	}
	d.tableSize = size
	for d.used > size {
		d.evict()
	}
	return nil
}

// Decode decodes one complete header block.
func (d *Decoder) Decode(block []byte) ([]Field, error) {
	var fields []Field
	pos, total, updates := 0, 0, 0
	for pos < len(block) {
		b := block[pos]
		add := false
		var f Field
		var err error
		switch {
		case b&0x80 != 0:
			var index int
			if index, pos, err = decodeInteger(block, pos, 7); err != nil {
				return nil, err
			}
			if f, err = d.lookup(index); err != nil {
				return nil, err
			}
		case b&0x40 != 0:
			var index int
			if index, pos, err = decodeInteger(block, pos, 6); err != nil {
				return nil, err
			}
			if f, pos, err = d.literal(block, pos, index); err != nil {
				return nil, err
			}
			add = true
		case b&0x20 != 0:
			if len(fields) > 0 || updates >= 2 {
				return nil, parsing.Malformed("HPACK dynamic table size update must begin the header block")
			}
			var size int
			if size, pos, err = decodeInteger(block, pos, 5); err != nil {
				return nil, err
			}
			if err := d.resize(size); err != nil {
				return nil, err
			}
			updates++
			continue
		default:
			var index int
			if index, pos, err = decodeInteger(block, pos, 4); err != nil {
				return nil, err
			}
			if f, pos, err = d.literal(block, pos, index); err != nil {
				return nil, err
			}
		}
		total += len(f.Name) + len(f.Value) + entryOverhead
		if total > d.maxListSize {
			return nil, parsing.Budget("HPACK header list exceeds the size budget")
		}
		if len(fields) >= d.maxFields {
			return nil, parsing.Budget("HPACK header field count exceeds budget")
		}
		fields = append(fields, f)
		if add {
			d.add(f)
		}
	}
	return fields, nil
}

func (d *Decoder) literal(block []byte, pos, index int) (Field, int, error) {
	var name []byte
	var err error
	if index != 0 {
		var f Field
		if f, err = d.lookup(index); err != nil {
			return Field{}, pos, err
		}
		name = f.Name
	} else {
		if name, pos, err = d.str(block, pos); err != nil {
			return Field{}, pos, err
		}
		if len(name) == 0 {
			return Field{}, pos, parsing.Malformed("Empty HPACK header name")
		}
	}
	value, pos, err := d.str(block, pos)
	if err != nil {
		return Field{}, pos, err
	}
	return Field{name, value}, pos, nil
}
