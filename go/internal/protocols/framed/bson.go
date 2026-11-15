package framed

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// bson ports bson.BSONValidator: bounded wire validation without building documents or running code.
// Field and document counters are shared by every document of one message.
type bson struct {
	data                  []byte
	fieldLimit, nameLimit int
	fields, documents     int
}

// bsonValue is a collected top-level element: its type and the value's byte range.
type bsonValue struct{ kind, start, end int }

// bsonFields keeps collected elements in wire order (Python dicts preserve insertion order).
type bsonFields struct {
	order  []string
	values map[string]bsonValue
}

var bsonFixed = map[byte]int{1: 8, 6: 0, 7: 12, 9: 8, 10: 0, 16: 4, 17: 8, 18: 8, 19: 16, 127: 0, 255: 0}

func newBSON(data []byte, maxHeaders, maxLine int) *bson {
	v := &bson{data: data, fieldLimit: maxHeaders, nameLimit: maxLine}
	if v.fieldLimit > 128 {
		v.fieldLimit = 128
	}
	if v.nameLimit > 1024 {
		v.nameLimit = 1024
	}
	return v
}

func bsonI32(data []byte, pos, limit int) (int, error) {
	if pos+4 > limit {
		return 0, parsing.Malformed("Truncated BSON integer")
	}
	return int(int32(binary.LittleEndian.Uint32(data[pos : pos+4]))), nil
}

func (v *bson) cstring(pos, limit int) (string, int, error) {
	end := find(v.data, 0, pos, limit)
	if end < 0 {
		return "", 0, parsing.Malformed("Unterminated BSON cstring")
	}
	if end-pos > v.nameLimit {
		return "", 0, parsing.Budget("BSON cstring exceeds name budget")
	}
	if !utf8.Valid(v.data[pos:end]) {
		return "", 0, parsing.Malformed("Invalid BSON UTF-8")
	}
	return string(v.data[pos:end]), end + 1, nil
}

func (v *bson) stringEnd(pos, limit int) (int, error) {
	size, err := bsonI32(v.data, pos, limit)
	if err != nil {
		return 0, err
	}
	end := pos + 4 + size
	if size < 1 || end > limit || v.data[end-1] != 0 {
		return 0, parsing.Malformed("Invalid BSON string length or terminator")
	}
	if !utf8.Valid(v.data[pos+4 : end-1]) {
		return 0, parsing.Malformed("Invalid BSON UTF-8")
	}
	return end, nil
}

func regexOptions(options string) bool {
	previous := byte(0)
	for i := 0; i < len(options); i++ {
		c := options[i]
		if bytes.IndexByte([]byte("imsux"), c) < 0 || c <= previous {
			return false
		}
		previous = c
	}
	return true
}

func (v *bson) document(start, limit, depth int, array, collect bool) (int, *bsonFields, error) {
	if depth > 16 {
		return 0, nil, parsing.Budget("BSON nesting exceeds 16 levels")
	}
	v.documents++
	if v.documents > 128 {
		return 0, nil, parsing.Budget("BSON document count exceeds 128")
	}
	size, err := bsonI32(v.data, start, limit)
	if err != nil {
		return 0, nil, err
	}
	end := start + size
	if size < 5 || end > limit || v.data[end-1] != 0 {
		return 0, nil, parsing.Malformed("Invalid BSON document length or terminator")
	}
	pos, index := start+4, 0
	names := map[string]bool{}
	var metadata *bsonFields
	if collect {
		metadata = &bsonFields{values: map[string]bsonValue{}}
	}
	for pos < end-1 {
		kind := v.data[pos]
		name, next, err := v.cstring(pos+1, end-1)
		if err != nil {
			return 0, nil, err
		}
		pos = next
		v.fields++
		if v.fields > v.fieldLimit {
			return 0, nil, parsing.Budget("BSON element count exceeds field budget")
		}
		if array {
			if name != strconv.Itoa(index) {
				return 0, nil, parsing.Malformed("BSON array keys must be consecutive decimal indices")
			}
		} else if names[name] {
			return 0, nil, parsing.Malformed("Duplicate BSON field name outside supported profile")
		}
		names[name] = true
		index++
		valueStart := pos
		if fixed, ok := bsonFixed[kind]; ok {
			pos += fixed
		} else {
			switch kind {
			case 8:
				if pos >= end-1 || v.data[pos] > 1 {
					return 0, nil, parsing.Malformed("Invalid BSON boolean")
				}
				pos++
			case 2, 12, 13, 14:
				if pos, err = v.stringEnd(pos, end-1); err != nil {
					return 0, nil, err
				}
				if kind == 12 {
					pos += 12
				}
			case 3, 4:
				if pos, _, err = v.document(pos, end-1, depth+1, kind == 4, false); err != nil {
					return 0, nil, err
				}
			case 5:
				size, err := bsonI32(v.data, pos, end-1)
				if err != nil {
					return 0, nil, err
				}
				if size < 0 || pos+5+size > end-1 {
					return 0, nil, parsing.Malformed("Invalid BSON binary length")
				}
				subtype := v.data[pos+4]
				if subtype >= 10 && subtype < 128 {
					return 0, nil, parsing.Malformed("Undefined BSON binary subtype")
				}
				if subtype == 2 {
					inner := -1
					if size >= 4 {
						if inner, err = bsonI32(v.data, pos+5, end-1); err != nil {
							return 0, nil, err
						}
					}
					if size < 4 || inner != size-4 {
						return 0, nil, parsing.Malformed("Legacy BSON binary lengths disagree")
					}
				}
				if (subtype == 3 || subtype == 4 || subtype == 5) && size != 16 {
					return 0, nil, parsing.Malformed("Invalid BSON UUID/MD5 width")
				}
				pos += 5 + size
			case 11:
				if _, pos, err = v.cstring(pos, end-1); err != nil {
					return 0, nil, err
				}
				var options string
				if options, pos, err = v.cstring(pos, end-1); err != nil {
					return 0, nil, err
				}
				if !regexOptions(options) {
					return 0, nil, parsing.Malformed("Invalid BSON regular-expression options")
				}
			case 15:
				size, err := bsonI32(v.data, pos, end-1)
				if err != nil {
					return 0, nil, err
				}
				scopeEnd := pos + size
				if size < 14 || scopeEnd > end-1 {
					return 0, nil, parsing.Malformed("Invalid BSON code-with-scope length")
				}
				codeEnd, err := v.stringEnd(pos+4, scopeEnd)
				if err != nil {
					return 0, nil, err
				}
				if pos, _, err = v.document(codeEnd, scopeEnd, depth+1, false, false); err != nil {
					return 0, nil, err
				}
				if pos != scopeEnd {
					return 0, nil, parsing.Malformed("BSON scope length mismatch")
				}
			default:
				return 0, nil, parsing.Malformed("Unknown BSON element type")
			}
		}
		if pos > end-1 {
			return 0, nil, parsing.Malformed("BSON value exceeds enclosing document")
		}
		if metadata != nil {
			if _, seen := metadata.values[name]; !seen {
				metadata.order = append(metadata.order, name)
			}
			metadata.values[name] = bsonValue{int(kind), valueStart, pos}
		}
	}
	if pos != end-1 {
		return 0, nil, parsing.Malformed("BSON document framing mismatch")
	}
	return end, metadata, nil
}
