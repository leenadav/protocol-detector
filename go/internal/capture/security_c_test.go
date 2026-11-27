package capture

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// scSection is a little-endian pcapng section header block.
func scSection() []byte {
	section := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
	section = append(section, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	return block(0x0A0D0D0A, section)
}

// scInterface is an Ethernet interface description block with the snapshot length and raw options.
func scInterface(snaplen uint32, options []byte) []byte {
	body := []byte{1, 0, 0, 0}
	body = binary.LittleEndian.AppendUint32(body, snaplen)
	return block(1, append(body, options...))
}

// scPacket is an enhanced packet block on the interface with the given lengths and data.
func scPacket(iface, captured, original uint32, data []byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, iface)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, captured)
	body = binary.LittleEndian.AppendUint32(body, original)
	return block(6, append(body, data...))
}

func scJoin(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func scFeed(data []byte, cuts []int) ([]Record, error) {
	d := NewDecoder()
	var records []Record
	start := 0
	for _, cut := range append(cuts, len(data)) {
		got, err := d.Feed(data[start:cut])
		if err != nil {
			return records, err
		}
		records = append(records, got...)
		start = cut
	}
	return records, d.End()
}

// SR-33: every pcapng block is bounded and validated before its contents are read: block length (minimum,
// four-byte alignment, maximum), trailer, the interface it references, the interface count, the option layout and
// count, and the snapshot length; each failure is a typed framing error that closes the decoder.
func TestPcapngBlocksAreBoundedAndValidatedBeforeTheyAreRead(t *testing.T) {
	header := scJoin(scSection(), scInterface(0, nil))
	misaligned := binary.LittleEndian.AppendUint32(nil, 6)
	misaligned = binary.LittleEndian.AppendUint32(misaligned, 22)
	misaligned = append(misaligned, make([]byte, 14)...)
	huge := binary.LittleEndian.AppendUint32(nil, 6)
	huge = binary.LittleEndian.AppendUint32(huge, 0x7ffffff0)
	huge = append(huge, 0, 0, 0, 0)
	var manyOptions []byte
	for i := 0; i < 257; i++ {
		manyOptions = append(manyOptions, 2, 0, 0, 0) // if_name, empty
	}
	overlong := []byte{2, 0, 40, 0, 'x', 'y', 0, 0} // if_name claiming 40 bytes in a 4-byte remainder
	var interfaces [][]byte
	for i := 0; i < 257; i++ {
		interfaces = append(interfaces, scInterface(0, nil))
	}
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"misaligned block":      {scJoin(header, misaligned), "Invalid pcapng block length"},
		"short block":           {scJoin(header, []byte{6, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0}), "Invalid pcapng block length"},
		"oversized block":       {scJoin(header, huge), "Invalid pcapng block length"},
		"undefined interface":   {scJoin(header, scPacket(1, 3, 3, []byte("abc"))), "pcapng packet references an undefined interface"},
		"captured over snaplen": {scJoin(scSection(), scInterface(2, nil), scPacket(0, 3, 3, []byte("abc"))), "Invalid pcapng packet lengths"},
		"captured over orig":    {scJoin(header, scPacket(0, 3, 2, []byte("abc"))), "Invalid pcapng packet lengths"},
		"data beyond block":     {scJoin(header, scPacket(0, 64, 64, []byte("abc"))), "pcapng packet data exceeds its block"},
		"snapshot over 1 MiB":   {scJoin(scSection(), scInterface(maxSnaplen+1, nil)), "pcapng snapshot length exceeds 1 MiB"},
		"option over block":     {scJoin(scSection(), scInterface(0, overlong)), "pcapng option exceeds its block"},
		"too many options":      {scJoin(scSection(), scInterface(0, manyOptions)), "pcapng option count exceeds profile"},
		"too many interfaces":   {scJoin(scSection(), scJoin(interfaces...)), "pcapng interface count exceeds profile"},
	} {
		if _, err := read(t, c.data); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// SR-33: a truncated capture fails closed at its end, and every split point and byte-wise feeding of a valid
// capture gives the records of the whole capture. Ported from test_pcapng.py
// test_every_split_point_and_bytewise_feeding and test_malformed_pcapng_is_rejected_and_bounded.
func TestPcapngEverySplitPointAndTruncationFailsClosed(t *testing.T) {
	data := scJoin(pcapng(), scPacket(0, 5, 9, []byte("hello")))
	whole, err := scFeed(data, nil)
	if err != nil || len(whole) != 2 || string(whole[1].Data) != "hello" || !whole[1].Truncated() {
		t.Fatalf("whole: %+v %v", whole, err)
	}
	boundary := map[int]bool{}
	for pos := 0; pos < len(data); pos += int(binary.LittleEndian.Uint32(data[pos+4:])) {
		boundary[pos] = true
	}
	bytewise := make([]int, 0, len(data))
	for i := 1; i < len(data); i++ {
		bytewise = append(bytewise, i)
		got, err := scFeed(data, []int{i})
		if err != nil || !reflect.DeepEqual(got, whole) {
			t.Fatalf("split at %d: %+v %v", i, got, err)
		}
		if _, err := scFeed(data[:i], nil); err == nil && !boundary[i] {
			t.Fatalf("a capture truncated inside a block at %d bytes ended cleanly", i)
		}
	}
	if got, err := scFeed(data, bytewise); err != nil || !reflect.DeepEqual(got, whole) {
		t.Fatalf("byte-wise: %+v %v", got, err)
	}
}
