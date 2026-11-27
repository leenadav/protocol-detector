package capture

import (
	"encoding/binary"
	"testing"
)

// SR-10: classic PCAP framing with an invalid record length, snapshot size or timestamp fraction fails closed:
// the decoder refuses the input, drops what it buffered and stays closed; truncation at EOF is an error; one chunk is
// bounded; byte-wise input yields every record with its truncation metadata and leaves nothing buffered.
func TestSecurityPCAPFramingFailsClosedAndBoundsItsBuffer(t *testing.T) {
	valid := classic([]byte("first-record"), []byte("second"))
	for _, size := range []int{0, 10, 25, len(valid) - 1} {
		d := NewDecoder()
		if _, err := d.Feed(valid[:size]); err != nil {
			t.Fatalf("prefix %d: %v", size, err)
		}
		if err := d.End(); err == nil {
			t.Fatalf("EOF after %d of %d bytes accepted", size, len(valid))
		}
	}
	refuse := func(name string, data []byte) {
		t.Helper()
		d := NewDecoder()
		if records, err := d.Feed(data); err == nil {
			t.Fatalf("%s accepted (%d records)", name, len(records))
		}
		if len(d.buffer) != 0 {
			t.Fatalf("%s: %d bytes still buffered after the failure", name, len(d.buffer))
		}
		if _, err := d.Feed(nil); err == nil {
			t.Fatalf("%s: decoder usable after the failure", name)
		}
	}
	bad := append([]byte{}, valid[:40]...)
	binary.LittleEndian.PutUint32(bad[32:36], 0xffffffff) // included length beyond the snapshot length
	refuse("included length 2^32-1", bad)
	over := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(over[32:36], 65536) // one byte beyond the 65535 snapshot length
	binary.LittleEndian.PutUint32(over[36:40], 65536)
	refuse("included length beyond the snapshot", over)
	longer := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(longer[36:40], 3) // original shorter than included
	refuse("included longer than original", longer)
	fraction := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(fraction[28:32], 1000000) // microsecond fraction out of range
	refuse("timestamp fraction", fraction)
	for _, snaplen := range []uint32{0, maxSnaplen + 1} {
		header := append([]byte{}, valid...)
		binary.LittleEndian.PutUint32(header[16:20], snaplen)
		refuse("snapshot length", header)
	}
	chunk := append(append([]byte{}, valid[:24]...), make([]byte, maxChunk+1-24)...) // a header and empty records
	if _, err := NewDecoder().Feed(chunk); err == nil {
		t.Fatal("a chunk over 64 KiB accepted")
	}
	if _, err := NewDecoder().Feed(chunk[:maxChunk]); err != nil {
		t.Fatalf("a 64 KiB chunk refused: %v", err)
	}
	truncated := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(truncated[36:40], 999)
	d := NewDecoder()
	var records []Record
	for _, b := range truncated {
		got, err := d.Feed([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, got...)
	}
	if err := d.End(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || !records[0].Truncated() || records[0].OriginalLength != 999 || !records[1].Truncated() ||
		string(records[0].Data) != "first-record" || len(d.buffer) != 0 {
		t.Fatalf("byte-wise records %+v, %d bytes buffered", records, len(d.buffer))
	}
}
