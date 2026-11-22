package capture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func classic(records ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1}
	out = binary.LittleEndian.AppendUint16(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = append(out, make([]byte, 8)...)
	out = binary.LittleEndian.AppendUint32(out, 65535)
	out = binary.LittleEndian.AppendUint32(out, 1)
	for i, data := range records {
		out = binary.LittleEndian.AppendUint32(out, uint32(1700000000+i))
		out = binary.LittleEndian.AppendUint32(out, 250000)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(data)))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(data)+i)) // the second record is truncated by one byte
		out = append(out, data...)
	}
	return out
}

func block(kind uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	out := binary.LittleEndian.AppendUint32(nil, kind)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(body)+12))
	out = append(out, body...)
	return binary.LittleEndian.AppendUint32(out, uint32(len(body)+12))
}

func pcapng() []byte {
	section := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
	section = append(section, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	iface := []byte{1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 1, 0, 9, 0, 0, 0} // Ethernet, if_tsresol 10^-9
	packet := binary.LittleEndian.AppendUint32(nil, 0)
	packet = binary.LittleEndian.AppendUint32(packet, 0)
	packet = binary.LittleEndian.AppendUint32(packet, 1500000000) // 1.5 s in nanoseconds
	packet = binary.LittleEndian.AppendUint32(packet, 3)
	packet = binary.LittleEndian.AppendUint32(packet, 3)
	packet = append(packet, 'a', 'b', 'c')
	out := append(block(0x0A0D0D0A, section), block(1, iface)...)
	out = append(out, block(5, []byte{1, 2, 3, 4})...) // a statistics block is skipped
	return append(out, block(6, packet)...)
}

func read(t *testing.T, data []byte) ([]Record, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var records []Record
	err := ReadFile(path, func(r Record) error { records = append(records, r); return nil })
	return records, err
}

func TestClassicAndPcapngRecords(t *testing.T) {
	records, err := read(t, classic([]byte("first"), []byte("second")))
	if err != nil || len(records) != 2 || string(records[0].Data) != "first" || records[0].Timestamp != 1700000000.25 ||
		records[0].Truncated() || !records[1].Truncated() || records[1].Linktype != 1 {
		t.Fatalf("classic: %+v %v", records, err)
	}
	records, err = read(t, pcapng())
	if err != nil || len(records) != 1 || string(records[0].Data) != "abc" || records[0].Timestamp != 1.5 || records[0].OriginalLength != 3 {
		t.Fatalf("pcapng: %+v %v", records, err)
	}
}

func TestFramingErrorsCloseTheDecoder(t *testing.T) {
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"not a capture":      {[]byte("GET / HTTP/1.1\r\n\r\n      "), "Not a classic PCAP or pcapng capture"},
		"trailing bytes":     {append(classic([]byte("x")), 1, 2, 3), "Incomplete or failed PCAP stream"},
		"empty":              {nil, "Incomplete or failed PCAP stream"},
		"bad block trailer":  {append(pcapng()[:len(pcapng())-4], 0, 0, 0, 0), "pcapng block trailer disagrees with its header"},
		"packet before idb":  {append(pcapng()[:28], block(3, []byte{0, 0, 0, 0})...), "pcapng simple packet without an interface description"},
		"unknown link type":  {append(classic()[:20], 105, 0, 0, 0), "Unsupported capture link type: 105"},
		"record over length": {append(classic(), 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0), "Invalid PCAP record lengths or timestamp"},
	} {
		if _, err := read(t, c.data); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	d := NewDecoder()
	if _, err := d.Feed(make([]byte, 65537)); err == nil {
		t.Error("an oversized chunk was accepted")
	}
	d = NewDecoder()
	d.Feed([]byte("nope nope nope nope nope nope"))
	if _, err := d.Feed([]byte{0}); err == nil || err.Error() != "PCAP decoder is closed" {
		t.Errorf("a failed decoder accepted more input: %v", err)
	}
}

func FuzzDecoderNeverPanics(f *testing.F) {
	f.Add(classic([]byte("first"), []byte("second")), uint16(7))
	f.Add(pcapng(), uint16(3))
	f.Fuzz(func(t *testing.T, data []byte, step uint16) {
		d := NewDecoder()
		size := int(step)%4096 + 1
		for len(data) > 0 {
			n := min(size, len(data))
			if _, err := d.Feed(data[:n]); err != nil {
				return
			}
			data = data[n:]
		}
		d.End()
	})
}

// Codex PRO-16 (P2): the 32-bit packet lengths were narrowed to int before any check, so on a 32-bit build an
// original length of 0xFFFFFFFF became -1: a simple packet block with an empty body passed the length check and
// sliced body[4:3], and a large original length made a truncated record look complete. Run it with GOARCH=386
// as well as natively.
func TestThirtyTwoBitLengthsAreNotNarrowedBeforeTheirChecks(t *testing.T) {
	header := func(snaplen uint32) []byte {
		section := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
		section = append(section, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
		iface := binary.LittleEndian.AppendUint32([]byte{1, 0, 0, 0}, snaplen)
		return append(block(0x0A0D0D0A, section), block(1, iface)...)
	}
	huge := binary.LittleEndian.AppendUint32(nil, 0xFFFFFFFF)
	if _, err := read(t, append(header(0), block(3, huge)...)); err == nil || err.Error() != "pcapng simple packet length disagrees with its block" {
		t.Fatalf("empty simple packet claiming 4 GiB: %v", err)
	}
	records, err := read(t, append(header(4), block(3, append(huge, 'a', 'b', 'c', 'd'))...))
	if err != nil || len(records) != 1 || string(records[0].Data) != "abcd" || !records[0].Truncated() || records[0].OriginalLength <= 4 {
		t.Fatalf("simple packet cut to the snapshot length: %+v %v", records, err)
	}
	packet := make([]byte, 12)
	packet = binary.LittleEndian.AppendUint32(packet, 3)
	packet = append(packet, huge...)
	packet = append(packet, 'a', 'b', 'c')
	records, err = read(t, append(header(0), block(6, packet)...))
	if err != nil || len(records) != 1 || !records[0].Truncated() || records[0].OriginalLength <= 3 {
		t.Fatalf("enhanced packet with a 4 GiB original length: %+v %v", records, err)
	}
	classicHuge := append(classic()[:24], make([]byte, 8)...)
	classicHuge = binary.LittleEndian.AppendUint32(classicHuge, 1)
	classicHuge = append(classicHuge, huge...)
	classicHuge = append(classicHuge, 'z')
	records, err = read(t, classicHuge)
	if err != nil || len(records) != 1 || !records[0].Truncated() || records[0].OriginalLength <= 1 {
		t.Fatalf("classic record with a 4 GiB original length: %+v %v", records, err)
	}
}
