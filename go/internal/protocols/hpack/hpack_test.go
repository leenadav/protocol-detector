package hpack

import (
	"encoding/hex"
	"strings"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func render(fields []Field) string {
	var parts []string
	for _, f := range fields {
		parts = append(parts, string(f.Name)+"="+string(f.Value))
	}
	return strings.Join(parts, " ")
}

// RFC 7541 C.4: three requests with Huffman coding on one connection exercise the dynamic table.
func TestRFC7541RequestsWithHuffman(t *testing.T) {
	d := NewDecoder(DefaultTableSize, 128, 8192, 16384)
	steps := []struct{ block, want string }{
		{"8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff", ":method=GET :scheme=http :path=/ :authority=www.example.com"},
		{"8286 84be 5886 a8eb 1064 9cbf", ":method=GET :scheme=http :path=/ :authority=www.example.com cache-control=no-cache"},
		{"8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf", ":method=GET :scheme=https :path=/index.html :authority=www.example.com custom-key=custom-value"},
	}
	for i, s := range steps {
		fields, err := d.Decode(decodeHex(t, s.block))
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		if got := render(fields); got != s.want {
			t.Fatalf("request %d: %s", i+1, got)
		}
	}
	if len(d.table) != 3 || d.used != 164 {
		t.Fatalf("dynamic table after C.4.3: %d entries, %d octets", len(d.table), d.used)
	}
}

// RFC 7541 C.5: responses with a 256-octet table force evictions.
func TestRFC7541ResponsesEvict(t *testing.T) {
	d := NewDecoder(256, 128, 8192, 16384)
	blocks := []string{
		"4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
		"4803 3330 37c1 c0bf",
	}
	for _, b := range blocks {
		if _, err := d.Decode(decodeHex(t, b)); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.table) != 4 || d.used != 222 || string(d.table[0].Value) != "307" {
		t.Fatalf("table after C.5.2: %d entries, %d octets", len(d.table), d.used)
	}
}

func TestDecoderErrorsAndBudgets(t *testing.T) {
	cases := []struct {
		block  string
		budget bool
	}{
		{"80", false},                   // index zero
		{"be", false},                   // index beyond the dynamic table
		{"ff ff ff ff ff 0f", false},    // integer over the decoder limit
		{"ff", false},                   // truncated integer
		{"40 00 00", false},             // empty literal name
		{"82 20", false},                // size update after a field
		{"3f e2 1f", false},             // size update above the maximum (4097)
		{"41 85 ff ff ff ff ff", false}, // Huffman string holding EOS
		{"41 81 fe", false},             // padding longer than 7 bits... ends inside a symbol
		{"00 01 61 20 " + strings.Repeat("61", 32), true}, // a 32-byte value over the 16-byte string budget
	}
	for i, c := range cases {
		d := NewDecoder(DefaultTableSize, 4, 16, 16384)
		_, err := d.Decode(decodeHex(t, c.block))
		if err == nil {
			t.Fatalf("case %d accepted", i)
		}
		if strings.Contains(err.Error(), "budget") != c.budget {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if _, err := NewDecoder(DefaultTableSize, 2, 8192, 16384).Decode(decodeHex(t, "82 86 84")); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("field count budget: %v", err)
	}
}

func TestHuffmanPaddingIsStrict(t *testing.T) {
	// "a" is 00011 (5 bits): padding 111 is valid; 0-padding and an extra all-ones byte are not.
	if out, err := HuffmanDecode([]byte{0x1f}); err != nil || string(out) != "a" {
		t.Fatalf("valid padding: %q %v", out, err)
	}
	if _, err := HuffmanDecode([]byte{0x18}); err == nil {
		t.Fatal("zero padding accepted")
	}
	if _, err := HuffmanDecode([]byte{0x1f, 0xff}); err == nil {
		t.Fatal("padding of 8 or more bits accepted")
	}
}

func FuzzDecoderStaysBounded(f *testing.F) {
	f.Add(decodeHexF("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
	f.Add(decodeHexF("4803333032"))
	f.Fuzz(func(t *testing.T, block []byte) {
		d := NewDecoder(DefaultTableSize, 32, 256, 4096)
		fields, err := d.Decode(block)
		if err == nil && len(fields) > 32 {
			t.Fatalf("%d fields over the budget", len(fields))
		}
		if d.used > DefaultTableSize {
			t.Fatalf("dynamic table %d octets", d.used)
		}
	})
}

func decodeHexF(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
