package ascii

import "testing"

func TestOnlyASCIILettersChange(t *testing.T) {
	if Upper("ſtarttls") == "STARTTLS" || Lower("K") == "k" {
		t.Fatal("non-ASCII runes were case-mapped")
	}
	if Upper("StartTLS-1") != "STARTTLS-1" || Lower("ÀB") != "Àb" || string(LowerBytes([]byte{0xc3, 0x80, 'Q'})) != "\xc3\x80q" {
		t.Fatal("ASCII mapping")
	}
}
