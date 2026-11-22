package textroute

import (
	"strings"
	"testing"
)

// SEC-SSH-1 (Codex PRO-15): a KEXINIT name-list length of 0xffffffff must be Malformed on every architecture.
// On 32-bit Go, int(0xffffffff) was -1, both bound checks passed and packet[pos:pos-1] panicked.
func TestKexInitNameListLengthAllOnesIsMalformed(t *testing.T) {
	packet := []byte{4, 20}
	packet = append(packet, make([]byte, 16)...)    // cookie
	packet = append(packet, 0xff, 0xff, 0xff, 0xff) // first name-list length
	packet = append(packet, 0, 0, 0, 0)             // padding
	err := newKexInit(1 << 16).validate(packet)
	if err == nil || !strings.Contains(err.Error(), "SSH KEXINIT name-list exceeds packet or profile") {
		t.Fatalf("validate err=%v, want the name-list bound error", err)
	}
}
