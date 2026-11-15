package framed

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

func rdpRequest(offered byte, flags byte) []byte {
	neg := []byte{1, flags, 8, 0, offered, 0, 0, 0}
	x224 := append([]byte{byte(6 + len(neg)), 0xe0, 0, 0, 0, 0, 0}, neg...)
	return append([]byte{3, 0, 0, byte(4 + len(x224))}, x224...)
}

func runFramed(t *testing.T, p *Parser, data []byte) (*parsing.Result, error) {
	t.Helper()
	if _, err := p.Feed(data); err != nil {
		return nil, err
	}
	if !p.Done() {
		t.Fatal("not done")
	}
	return p.Result(), nil
}

// The automatic route resolves the family from the bytes after the X.224 header, and offers shift to TLS.
func TestTPKTRouteResolvesRDPAndISOTSAP(t *testing.T) {
	r, err := runFramed(t, NewTPKT(65536), rdpRequest(3, 1))
	if err != nil || r.Family != "rdp" || r.Shift == nil || r.Shift.Expected != "tls" {
		t.Fatalf("rdp: %+v %v", r, err)
	}
	want := map[string]bool{"rdp_security_flags=3": true, "rdp_offered_security=tls": true, "rdp_offered_security=credssp": true,
		"rdp_credential_mode=restricted-admin": true}
	for _, e := range r.Extra {
		delete(want, e.Field+"="+e.Value)
	}
	if len(want) != 0 {
		t.Fatalf("missing rows %v in %+v", want, r.Extra)
	}
	tsap := []byte{3, 0, 0, 0x16, 0x11, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 0x0a, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2}
	if r, err = runFramed(t, NewTPKT(65536), tsap); err != nil || r.Family != "iso-tsap" || r.Shift.Expected != "s7comm" {
		t.Fatalf("iso-tsap: %+v %v", r, err)
	}
	// Standard RDP security announces no TLS phase.
	if r, err = runFramed(t, NewTPKT(65536), rdpRequest(0, 0)); err != nil || r.Shift != nil {
		t.Fatalf("standard rdp: %+v %v", r, err)
	}
}

// The explicit rdp hint frames with RDP's own 11..260 bound; the automatic route allows up to 1024.
func TestRDPHintKeepsItsOwnLengthBound(t *testing.T) {
	long := append([]byte{3, 0, 0x01, 0x10}, make([]byte, 0x110-4)...)
	if _, err := NewRDP(65536).Feed(long[:4]); err == nil {
		t.Fatal("rdp hint accepted a 272-byte TPKT length")
	}
	if _, err := NewTPKT(65536).Feed(long[:4]); err != nil {
		t.Fatalf("automatic route refused a 272-byte TPKT length: %v", err)
	}
}
