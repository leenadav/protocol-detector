package framed

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// smb2Negotiate builds a direct-TCP SMB2 NEGOTIATE request offering dialect 0x302.
func smb2NegotiateRequest() []byte {
	m := make([]byte, 102)
	copy(m, "\xfeSMB")
	binary.LittleEndian.PutUint16(m[4:], 64)
	binary.LittleEndian.PutUint16(m[64:], 36)
	binary.LittleEndian.PutUint16(m[66:], 1)
	binary.LittleEndian.PutUint16(m[68:], 1)
	binary.LittleEndian.PutUint16(m[100:], 0x302)
	return append([]byte{0, 0, 0, byte(len(m))}, m...)
}

// smb2SessionRequest builds a SESSION_SETUP request carrying token.
func smb2SessionRequest(token []byte) []byte {
	m := make([]byte, 88)
	copy(m, "\xfeSMB")
	binary.LittleEndian.PutUint16(m[4:], 64)
	binary.LittleEndian.PutUint16(m[12:], 1)
	binary.LittleEndian.PutUint16(m[64:], 25)
	m[67] = 1
	binary.LittleEndian.PutUint16(m[76:], 88)
	binary.LittleEndian.PutUint16(m[78:], uint16(len(token)))
	m = append(m, token...)
	return append([]byte{0, byte(len(m) >> 16), byte(len(m) >> 8), byte(len(m))}, m...)
}

func feedSMB(t *testing.T, p parsing.Parser, data []byte) error {
	t.Helper()
	for len(data) > 0 {
		n, err := p.Feed(data)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		data = data[n:]
	}
	return nil
}

func extra(r *parsing.Result) map[string]string {
	out := map[string]string{}
	for _, e := range r.Extra {
		out[e.Field] = e.Value
	}
	return out
}

func TestLittleEndianReadsShortSlicesLikePython(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	for _, tc := range []struct{ at, n, want int }{{0, 2, 0x0201}, {1, 2, 0x0302}, {2, 2, 0x03}, {3, 2, 0}, {9, 4, 0}, {1, 4, 0x0302}} {
		if got := le(data, tc.at, tc.n); got != tc.want {
			t.Errorf("le(%d,%d) = %#x want %#x", tc.at, tc.n, got, tc.want)
		}
	}
}

// NEGOTIATE identifies; the next SESSION_SETUP refines with closed labels from the token and nothing else.
func TestSMB2SessionSetupRefinesWithClosedLabels(t *testing.T) {
	p := NewSMB2(65536)
	token := spnegoInit([][]byte{testOIDNTLMSSP}, ntlmssp(1, 40))
	if err := feedSMB(t, p, smb2NegotiateRequest()); err != nil || !p.Done() {
		t.Fatalf("negotiate: %v", err)
	}
	r := p.Result()
	if !r.Continues || extra(r)["smb_signing"] != "enabled" || p.(interface{ Refined() bool }).Refined() {
		t.Fatalf("after negotiate: %+v", r)
	}
	if err := feedSMB(t, p, smb2SessionRequest(token)); err != nil {
		t.Fatal(err)
	}
	r = p.Result()
	got := extra(r)
	if r.Continues || got["smb_message"] != "session-setup-request" || got["gss_mechanism"] != "ntlm" || got["ntlm_message"] != "negotiate" {
		t.Fatalf("after session setup: %+v", r)
	}
	if !strings.HasSuffix(r.Reason, "credentials and tokens not emitted") {
		t.Fatalf("reason %q", r.Reason)
	}
}

// A frame of another family after NEGOTIATE ends the watch without consuming it; a malformed SESSION_SETUP is an
// error the inspector turns into "identification stands, nothing refined".
func TestSMB2WatchEndsOnForeignOrBadFrames(t *testing.T) {
	p := NewSMB2(65536)
	feedSMB(t, p, smb2NegotiateRequest())
	n, err := p.Feed([]byte("GET / HTTP/1.1\r\n"))
	if err != nil || n != 0 || p.Result().Continues {
		t.Fatalf("foreign frame: n=%d err=%v continues=%v", n, err, p.Result().Continues)
	}
	p = NewSMB2(65536)
	feedSMB(t, p, smb2NegotiateRequest())
	if err := feedSMB(t, p, smb2SessionRequest([]byte{0x30, 0})); err == nil {
		t.Fatal("bad token accepted")
	}
	p = NewSMB2(200)
	feedSMB(t, p, smb2NegotiateRequest())
	big := smb2SessionRequest(make([]byte, 300))
	if err := feedSMB(t, p, big); err == nil || !strings.Contains(err.Error(), "exceeds byte budget") {
		t.Fatalf("budget: %v", err)
	}
}
