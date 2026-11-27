package tlsx_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

// scHello is a TLS 1.2 ClientHello record offering the given suites, without extensions.
func scHello(suites ...uint16) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, byte(2*len(suites)>>8), byte(2*len(suites)))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}
	body = append(body, 1, 0, 0, 0)
	return record(append(append([]byte{1}, scU24(len(body))...), body...))
}

// scWeak returns the tls_weak_cipher_offered values of the parser's result, in order, and the rendering.
func scWeak(t *testing.T, data []byte, step int) ([]string, string) {
	t.Helper()
	p, err := tlsx.New(tlsx.Options{MaxBytes: 65536, MaxHeaders: 128})
	if err != nil {
		t.Fatal(err)
	}
	rendering := parsertest.Drive(p, data, step)
	if !strings.Contains(rendering, `error="" done=true`) {
		t.Fatalf("ClientHello not identified: %s", rendering)
	}
	var out []string
	for _, r := range p.Result().Extra {
		if r.Field == "tls_weak_cipher_offered" {
			if r.Strength != "offered" || r.Provenance != "client_hello" {
				t.Fatalf("weak-cipher row %+v", r)
			}
			out = append(out, r.Value)
		}
	}
	return out, rendering
}

// SR-62: weak cipher-suite classes come from a validated ClientHello cipher vector through the fixed RFC 9325
// table (102 suites, one class each, classes reported in the fixed rule order, never the suite numbers), and the
// ClientHello identification is the same with or without weak suites, in any split.
func TestWeakCipherClassesFollowTheTableAndNeverChangeTheIdentification(t *testing.T) {
	expected := map[uint16]string{0x0000: "null", 0x0003: "export", 0x0018: "anon", 0x0004: "rc4", 0x0009: "des", 0x000a: "64-bit-block",
		0x0007: "64-bit-block", 0xc0b4: "null"}
	for code, label := range expected {
		if got, _ := scWeak(t, scHello(0x002f, code), 0); len(got) != 1 || got[0] != label {
			t.Fatalf("suite %#04x: %v, want %s", code, got, label)
		}
	}
	for _, code := range []uint16{0x002f, 0x0035, 0xc02f, 0xc030, 0x1301, 0x1302, 0x1303, 0x00ff, 0x5600, 0x0a0a, 0xfafa} {
		if got, _ := scWeak(t, scHello(code), 0); len(got) != 0 {
			t.Fatalf("suite %#04x classified %v", code, got)
		}
	}
	weak := 0
	for code := 0; code < 1<<16; code++ {
		if got, _ := scWeak(t, scHello(uint16(code)), 0); len(got) > 0 {
			weak++
		}
	}
	if weak != 102 {
		t.Fatalf("%d suites are classified weak, the derived table has 102", weak)
	}
	all := scHello(0x000a, 0x0009, 0x0004, 0x0018, 0x0003, 0x0000, 0x1301)
	got, rendering := scWeak(t, all, 0)
	if strings.Join(got, ",") != "null,export,anon,rc4,des,64-bit-block" {
		t.Fatalf("class order %v", got)
	}
	for _, number := range []string{"0x000a", "0x0009", "0x0004", "0x0018", "0x0003", "0x0000", "000a", "0018"} {
		if strings.Contains(strings.ToLower(rendering), number) {
			t.Fatalf("a suite number is emitted: %s", rendering)
		}
	}
	strip := func(r string) string {
		i := strings.Index(r, " extra=")
		j := strings.Index(r, " reason=")
		return r[:i] + r[j:]
	}
	_, strong := scWeak(t, scHello(0x1301, 0x1301, 0x1301, 0x1301, 0x1301, 0x1301, 0x1301), 0)
	if strip(rendering) != strip(strong) {
		t.Fatalf("weak suites changed the identification:\n%s\n%s", rendering, strong)
	}
	for step := 1; step < len(all); step++ {
		if again, r := scWeak(t, all, step); fmt.Sprint(again) != fmt.Sprint(got) || r != rendering {
			t.Fatalf("step %d: %s", step, r)
		}
	}
}

func scU24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

// SR-38: the certificate watch that follows a TLS 1.2 ServerHello shares the parser's max_bytes budget: fed a
// flight larger than the budget in one call or byte by byte, the parser never consumes more than max_bytes, and
// the watch ends with an error (the inspector keeps the ServerHello identification) rather than reading on.
func TestCertificateWatchNeverConsumesPastTheByteBudget(t *testing.T) {
	leaf := append([]byte{0x30, 0x82, 0x07, 0xcc}, make([]byte, 0x7cc)...) // a 2000-byte DER SEQUENCE
	list := append(scU24(len(leaf)), leaf...)
	body := append(scU24(len(list)), list...)
	message := append(append([]byte{11}, scU24(len(body))...), body...)
	hello := serverHello(0xc02f, ext(0xff01, 0))
	flight := append(append([]byte{}, hello...), record(message)...)
	for _, budget := range []int{len(hello) + 3, len(hello) + 5, len(hello) + 12, len(hello) + 15, len(hello) + 600, len(flight) - 1} {
		for _, step := range []int{len(flight), 1, 7} {
			p, err := tlsx.New(tlsx.Options{MaxBytes: budget, MaxHeaders: 128, Certificates: true})
			if err != nil {
				t.Fatal(err)
			}
			consumed, failed := 0, false
			for pos := 0; pos < len(flight) && !failed; {
				end := pos + step
				if end > len(flight) {
					end = len(flight)
				}
				for chunk := flight[pos:end]; len(chunk) > 0; {
					n, err := p.Feed(chunk)
					consumed += n
					chunk = chunk[n:]
					if err != nil {
						failed = true
						break
					}
					if n == 0 {
						break
					}
				}
				pos = end
			}
			if consumed > budget {
				t.Fatalf("budget %d, step %d: consumed %d bytes", budget, step, consumed)
			}
			if !failed {
				t.Fatalf("budget %d, step %d: the watch ended without an error after %d bytes", budget, step, consumed)
			}
			if r := p.Result(); r == nil || r.Scope != "server_hello" {
				t.Fatalf("budget %d, step %d: the ServerHello result is gone: %+v", budget, step, r)
			}
		}
	}
}
