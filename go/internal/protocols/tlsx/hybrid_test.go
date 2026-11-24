package tlsx_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
)

// PRO-260 (Lee, 2026-11-23: Go only; the Python reference stays frozen and the difference is an approved parity
// exception, migration/STATUS.md). The post-quantum hybrid key-exchange groups that current TLS stacks negotiate
// by default, from the IANA TLS Supported Groups registry (draft-ietf-tls-ecdhe-mlkem):
//
//	0x11EB SecP256r1MLKEM768   client share 65+1184, server share 65+1088 (uncompressed P-256 point first)
//	0x11EC X25519MLKEM768      client share 1184+32, server share 1088+32 (ML-KEM first; no fixed first byte)
//	0x11ED SecP384r1MLKEM1024  client share 97+1568, server share 97+1568 (uncompressed P-384 point first)
//
// The ServerHello key_share must have the exact server-share length; the NIST-curve hybrids must start with an
// uncompressed point. The exchange class is "hybrid", which carries no forward-secrecy risk.
var hybrids = []struct {
	name       string
	group      int
	server     int // server share: classical share + ML-KEM ciphertext
	client     int // client share: classical share + ML-KEM encapsulation key
	pointFirst bool
}{
	{"SecP256r1MLKEM768", 0x11eb, 65 + 1088, 65 + 1184, true},
	{"X25519MLKEM768", 0x11ec, 1088 + 32, 1184 + 32, false},
	{"SecP384r1MLKEM1024", 0x11ed, 97 + 1568, 97 + 1568, true},
}

func hybridShare(group, size int, first byte) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i*7 + 1) // not all zero: the parser must not depend on the key bytes
	}
	if size > 0 {
		key[0] = first
	}
	return ext(51, append([]byte{byte(group >> 8), byte(group), byte(size >> 8), byte(size)}, key...)...)
}

func hrrHello(extensions []byte) []byte {
	// The HelloRetryRequest random (RFC 8446 4.1.3).
	random := []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	body := append([]byte{3, 3}, random...)
	body = append(body, 0, 0x13, 0x01, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return record(append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

func driveAll(t *testing.T, name string, data []byte, wants ...string) {
	t.Helper()
	got := parsertest.Drive(fresh(t), data, 0)
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("%s: want %s in %s", name, want, got)
		}
	}
	for _, step := range []int{1, 7} {
		if split := parsertest.Drive(fresh(t), data, step); split != got {
			t.Errorf("%s: %d-byte pieces differ:\n whole %s\n split %s", name, step, got, split)
		}
	}
}

func TestPostQuantumHybridServerHello(t *testing.T) {
	tls13 := ext(43, 3, 4)
	for _, h := range hybrids {
		group := `"selected_group" "` + strconv.Itoa(h.group) + `"`
		for _, cipher := range []int{0x1301, 0x1302, 0x1303} {
			driveAll(t, h.name, serverHello(cipher, append(append([]byte{}, tls13...), hybridShare(h.group, h.server, 4)...)),
				`done=true`, group, `"selected_key_exchange" "hybrid"`, `"selected_tls_version" "1.3"`, `"selected_cipher_mode" "aead"`)
		}
		// With pre_shared_key (psk_dhe_ke resumption) the key share still names the exchange.
		driveAll(t, h.name+" with psk", serverHello(0x1301, append(append(append([]byte{}, tls13...), ext(41, 0, 0)...), hybridShare(h.group, h.server, 4)...)),
			`done=true`, `"selected_key_exchange" "hybrid"`)
		// Exact length only: one short, one long, empty, and the client-share length are malformed.
		for _, size := range []int{h.server - 1, h.server + 1, 0, h.client} {
			if size == h.server {
				continue
			}
			driveAll(t, h.name+" bad length", serverHello(0x1301, append(append([]byte{}, tls13...), hybridShare(h.group, size, 4)...)),
				`error="malformed: Server key share encoding length or point format invalid"`)
		}
		if h.pointFirst {
			for _, first := range []byte{0, 2, 3} {
				driveAll(t, h.name+" compressed point", serverHello(0x1301, append(append([]byte{}, tls13...), hybridShare(h.group, h.server, first)...)),
					`error="malformed: Server key share encoding length or point format invalid"`)
			}
		} else {
			// X25519MLKEM768 starts with the ML-KEM ciphertext, which has no fixed first byte.
			driveAll(t, h.name+" any first byte", serverHello(0x1301, append(append([]byte{}, tls13...), hybridShare(h.group, h.server, 0)...)),
				`done=true`, `"selected_key_exchange" "hybrid"`)
		}
	}
	// Neighbouring and withdrawn code points stay outside the profile: 0x11EA (unassigned next to the hybrids),
	// 0x11EE, and 0x6399 (the withdrawn X25519Kyber768Draft00).
	for _, group := range []int{0x11ea, 0x11ee, 0x6399} {
		driveAll(t, "unnamed "+strconv.Itoa(group), serverHello(0x1301, append(append([]byte{}, tls13...), hybridShare(group, 1120, 4)...)),
			`error="unsupported: Server key share group outside supported profile"`)
	}
}

func TestPostQuantumHybridHelloRetryRequest(t *testing.T) {
	tls13 := ext(43, 3, 4)
	for _, h := range hybrids {
		driveAll(t, h.name+" retry", hrrHello(append(append([]byte{}, tls13...), ext(51, byte(h.group>>8), byte(h.group))...)),
			`done=true`, `"requested_group" "`+strconv.Itoa(h.group)+`"`, `"tls_handshake" "hello_retry_request"`)
	}
	driveAll(t, "retry 0x6399", hrrHello(append(append([]byte{}, tls13...), ext(51, 0x63, 0x99)...)),
		`error="unsupported: Retry group outside supported named groups"`)
}

// The ClientHello side needed no change: an offer is collected, never judged by group. A modern client offering
// X25519MLKEM768 in supported_groups and key_share is identified as TLS with its hostname.
func TestPostQuantumHybridClientHello(t *testing.T) {
	sni := ext(0, append([]byte{0, 18, 0, 0, 15}, "www.example.com"...)...)
	groups := ext(10, 0, 8, 0x11, 0xec, 0, 29, 0, 23, 0x11, 0xeb)
	versions := ext(43, 4, 3, 4, 3, 3)
	x25519 := make([]byte, 32)
	hybrid := make([]byte, 1184+32)
	shares := append([]byte{0x11, 0xec, byte(len(hybrid) >> 8), byte(len(hybrid))}, hybrid...)
	shares = append(shares, append([]byte{0, 29, 0, 32}, x25519...)...)
	keyShare := ext(51, append([]byte{byte(len(shares) >> 8), byte(len(shares))}, shares...)...)
	extensions := append(append(append(append([]byte{}, sni...), groups...), versions...), keyShare...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	data := record(append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...))
	driveAll(t, "client X25519MLKEM768", data, `done=true`, `host="www.example.com"/true`, `"tls_offered_max_version" "1.3"`)
}
