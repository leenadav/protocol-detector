package keylogcap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// --- a synthetic TLS 1.3 exchange (TLS_AES_128_GCM_SHA256) from fixed test secrets; nothing is captured ------

func label(secret []byte, name string, length int) []byte {
	full := "tls13 " + name
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(append(append(info, byte(len(full))), full...), 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

type writer struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newWriter(secret []byte) *writer {
	block, _ := aes.NewCipher(label(secret, "key", 16))
	aead, _ := cipher.NewGCM(block)
	return &writer{aead: aead, iv: label(secret, "iv", 12)}
}

func (w *writer) record(kind byte, content []byte) []byte {
	inner := append(append([]byte{}, content...), kind)
	header := []byte{23, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+16))
	nonce := append([]byte{}, w.iv...)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= byte(w.seq >> (56 - 8*i))
	}
	w.seq++
	return append(header, w.aead.Seal(nil, nonce, inner, header)...)
}

func handshake(kind byte, body []byte) []byte {
	return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func plain(kind byte, body []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

const request = "GET /private/path HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic c2VjcmV0\r\n\r\n"

// exchange is (client stream, server stream, key log) of one HTTP exchange inside TLS 1.3.
func exchange() ([]byte, []byte, string) {
	random := bytes.Repeat([]byte{0x5a}, 32)
	secret := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	serverHello := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...), 0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	finished := handshake(20, bytes.Repeat([]byte{9}, 32))
	server := append(plain(22, handshake(2, serverHello)), plain(20, []byte{1})...)
	server = append(server, newWriter(secret(2)).record(22, append(append(handshake(8, []byte{0, 0}), handshake(11, []byte("cert"))...), finished...))...)
	client := append(plain(22, handshake(1, hello)), newWriter(secret(1)).record(22, finished)...)
	client = append(client, newWriter(secret(3)).record(23, []byte(request))...)
	server = append(server, newWriter(secret(4)).record(23, []byte("HTTP/1.1 204 No Content\r\n\r\n"))...)
	keylog := ""
	for i, name := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		keylog += fmt.Sprintf("%s %s %s\n", name, hex.EncodeToString(random), hex.EncodeToString(secret(byte(i+1))))
	}
	return client, server, keylog
}

// --- frames and captures ---------------------------------------------------------------------------------

type endpoint struct {
	addr [4]byte
	port uint16
}

var (
	clientEnd = endpoint{[4]byte{192, 0, 2, 10}, 51000}
	serverEnd = endpoint{[4]byte{198, 51, 100, 20}, 443}
)

func frame(source, destination endpoint, sequence uint32, flags byte, payload []byte) []byte {
	out := make([]byte, 14+20+20, 14+20+20+len(payload))
	out[12], out[13] = 8, 0
	ip := out[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	copy(ip[12:], source.addr[:])
	copy(ip[16:], destination.addr[:])
	tcp := out[34:54]
	binary.BigEndian.PutUint16(tcp[0:], source.port)
	binary.BigEndian.PutUint16(tcp[2:], destination.port)
	binary.BigEndian.PutUint32(tcp[4:], sequence)
	tcp[12], tcp[13] = 5<<4, flags
	return append(out, payload...)
}

func pcap(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, f := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], 1700000000)
		binary.LittleEndian.PutUint32(header[4:], uint32(i))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(f)))
		out = append(append(out, header...), f...)
	}
	return out
}

// conversation is the frames of one connection carrying the two streams in 100-byte segments.
func conversation(client, server []byte) [][]byte {
	frames := [][]byte{frame(clientEnd, serverEnd, 999, 2, nil), frame(serverEnd, clientEnd, 8999, 18, nil)}
	for _, side := range []struct {
		from, to endpoint
		origin   uint32
		data     []byte
	}{{clientEnd, serverEnd, 1000, client}, {serverEnd, clientEnd, 9000, server}} {
		for offset := 0; offset < len(side.data); offset += 100 {
			end := offset + 100
			if end > len(side.data) {
				end = len(side.data)
			}
			frames = append(frames, frame(side.from, side.to, side.origin+uint32(offset), 24, side.data[offset:end]))
		}
		frames = append(frames, frame(side.from, side.to, side.origin+uint32(len(side.data)), 17, nil))
	}
	return frames
}

type report struct {
	Connections []map[string]interface{} `json:"connections"`
	Decrypted   int                      `json:"decrypted"`
	Frames      int                      `json:"frames"`
}

func analyzeFrames(t *testing.T, keylog string, frames ...[]byte) (report, string) {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	text, err := Analyze(pcap(frames...), keylog, pack)
	if err != nil {
		t.Fatal(err)
	}
	var out report
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%v in %s", err, text)
	}
	return out, text
}

func TestDecryptedRowNamesTheInnerProtocolAndLeaksNothing(t *testing.T) {
	client, server, keylog := exchange()
	out, text := analyzeFrames(t, keylog, conversation(client, server)...)
	if len(out.Connections) != 1 || out.Decrypted != 1 {
		t.Fatalf("report: %s", text)
	}
	row := out.Connections[0]
	if row["status"] != "decrypted" || row["application"] != "web-browsing" || row["inner_protocol"] != "http/1.1" || row["version"] != "TLS 1.3" {
		t.Errorf("row: %v", row)
	}
	layers := row["layers"].(map[string]interface{})
	if basis := layers["application"].(map[string]interface{})["basis"]; basis != "authenticated_plaintext" {
		t.Errorf("identity basis: %v", basis)
	}
	// AGENTS.md: no payload, credential, name or key material as output.
	for _, forbidden := range []string{"example.test", "/private/path", "c2VjcmV0", "Authorization", strings.Repeat("01", 32), strings.Repeat("5a", 32)} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the report carries %q", forbidden)
		}
	}
}

func TestMissingKeysGapsAndConflictsAreUnavailable(t *testing.T) {
	client, server, keylog := exchange()
	frames := conversation(client, server)
	check := func(name, wantCode, wantReason string, keys string, frames ...[]byte) {
		t.Helper()
		out, text := analyzeFrames(t, keys, frames...)
		if len(out.Connections) != 1 || out.Decrypted != 0 {
			t.Fatalf("%s: %s", name, text)
		}
		row := out.Connections[0]
		if row["status"] != "unavailable" || row["reason_code"] != wantCode || (wantReason != "" && row["reason"] != wantReason) {
			t.Errorf("%s: %v", name, row)
		}
		if _, has := row["application"]; has {
			t.Errorf("%s: an unavailable row names an inner application: %v", name, row)
		}
	}
	check("no keys", "awaiting_keys", "", "", frames...)
	dropped := append(append([][]byte{}, frames[:3]...), frames[4:]...)
	check("dropped segment", "gap", "TCP capture has missing bytes.", keylog, dropped...)
	conflict := append([]byte{}, frames[3]...)
	conflict[len(conflict)-1] ^= 1
	check("conflicting retransmission", "gap", "Conflicting overlapping bytes; classification invalidated", keylog, append(append([][]byte{}, frames...), conflict)...)
	check("one direction", "unsupported_profile", "Both TCP directions and SYNs are required.", keylog,
		frame(clientEnd, serverEnd, 999, 2, nil), frame(clientEnd, serverEnd, 1000, 24, client))
}

func TestRefusals(t *testing.T) {
	pack, _ := content.Embedded()
	client, server, keylog := exchange()
	capture := pcap(conversation(client, server)...)
	refused := func(name string, data []byte, keys, kind, message, code string) {
		t.Helper()
		_, err := Analyze(data, keys, pack)
		r, ok := err.(*Refusal)
		if !ok || r.Type != kind || r.Message != message || r.Code != code {
			t.Errorf("%s: %#v", name, err)
		}
	}
	refused("oversize", make([]byte, MaxCapture+1), "", "DecryptionError", "Capture exceeds 8 MiB.", "budget_exhausted")
	refused("key-log line", capture, keylog+"two fields\n", "DecryptionError", "Invalid key-log line (secret values are not displayed).", "unsupported_profile")
	refused("not a capture", []byte("not a capture"), "", "CaptureError", "Incomplete or failed PCAP stream", "")
	truncated := append([]byte{}, capture...)
	binary.LittleEndian.PutUint32(truncated[24+12:], 9999)
	refused("truncated record", truncated, keylog, "DecryptionError", "Capture is truncated or exceeds 20,000 frames.", "budget_exhausted")
	var many [][]byte
	for i := 0; i < MaxConnections+1; i++ {
		many = append(many, frame(endpoint{clientEnd.addr, uint16(20000 + i)}, serverEnd, 5, 2, nil))
	}
	refused("too many connections", pcap(many...), "", "DecryptionError", "Capture exceeds 64 TCP connections.", "budget_exhausted")
}

func TestTupleReuseStartsANewGeneration(t *testing.T) {
	client, server, keylog := exchange()
	frames := conversation(client, server)
	again := []([]byte){frame(clientEnd, serverEnd, 500000, 2, nil), frame(serverEnd, clientEnd, 600000, 18, nil),
		frame(clientEnd, serverEnd, 500001, 24, client[:60])}
	out, text := analyzeFrames(t, keylog, append(frames, again...)...)
	if len(out.Connections) != 2 || out.Connections[0]["generation"] != float64(0) || out.Connections[1]["generation"] != float64(1) ||
		out.Connections[0]["session_id"] != out.Connections[1]["session_id"] {
		t.Fatalf("generations: %s", text)
	}
}

// A retransmitted SYN (same client, same ISN) is the same connection, not tuple reuse: it must not close the
// retained stream nor start a new generation (Codex PRO-18 P2).
func TestRetransmittedSYNKeepsTheGeneration(t *testing.T) {
	client, server, keylog := exchange()
	frames := conversation(client, server)
	for _, at := range []int{1, 2} { // before and after the SYN-ACK
		duplicated := append(append(append([][]byte{}, frames[:at]...), frames[0]), frames[at:]...)
		out, text := analyzeFrames(t, keylog, duplicated...)
		if len(out.Connections) != 1 || out.Decrypted != 1 || out.Connections[0]["generation"] != float64(0) {
			t.Fatalf("SYN repeated at %d: %s", at, text)
		}
	}
}

// A closed connection the report keeps holds its settled row, not its inspectors (Codex PRO-13 P2): the
// row is built once at the close and the report still names the inner protocol.
func TestClosedConnectionsKeepTheirRowNotTheirInspectors(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newCoordinator(pack, Budget{PerDirection: decrypt.MaxStream, Aggregate: 4 * 1024 * 1024, Connections: MaxConnections, Pending: 8192}, MaxConnections)
	if err != nil {
		t.Fatal(err)
	}
	keys := decrypt.NewKeyProvider()
	defer keys.Release()
	client, server, keylog := exchange()
	if _, err := keys.Append(keylog); err != nil {
		t.Fatal(err)
	}
	d := newDecryptor(pack, owner.Tier, keys)
	for i, f := range conversation(client, server) {
		packet, err := transport.Decode(f, 1, transport.Ignore)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.accept(packet.(*transport.TCP), 1700000000+float64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.end("Capture input EOF"); err != nil {
		t.Fatal(err)
	}
	if err := d.pump(); err != nil {
		t.Fatal(err)
	}
	if len(d.finished) != 1 {
		t.Fatalf("finished: %d", len(d.finished))
	}
	c := d.finished[0]
	if c.outer != [2]*engine.Inspector{} || c.inner != [2]*engine.Inspector{} || c.dirty || c.row == nil {
		t.Fatalf("a closed connection keeps its inspectors (dirty %v)", c.dirty)
	}
	text := d.report(0, 0, "")
	if !strings.Contains(text, `"status": "decrypted"`) || !strings.Contains(text, `"inner_protocol": "http/1.1"`) {
		t.Fatalf("report: %s", text)
	}
}

func FuzzAnalyzeNeverPanics(f *testing.F) {
	client, server, keylog := exchange()
	capture := pcap(conversation(client, server)...)
	f.Add(capture, keylog)
	f.Add(capture[:len(capture)/2], "")
	f.Add([]byte("not a capture"), "CLIENT_RANDOM 00 00\n")
	pack, _ := content.Embedded()
	f.Fuzz(func(t *testing.T, data []byte, keys string) {
		if len(data) > 1<<16 {
			return
		}
		text, err := Analyze(data, keys, pack)
		if err == nil && !json.Valid([]byte(text)) {
			t.Fatalf("invalid JSON: %s", text)
		}
	})
}
